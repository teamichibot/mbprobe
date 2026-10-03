"""mbprobe — Modbus probe tool READ-ONLY untuk genba."""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn,
                           TimeElapsedColumn, TimeRemainingColumn)
from rich.table import Table

from . import __version__
from .config import ConfigError, load_config
from .decode import (WORD_ORDERS, Frame, find_value, fmt_num, interpret_16, interpret_32)
from .hints import HINT_CRC, HINT_PORT_TCP, HINT_TIMEOUT_RTU, HINT_TIMEOUT_TCP
from .logging_utils import Session
from .poll import Poller
from .protocol import EXCEPTION_NAMES, FC_NAMES, Result, hexs, max_count
from .scan import (DEFAULT_POLL_INTERVAL, DEFAULT_RTU_SCAN_TIMEOUT, DEFAULT_RTU_TIMEOUT, DEFAULT_SCAN_DELAY, MIN_POLL_INTERVAL, MIN_SCAN_DELAY,
                   DeviceSilent, RegRow, clamp_delay, compress_ranges, estimate_rtu_seconds, expand_hosts,
                   parse_int_list, read_range, scan_rtu, scan_tcp)
from .sniff import sniff as do_sniff
from .transport_rtu import PortError, RtuTransport
from .transport_tcp import TcpTransport

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="Modbus probe tool [bold]READ-ONLY[/] (FC 01/02/03/04 saja) untuk verifikasi controller di lapangan.\n\n"
         "Prosedur: ports → sniff → scan-rtu / scan-tcp → read / find-value → dump → poll",
)
console = Console(highlight=False)
INTERACTIVE = False  # True saat dijalankan dari mode interaktif (repl.py)

AUTO_BAUDS = [9600, 19200, 38400, 57600, 115200]

# ---------------------------------------------------------------- helper umum


def warn(msg: str) -> None:
    console.print(f"[yellow]⚠ {msg}[/]")


def err(msg: str) -> None:
    console.print(f"[bold red]✖ {msg}[/]")


def ok(msg: str) -> None:
    console.print(f"[green]✔ {msg}[/]")


def show_files(s: Session) -> None:
    console.print(f"\n[dim]Hasil disimpan di[/] [bold]{s.dir}[/]")
    for f in s.files:
        if f.exists():
            console.print(f"  [dim]•[/] {f.name}")


@contextmanager
def session_scope(command: str, label: str, out: str):
    """Buka sesi; tangani Ctrl+C / port putus / error input dengan rapi; selalu tutup & tampilkan file."""
    s = Session(command, label, out)
    code = 0
    try:
        yield s
    except KeyboardInterrupt:
        warn("Dihentikan (Ctrl+C). Hasil yang sudah didapat tetap disimpan.")
        s.log("Dihentikan oleh pengguna (Ctrl+C)")
        code = 130
    except PortError as e:
        err(str(e))
        s.log(f"PORT ERROR: {e}")
        code = 1
    except (ConfigError, ValueError) as e:
        err(str(e))
        s.log(f"ERROR: {e}")
        code = 1
    finally:
        s.close()
        show_files(s)
    if code:
        raise typer.Exit(code)


def parity_list(spec: str) -> list[str]:
    out = [p.strip().upper() for p in spec.split(",") if p.strip()]
    bad = [p for p in out if p not in ("N", "E", "O")]
    if bad:
        raise typer.BadParameter(f"parity {bad} tidak dikenal (pakai N, E, O)")
    return out


def make_transport(rtu: Optional[str], tcp: Optional[str], tcp_port: int, baud: int, parity: str,
                   stopbits: float, timeout: Optional[float], s: Session):
    if bool(rtu) == bool(tcp):
        raise typer.BadParameter("Pilih salah satu: --rtu PORT atau --tcp HOST")
    if rtu:
        return RtuTransport(rtu, baud, parity_list(parity)[0], stopbits, timeout or DEFAULT_RTU_TIMEOUT, session=s)
    return TcpTransport(tcp, tcp_port, timeout or 2.0, session=s)


def explain_failure(r: Result, t) -> None:
    if r.status == "exception":
        name = EXCEPTION_NAMES.get(r.exc_code, "?")
        console.print(f"[yellow]Device menjawab EXCEPTION {r.exc_code:02d} ({name}).[/] "
                      "Device hidup & bicara Modbus.")
        if r.exc_code == 2:
            console.print("  → Alamat/rentang tidak valid. Coba alamat lain, count lebih kecil, atau `dump`.")
        elif r.exc_code == 1:
            console.print("  → FC tidak didukung. Coba --fc 3 ↔ --fc 4.")
        return
    if r.status == "nonstandard":
        console.print(f"[yellow]Device menjawab, tapi dengan frame non-standar.[/] {r.message}")
        console.print("  → Device hidup. Coba alamat lain (mis. --addr 1) atau FC lain (3 ↔ 4).")
        return
    if r.status == "late":
        warn(f"Device hidup tapi lambat: {r.message}, lebih lama dari --timeout. Ulangi dengan --timeout 2.")
        return
    if r.status == "timeout":
        err(HINT_TIMEOUT_RTU if t.kind == "rtu" else HINT_TIMEOUT_TCP)
        if getattr(t, "late", None):
            warn("Balasan datang setelah timeout — device lambat, ulangi dengan --timeout 2.")
    elif r.status == "crc_error":
        err(HINT_CRC)
        console.print(f"  [dim]raw: {hexs(r.rx)}[/]")
    elif r.status == "port_error":
        err(f"{r.message}. {HINT_PORT_TCP}")
    else:
        err(f"Response tidak valid: {r.message} [dim]{hexs(r.rx)}[/]")


def progress_bar() -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("sisa"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )


# opsi bersama
OPT_LABEL = typer.Option("", "--label", "-l", help="Label sesi, mis. nama unit 'ZR250'")
OPT_OUT = typer.Option("sessions", "--out", help="Folder induk sesi")
OPT_RTU = typer.Option(None, "--rtu", help="Serial port RTU, mis. COM5 atau /dev/ttyUSB0")
OPT_TCP = typer.Option(None, "--tcp", help="IP device Modbus TCP")
OPT_TCP_PORT = typer.Option(502, "--tcp-port", help="Port Modbus TCP")
OPT_BAUD = typer.Option(9600, "--baud", "-b")
OPT_PARITY = typer.Option("N", "--parity", "-p", help="N / E / O")
OPT_STOP = typer.Option(1.0, "--stopbits", help="1 atau 2")
OPT_ID = typer.Option(1, "--id", "--unit", "-u", help="Slave ID (RTU) / unit ID (TCP)")
OPT_TIMEOUT = typer.Option(None, "--timeout", "-t",
                           help="Timeout response (detik). Default RTU 2.0 (sensor murah bisa butuh ±1 s), TCP 2.0")
OPT_FC = typer.Option(3, "--fc", help="1=coils 2=discrete inputs 3=holding 4=input registers")
OPT_DELAY = typer.Option(DEFAULT_SCAN_DELAY, "--delay", help=f"Jeda antar request, detik (min {MIN_SCAN_DELAY})")


def check_fc(fc: int) -> int:
    if fc not in (1, 2, 3, 4):
        raise typer.BadParameter("mbprobe read-only: --fc hanya 1, 2, 3, atau 4")
    return fc


# ---------------------------------------------------------------- ports


@app.command()
def ports():
    """Daftar serial port (deskripsi & VID:PID) untuk mengenali adaptor USB-RS485."""
    from serial.tools import list_ports

    known = {0x0403: "FTDI", 0x1A86: "CH340/CH341", 0x10C4: "CP210x", 0x067B: "PL2303"}
    rows = sorted(list_ports.comports(), key=lambda p: p.device)
    if not rows:
        warn("Tidak ada serial port. Colok adaptor USB-RS485; di Windows cek Device Manager → Ports (COM & LPT); "
             "kalau muncul tanda seru, install driver CH340/FTDI.")
        return
    tb = Table(title="Serial port")
    for c in ("Port", "Deskripsi", "VID:PID", "Chip", "Pabrikan", "Serial"):
        tb.add_column(c)
    for p in rows:
        vidpid = f"{p.vid:04X}:{p.pid:04X}" if p.vid is not None else "-"
        chip = known.get(p.vid, "") if p.vid is not None else ""
        tb.add_row(p.device, p.description or "-", vidpid, chip, p.manufacturer or "-", p.serial_number or "-")
    console.print(tb)
    console.print("[dim]Adaptor USB-RS485 biasanya chip FTDI / CH340 / CP210x. Cabut-colok untuk memastikan port mana.[/]")


# ---------------------------------------------------------------- sniff


@app.command()
def sniff(
    port: str = typer.Option(..., "--port", help="Serial port, mis. COM5"),
    baud: int = OPT_BAUD,
    parity: str = OPT_PARITY,
    stopbits: float = OPT_STOP,
    duration: float = typer.Option(60, "--duration", "-d", help="Lama mendengarkan (detik)"),
    auto: bool = typer.Option(False, "--auto", help="Coba baud 9600..115200 × parity N/E/O bergantian"),
    dwell: float = typer.Option(5, "--dwell", help="Lama per kombinasi untuk --auto (detik)"),
    gap_ms: Optional[float] = typer.Option(None, "--gap-ms", help="Jeda pemisah frame (ms). Default otomatis"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Jangan tampilkan tiap frame"),
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Dengarkan bus RS485 secara PASIF (tidak mengirim apa pun) dan decode frame Modbus RTU."""
    with session_scope("sniff", label, out) as s:
        if auto:
            _sniff_auto(port, stopbits, dwell, gap_ms, s)
            return
        p = parity_list(parity)[0]
        console.print(f"Mendengarkan [bold]{port}[/] {baud} {p} selama {duration:g} s — pasif, tidak mengirim byte. "
                      "Ctrl+C untuk berhenti.")
        csvf = s.csv("sniff_frames.csv", ["time", "slave", "fc", "kind", "addr", "count", "byte_count",
                                          "exc_code", "values", "hex"])
        shown_junk = [0]

        def on_frame(f: Frame):
            csvf.add([datetime.fromtimestamp(f.t).isoformat(timespec="milliseconds"), f.slave, f.fc, f.kind,
                      f.addr, f.count, f.byte_count, f.exc_code, " ".join(map(str, f.values)), hexs(f.raw)])
            if not quiet:
                console.print(f"[cyan]{datetime.fromtimestamp(f.t):%H:%M:%S.%f}"[:-3] + f"[/] {f.describe()}  "
                              f"[dim]{hexs(f.raw)}[/]")

        def on_junk(j: bytes):
            if not quiet and shown_junk[0] < 20:
                shown_junk[0] += 1
                console.print(f"[magenta]raw[/] [dim]{hexs(j[:64])}{' …' if len(j) > 64 else ''}[/]")

        st = do_sniff(port, baud, p, duration, stopbits, gap_ms, on_frame, on_junk, session=s)
        _sniff_summary(st, s)


def _sniff_summary(st, s: Session) -> None:
    reqs: dict[tuple, int] = {}
    for f in st.frames:
        if f.kind == "request":
            k = (f.slave, f.fc, f.addr, f.count)
            reqs[k] = reqs.get(k, 0) + 1
    slaves = sorted({f.slave for f in st.frames})
    console.print()
    console.print(f"[bold]Ringkasan sniff[/] {st.baud} {st.parity}: {st.bytes_rx} byte, "
                  f"{st.valid} frame valid, {st.junk_bytes} byte tidak valid, {st.duration:.0f} s")
    if st.valid:
        ok(f"{st.verdict()} — slave ID terlihat: {slaves}")
        if reqs:
            tb = Table(title="Request yang dikirim master lain di bus")
            for c in ("Slave", "FC", "Alamat", "Count", "Kali"):
                tb.add_column(c)
            for (sl, fc, a, c), n in sorted(reqs.items()):
                tb.add_row(str(sl), f"{fc:02d}", str(a), str(c), str(n))
            console.print(tb)
        warn("Bus SUDAH dipakai master lain. Polling dari laptop bisa bentrok — koordinasikan dulu "
             "(atau pakai port lain / jadwal saat master off).")
    elif st.bytes_rx:
        warn("Ada lalu lintas non-Modbus atau baud/parity tidak cocok. Coba --auto.")
        raw = b"".join(st.junk)[:96]
        console.print(f"  [dim]contoh raw: {hexs(raw)}[/]")
    else:
        console.print("Bus sepi: tidak ada lalu lintas. Aman untuk scan-rtu (atau wiring belum tersambung).")
    s.json("summary.json", {
        "baud": st.baud, "parity": st.parity, "bytes": st.bytes_rx, "valid_frames": st.valid,
        "junk_bytes": st.junk_bytes, "verdict": st.verdict(), "slaves": slaves,
        "requests": [{"slave": k[0], "fc": k[1], "addr": k[2], "count": k[3], "n": n} for k, n in reqs.items()],
        "sample_raw_hex": hexs(b"".join(st.junk)[:256]), "interrupted": st.interrupted,
    })
    if st.interrupted:
        raise KeyboardInterrupt


def _sniff_auto(port: str, stopbits: float, dwell: float, gap_ms, s: Session) -> None:
    combos = [(b, p) for b in AUTO_BAUDS for p in ("N", "E", "O")]
    console.print(f"Sniff --auto di [bold]{port}[/]: {len(combos)} kombinasi × {dwell:g} s "
                  f"≈ {len(combos) * dwell:.0f} s. Pasif, tidak mengirim byte.")
    csvf = s.csv("sniff_auto.csv", ["baud", "parity", "bytes", "valid_frames", "junk_bytes", "verdict", "slaves"])
    results = []
    interrupted = False
    for b, p in combos:
        st = do_sniff(port, b, p, dwell, stopbits, gap_ms, session=s)
        slaves = sorted({f.slave for f in st.frames})
        results.append((b, p, st, slaves))
        csvf.add([b, p, st.bytes_rx, st.valid, st.junk_bytes, st.verdict(), " ".join(map(str, slaves))])
        color = "green" if st.valid else ("yellow" if st.bytes_rx else "dim")
        console.print(f"  [{color}]{b:>6} {p}: {st.bytes_rx:5d} byte, {st.valid:3d} frame valid → {st.verdict()}[/]")
        if st.interrupted:
            interrupted = True
            break
    good = sorted([r for r in results if r[2].valid], key=lambda r: -r[2].valid)
    console.print()
    if good:
        b, p, st, slaves = good[0]
        ok(f"Kombinasi terbaik: {b} {p} ({st.valid} frame valid, slave {slaves}).")
        for b2, p2, st2, _ in good[1:]:
            console.print(f"  [dim]juga valid: {b2} {p2} ({st2.valid} frame) — parity N vs E/O kadang sama-sama lolos[/]")
        warn("Bus sudah dipakai master lain. Jangan polling sembarangan sebelum koordinasi.")
    elif any(r[2].bytes_rx for r in results):
        warn("Ada lalu lintas, tapi tidak ada kombinasi dengan CRC valid → kemungkinan bukan Modbus RTU "
             "(protokol proprietary) atau setting 7-bit/stop bit lain.")
    else:
        console.print("Bus sepi di semua kombinasi.")
    s.json("summary.json", {
        "results": [{"baud": b, "parity": p, "bytes": st.bytes_rx, "valid_frames": st.valid,
                     "junk_bytes": st.junk_bytes, "slaves": sl, "verdict": st.verdict()} for b, p, st, sl in results],
        "best": {"baud": good[0][0], "parity": good[0][1]} if good else None,
        "interrupted": interrupted,
    })
    if interrupted:
        raise KeyboardInterrupt


# ---------------------------------------------------------------- scan-rtu


@app.command("scan-rtu")
def scan_rtu_cmd(
    port: str = typer.Option(..., "--port", help="Serial port, mis. COM5"),
    bauds: str = typer.Option("9600,19200,38400", "--bauds"),
    parity: str = typer.Option("N,E", "--parity", "-p", help="Daftar parity, mis. N,E,O"),
    ids: str = typer.Option("1-32", "--ids", help="Rentang slave ID, mis. 1-247 atau 1,2,10"),
    timeout: float = typer.Option(DEFAULT_RTU_SCAN_TIMEOUT, "--timeout", "-t",
                                  help="Tunggu jawaban per request (detik). Sensor murah bisa butuh ±0,6 s; "
                                       "0,3 cukup untuk PLC/power meter yang cepat"),
    addr: int = typer.Option(0, "--addr", "-a", help="Alamat register yang dipakai untuk probe"),
    delay: float = OPT_DELAY,
    stopbits: float = OPT_STOP,
    stop_on_first: bool = typer.Option(False, "--stop-on-first", help="Berhenti di temuan pertama"),
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Cari device RTU: coba baud × parity × slave ID dengan FC03 (lalu FC04) di --addr, count 1."""
    delay = clamp_delay(delay, MIN_SCAN_DELAY, "--delay", warn)
    bl = parse_int_list(bauds, 300, 1_000_000)
    pl = parity_list(parity)
    il = parse_int_list(ids, 1, 247)
    total = len(bl) * len(pl) * len(il)
    est = estimate_rtu_seconds(len(bl) * len(pl), len(il), timeout, delay)
    with session_scope("scan-rtu", label, out) as s:
        console.print(f"Scan RTU di [bold]{port}[/]: baud {bl} × parity {pl} × ID {il[0]}..{il[-1]} "
                      f"= {total} percobaan, estimasi maks ≈ {est / 60:.1f} menit.")
        csvf = s.csv("scan_rtu.csv", ["baud", "parity", "slave", "fc", "status", "exc_code", "detail"])
        with progress_bar() as prog:
            task = prog.add_task("scan", total=total)

            def on_attempt(sid, combo):
                prog.update(task, advance=1, description=f"{combo} id {sid:3d}")

            def on_hit(h):
                csvf.add([h.baud, h.parity, h.slave, h.fc, h.status, h.exc_code, h.detail])
                fc = f" FC{h.fc:02d}" if h.fc else ""
                prog.console.print(f"[bold green]DITEMUKAN[/] {h.baud} {h.parity} ID {h.slave}{fc}: {h.detail}")

            rep = scan_rtu(port, bl, pl, il, timeout, delay, stopbits, stop_on_first, s, on_hit, on_attempt,
                           probe_addr=addr)
        _scan_rtu_summary(rep, s, port, timeout, addr)


def _scan_rtu_summary(rep, s: Session, port: str, timeout: float = 1.0, addr: int = 0) -> None:
    console.print()
    if rep.hits:
        tb = Table(title="Device RTU ditemukan")
        for c in ("Baud", "Parity", "Slave ID", "FC", "Response"):
            tb.add_column(c)
        for h in rep.hits:
            tb.add_row(str(h.baud), h.parity, str(h.slave), f"{h.fc:02d}" if h.fc else "-", h.detail)
        console.print(tb)
        h = next((x for x in rep.hits if x.status == "ok"), rep.hits[0])
        conn = f"--rtu {port} --baud {h.baud} --parity {h.parity} --id {h.slave}"
        if h.status == "ok":
            nxt = f"read --fc {h.fc} --addr {addr} --count 10"
        else:
            nxt = f"dump --fc {h.fc or 3} --from 0 --to 100"
            console.print(f"[dim]Device hidup tapi alamat {addr} tidak dijawab normal → petakan alamat valid dulu "
                          "dengan dump (coba FC03 dan FC04).[/]")
        console.print(f"Langkah berikut: [bold]{'' if INTERACTIVE else 'mbprobe '}{nxt}"
                      f"{'' if INTERACTIVE else ' ' + conn}[/]")
    elif rep.extra.get("rx_bytes", 0) == 0:
        err("Tidak ada SATU byte pun yang diterima di semua kombinasi. Biasanya ini masalah fisik: "
            "A/B tertukar, device belum dapat daya, kabel/terminal longgar, atau port dipakai program lain.")
        console.print(f"  Kalau wiring yakin benar: device mungkin lambat (coba [bold]--timeout 2[/], sekarang "
                      f"{timeout:g}) atau tidak menjawab alamat {addr} (coba [bold]--addr 1[/]).")
    else:
        err("Tidak ada device yang menjawab. " + HINT_TIMEOUT_RTU)
    if rep.extra.get("late"):
        warn(f"Ada {len(rep.extra['late'])} balasan yang datang SETELAH timeout {timeout:g} s — device lambat. "
             f"Ulangi dengan --timeout {max(2.0, timeout * 2):g} supaya pembacaan andal.")
    if rep.crc_hints:
        hint = ", ".join(f"{b} {p}: {n}×" for (b, p), n in rep.crc_hints.items())
        warn(f"Ada byte balasan dengan CRC/format salah di: {hint}. Kemungkinan ada device tapi baud/parity "
             "belum pas, atau masalah wiring/noise.")
    if rep.echo:
        warn("Adaptor memantulkan byte yang dikirim (echo) — sudah otomatis diabaikan.")
    s.json("summary.json", {
        "hits": [h.__dict__ for h in rep.hits],
        "crc_hints": [{"baud": b, "parity": p, "count": n} for (b, p), n in rep.crc_hints.items()],
        "echo": rep.echo, "attempts": rep.attempts, "interrupted": rep.interrupted,
        "late": rep.extra.get("late", []), "rx_bytes": rep.extra.get("rx_bytes", 0),
        "timeout": timeout, "probe_addr": addr,
    })
    if rep.interrupted:
        raise KeyboardInterrupt


# ---------------------------------------------------------------- scan-tcp


@app.command("scan-tcp")
def scan_tcp_cmd(
    subnet: Optional[str] = typer.Option(None, "--subnet", help="mis. 192.168.1.0/24"),
    host: Optional[str] = typer.Option(None, "--host", help="Uji satu IP saja"),
    ports_: str = typer.Option("502,80,443", "--ports", help="Port TCP yang dicek"),
    unit_ids: str = typer.Option("0,1,255", "--unit-ids"),
    modbus_port: int = typer.Option(502, "--modbus-port"),
    connect_timeout: float = typer.Option(0.4, "--connect-timeout"),
    timeout: float = typer.Option(1.5, "--timeout", "-t", help="Timeout response Modbus"),
    delay: float = OPT_DELAY,
    workers: int = typer.Option(32, "--workers", help="Koneksi paralel saat cek port"),
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Cari host dengan port 502/80/443 terbuka, lalu uji Modbus TCP (FC03/FC04 alamat 0)."""
    if not subnet and not host:
        raise typer.BadParameter("Isi --subnet atau --host")
    delay = clamp_delay(delay, MIN_SCAN_DELAY, "--delay", warn)
    pl = parse_int_list(ports_, 1, 65535)
    ul = parse_int_list(unit_ids, 0, 255)
    with session_scope("scan-tcp", label, out) as s:
        hosts = expand_hosts(subnet, host)
        console.print(f"Scan TCP {len(hosts)} host, port {sorted(set(pl + [modbus_port]))}, unit ID {ul}.")
        csvf = s.csv("scan_tcp.csv", ["host", "open_ports", "unit", "fc", "status", "detail"])
        with progress_bar() as prog:
            task = prog.add_task("cek port", total=len(hosts))

            def on_host(h):
                if not h.modbus:
                    csvf.add([h.host, " ".join(map(str, h.open_ports)), "", "", "", ""])
                for m in h.modbus:
                    csvf.add([h.host, " ".join(map(str, h.open_ports)), m["unit"], m["fc"], m["status"], m["detail"]])

            rep = scan_tcp(hosts, pl, ul, connect_timeout, timeout, delay, modbus_port, workers, s,
                           on_host, lambda n: prog.update(task, advance=n))
        console.print()
        if rep.hits:
            tb = Table(title="Host ditemukan")
            for c in ("Host", "Port terbuka", "Modbus TCP", "Catatan"):
                tb.add_column(c)
            for h in rep.hits:
                mb = "; ".join(f"unit {m['unit']} FC{m['fc']:02d}: {m['detail']}" for m in h.modbus) or "-"
                note = []
                if 80 in h.open_ports or 443 in h.open_ports:
                    note.append("web server (cek di browser — mis. Mk5)")
                if modbus_port in h.open_ports and not any(m["status"] in ("ok", "exception") for m in h.modbus):
                    note.append("502 terbuka tapi tidak jawab Modbus")
                tb.add_row(h.host, " ".join(map(str, h.open_ports)), mb, ", ".join(note))
            console.print(tb)
        else:
            err("Tidak ada host dengan port tersebut. Cek IP laptop satu subnet dengan controller, dan kabel LAN.")
        s.json("summary.json", {
            "hosts": [h.__dict__ for h in rep.hits], "attempts": rep.attempts, "interrupted": rep.interrupted,
        })
        if rep.interrupted:
            raise KeyboardInterrupt


# ---------------------------------------------------------------- read


@app.command()
def read(
    rtu: Optional[str] = OPT_RTU,
    tcp: Optional[str] = OPT_TCP,
    tcp_port: int = OPT_TCP_PORT,
    baud: int = OPT_BAUD,
    parity: str = OPT_PARITY,
    stopbits: float = OPT_STOP,
    slave: int = OPT_ID,
    fc: int = OPT_FC,
    addr: int = typer.Option(0, "--addr", "-a"),
    count: int = typer.Option(10, "--count", "-c"),
    timeout: Optional[float] = OPT_TIMEOUT,
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Baca satu blok dan tampilkan dalam banyak interpretasi (16/32-bit, float, 4 urutan word, ÷10, ÷100)."""
    check_fc(fc)
    with session_scope("read", label, out) as s:
        t = make_transport(rtu, tcp, tcp_port, baud, parity, stopbits, timeout, s)
        with t:
            r = t.request(slave, fc, addr, count)
            if t.kind == "rtu" and r.status == "timeout":
                for info in t.drain_late(1.5):
                    r.status, r.message = "late", f"device menjawab {info['delay_ms']:.0f} ms setelah request" \
                        if info.get("delay_ms") else info["detail"]
        console.print(f"[dim]{t.link} id={slave} FC{fc:02d} ({FC_NAMES[fc]}) addr={addr} count={count} "
                      f"{r.elapsed_ms:.0f} ms[/]")
        if r.echo:
            warn("Echo adaptor terdeteksi dan diabaikan.")
        if r.status != "ok":
            explain_failure(r, t)
            s.json("summary.json", {"status": r.status, "exc_code": r.exc_code, "message": r.message,
                                    "tx": hexs(r.tx), "rx": hexs(r.rx)})
            return
        _print_read(r, s)


def _print_read(r: Result, s: Session) -> None:
    if r.fc in (1, 2):
        tb = Table(title=f"FC{r.fc:02d} bits")
        tb.add_column("Alamat")
        tb.add_column("Nilai")
        f = s.csv("read_bits.csv", ["addr", "value"])
        for i, v in enumerate(r.values):
            tb.add_row(str(r.addr + i), str(v))
            f.add([r.addr + i, v])
        console.print(tb)
        s.json("summary.json", {"fc": r.fc, "addr": r.addr, "values": r.values})
        return
    rows16 = [interpret_16(r.addr + i, v) for i, v in enumerate(r.values)]
    tb = Table(title="16-bit")
    for c in ("Alamat", "uint16", "int16", "hex", "÷10", "÷100"):
        tb.add_column(c, justify="right")
    f16 = s.csv("read_16.csv", list(rows16[0].keys()))
    for row in rows16:
        tb.add_row(str(row["addr"]), str(row["uint16"]), str(row["int16"]), row["hex"],
                   fmt_num(row["div10"]), fmt_num(row["div100"]))
        f16.add(list(row.values()))
    console.print(tb)
    rows32 = [interpret_32(r.addr + i, r.values[i], r.values[i + 1]) for i in range(len(r.values) - 1)]
    if rows32:
        f32 = s.csv("read_32.csv", list(rows32[0].keys()))
        ti = Table(title="32-bit integer, alamat N & N+1 (int32 dalam kurung kalau negatif)")
        tf = Table(title="32-bit float, alamat N & N+1")
        for tb in (ti, tf):
            tb.add_column("Alamat", justify="right")
            for o in WORD_ORDERS:
                tb.add_column(o, justify="right")
        for row in rows32:
            a = f"{row['addr']}-{row['addr'] + 1}"
            ints = []
            for o in WORD_ORDERS:
                u, i32 = row[f"uint32_{o}"], row[f"int32_{o}"]
                ints.append(f"{u}" + (f" ({i32})" if i32 < 0 else ""))
            ti.add_row(a, *ints)
            tf.add_row(a, *[fmt_num(row[f"float32_{o}"]) for o in WORD_ORDERS])
            f32.add(list(row.values()))
        console.print(ti)
        console.print(tf)
        console.print("[dim]Urutan: ABCD = big-endian standar; CDAB = word swap (umum di PLC/controller); "
                      "BADC = byte swap; DCBA = little-endian.[/]")
    s.json("summary.json", {"fc": r.fc, "addr": r.addr, "count": r.count, "values": r.values})


# ---------------------------------------------------------------- dump & find-value


def _range_reader(t, slave, fc, start, end, block, delay, s: Session, csv_name="dump.csv"):
    """Jalankan read_range dengan progress & CSV. Return (regs dict, rows list, stats, error)."""
    regs: dict[int, int] = {}
    rows: list[RegRow] = []
    f = s.csv(csv_name, ["addr", "raw", "hex", "status", "exc_code"])
    error = ""

    def on_row(row: RegRow):
        rows.append(row)
        if row.status == "ok":
            regs[row.addr] = row.value
        st = row.status if row.status != "exception" else f"exception {row.exc_code}"
        f.add([row.addr, "" if row.value is None else row.value,
               "" if row.value is None else f"0x{row.value:04X}", st, row.exc_code or ""])

    stats = {}
    pending_exc = None
    with progress_bar() as prog:
        task = prog.add_task(f"FC{fc:02d} {start}..{end}", total=end - start + 1)
        try:
            read_range(t, slave, fc, start, end, block, delay, on_row,
                       on_progress=lambda n: prog.update(task, advance=n), stats=stats)
        except DeviceSilent as e:
            error = str(e)
        except (KeyboardInterrupt, PortError) as e:
            # simpan ringkasan hasil sementara dulu, lalu lempar ulang lewat finish()
            error = "Dihentikan (Ctrl+C)" if isinstance(e, KeyboardInterrupt) else str(e)
            pending_exc = e
    s.pending_exc = pending_exc
    return regs, rows, stats, error


def finish(s: Session) -> None:
    """Lempar ulang Ctrl+C / port error yang ditunda setelah ringkasan tersimpan."""
    if getattr(s, "pending_exc", None) is not None:
        raise s.pending_exc


def _print_ranges(ranges: list[dict]) -> None:
    tb = Table(title="Peta alamat")
    for c in ("Dari", "Sampai", "Jumlah", "Status"):
        tb.add_column(c)
    for r in ranges[:60]:
        color = "green" if r["status"] == "ok" else ("yellow" if r["status"].startswith("exception") else "red")
        tb.add_row(str(r["from"]), str(r["to"]), str(r["to"] - r["from"] + 1), f"[{color}]{r['status']}[/]")
    console.print(tb)
    if len(ranges) > 60:
        console.print(f"[dim]… {len(ranges) - 60} rentang lagi, lihat dump.csv / summary.json[/]")


def _check_range(fc: int, start: int, end: int) -> None:
    check_fc(fc)
    if not 0 <= start <= end <= 0xFFFF:
        raise typer.BadParameter("--from/--to harus 0..65535 dan from ≤ to")


@app.command()
def dump(
    rtu: Optional[str] = OPT_RTU,
    tcp: Optional[str] = OPT_TCP,
    tcp_port: int = OPT_TCP_PORT,
    baud: int = OPT_BAUD,
    parity: str = OPT_PARITY,
    stopbits: float = OPT_STOP,
    slave: int = OPT_ID,
    fc: int = OPT_FC,
    start: int = typer.Option(0, "--from"),
    end: int = typer.Option(2000, "--to"),
    block: int = typer.Option(50, "--block"),
    delay: float = OPT_DELAY,
    timeout: Optional[float] = OPT_TIMEOUT,
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Baca rentang besar per blok; blok yang exception dipecah sampai per register → peta alamat valid."""
    _check_range(fc, start, end)
    delay = clamp_delay(delay, MIN_SCAN_DELAY, "--delay", warn)
    with session_scope("dump", label, out) as s:
        t = make_transport(rtu, tcp, tcp_port, baud, parity, stopbits, timeout, s)
        with t:
            regs, rows, stats, error = _range_reader(t, slave, fc, start, end, min(block, max_count(fc)), delay, s)
        _dump_summary(rows, stats, error, s, t)
        finish(s)


def _dump_summary(rows, stats, error, s, t) -> list[dict]:
    ranges = compress_ranges(rows)
    console.print()
    if ranges:
        _print_ranges(ranges)
    n_ok = sum(1 for r in rows if r.status == "ok")
    n_exc = sum(1 for r in rows if r.status == "exception")
    n_ns = sum(1 for r in rows if r.status == "nonstandard")
    ns = f", {n_ns} ditolak (non-standar)" if n_ns else ""
    console.print(f"{n_ok} alamat valid, {n_exc} exception{ns}, {len(rows) - n_ok - n_exc - n_ns} gagal "
                  f"(timeout/CRC); {stats.get('requests', '?')} request.")
    if getattr(t, "late", None):
        warn(f"{len(t.late)} balasan datang setelah timeout — device lambat. Ulangi dengan --timeout "
             f"{max(3.0, t.timeout * 2):g} supaya peta alamat akurat.")
    if error and getattr(s, "pending_exc", None) is None:
        err(error + " " + (HINT_TIMEOUT_RTU if t.kind == "rtu" else HINT_TIMEOUT_TCP))
    s.json("summary.json", {"ranges": ranges, "stats": stats, "error": error,
                            "valid": n_ok, "exception": n_exc, "nonstandard": n_ns,
                            "late": len(getattr(t, "late", []))})
    return ranges


@app.command("find-value")
def find_value_cmd(
    value: List[float] = typer.Option(..., "--value", "-v", help="Nilai di layar controller; boleh diulang"),
    tolerance: float = typer.Option(0.0, "--tolerance", help="Toleransi absolut (satuan sama dengan --value)"),
    rtu: Optional[str] = OPT_RTU,
    tcp: Optional[str] = OPT_TCP,
    tcp_port: int = OPT_TCP_PORT,
    baud: int = OPT_BAUD,
    parity: str = OPT_PARITY,
    stopbits: float = OPT_STOP,
    slave: int = OPT_ID,
    fc: int = OPT_FC,
    start: int = typer.Option(0, "--from"),
    end: int = typer.Option(2000, "--to"),
    block: int = typer.Option(50, "--block"),
    delay: float = OPT_DELAY,
    timeout: Optional[float] = OPT_TIMEOUT,
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Cari register (16-bit, atau 32-bit di 4 urutan word, skala ×1/×0.1/×0.01/…) yang cocok dengan nilai di layar."""
    _check_range(fc, start, end)
    if fc not in (3, 4):
        raise typer.BadParameter("find-value hanya untuk register: --fc 3 atau 4")
    delay = clamp_delay(delay, MIN_SCAN_DELAY, "--delay", warn)
    with session_scope("find-value", label, out) as s:
        t = make_transport(rtu, tcp, tcp_port, baud, parity, stopbits, timeout, s)
        with t:
            regs, rows, stats, error = _range_reader(t, slave, fc, start, end, min(block, 125), delay, s)
        f = s.csv("matches.csv", ["target", "addr", "type", "word_order", "raw", "scale", "value"])
        result = {}
        console.print()
        console.print(f"[dim]{len(regs)} register terbaca dari {start}..{end}.[/]")
        for target in value:
            ms = find_value(regs, target, tolerance)
            result[fmt_num(target)] = [m.__dict__ for m in ms]
            if ms:
                ok(f"{fmt_num(target)}: {len(ms)} kandidat")
                for m in ms[:30]:
                    console.print(f"   {m.describe()}")
                    f.add([target, m.addr, m.typ, m.order, m.raw, m.scale, m.value])
                if len(ms) > 30:
                    console.print(f"   [dim]… {len(ms) - 30} lagi di matches.csv[/]")
                    for m in ms[30:]:
                        f.add([target, m.addr, m.typ, m.order, m.raw, m.scale, m.value])
            else:
                warn(f"{fmt_num(target)}: tidak ditemukan. Coba --tolerance (nilai berubah?), FC lain, atau rentang lain.")
        if len(regs) and any(result.values()):
            console.print("[dim]Tip: nilai yang berubah (tekanan/suhu) → bandingkan beberapa kali; "
                          "kandidat yang konsisten dengan layar adalah yang benar.[/]")
        if error and getattr(s, "pending_exc", None) is None:
            err(error)
        s.json("summary.json", {"targets": result, "registers_read": len(regs), "ranges": compress_ranges(rows),
                                "stats": stats, "error": error})
        finish(s)


# ---------------------------------------------------------------- poll


@app.command()
def poll(
    config: str = typer.Option(..., "--config", "-c", help="File YAML unit"),
    interval: float = typer.Option(DEFAULT_POLL_INTERVAL, "--interval", "-i",
                                   help=f"Jeda antar siklus baca, detik (min {MIN_POLL_INTERVAL})"),
    duration: Optional[float] = typer.Option(None, "--duration", "-d", help="Lama polling (detik). Default sampai Ctrl+C"),
    delay: float = typer.Option(DEFAULT_SCAN_DELAY, "--request-delay", help="Jeda antar request dalam 1 siklus"),
    port: Optional[str] = typer.Option(None, "--port", help="Override serial port di config"),
    label: str = OPT_LABEL,
    out: str = OPT_OUT,
):
    """Baca register yang sudah teridentifikasi secara berkala, log ke CSV."""
    interval = clamp_delay(interval, MIN_POLL_INTERVAL, "--interval", warn)
    delay = clamp_delay(delay, MIN_SCAN_DELAY, "--request-delay", warn)
    try:
        cfg = load_config(config)
    except ConfigError as e:
        err(str(e))
        raise typer.Exit(1)
    c = cfg.connection
    if port:
        c.port = port
    with session_scope("poll", label or cfg.name, out) as s:
        (s.dir / "config.yaml").write_text(open(config, encoding="utf-8").read(), encoding="utf-8")
        if c.type == "rtu":
            t = RtuTransport(c.port, c.baud, c.parity, c.stopbits, c.timeout, session=s)
        else:
            t = TcpTransport(c.host, c.tcp_port, c.timeout, session=s)
        poller = Poller(cfg, t, delay)
        names = [r.name for r in cfg.registers]
        units = {r.name: r.unit for r in cfg.registers}
        f = s.csv("poll.csv", ["timestamp"] + names)
        console.print(f"Polling [bold]{cfg.name}[/] via {t.link}, {len(names)} register dalam "
                      f"{len(poller.blocks)} request/siklus, tiap {interval:g} s. Ctrl+C untuk berhenti.")
        t0 = time.monotonic()
        cycles = fails = 0
        last: dict = {}
        with t:
            try:
                while duration is None or time.monotonic() - t0 < duration:
                    tc = time.monotonic()
                    res = poller.cycle()
                    cycles += 1
                    ts = datetime.now().isoformat(timespec="seconds")
                    f.add([ts] + ["" if res[n][0] is None else res[n][0] for n in names])
                    bad = [n for n in names if res[n][1] != "ok"]
                    fails += bool(bad)
                    last = res
                    parts = []
                    for n in names:
                        v, st = res[n]
                        parts.append(f"{n}=[bold]{fmt_num(v)}[/]{units[n]}" if v is not None else f"{n}=[red]{st}[/]")
                    console.print(f"[cyan]{ts[11:]}[/] " + "  ".join(parts))
                    wait = interval - (time.monotonic() - tc)
                    if duration is not None:
                        wait = min(wait, duration - (time.monotonic() - t0))
                    if wait > 0:
                        time.sleep(wait)
            finally:
                s.json("summary.json", {"unit": cfg.name, "cycles": cycles, "cycles_with_errors": fails,
                                        "last": {k: {"value": v, "status": st} for k, (v, st) in last.items()}})
                console.print(f"\n{cycles} siklus, {fails} siklus dengan error.")


@app.command()
def version():
    """Versi mbprobe."""
    console.print(f"mbprobe {__version__} (read-only: FC 01/02/03/04)")


def main():
    if os.name == "nt":
        # output dialihkan ke file di Windows (cp1252) jangan sampai crash karena ✔/Ω
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass
    if len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty():
        from .repl import run  # mode interaktif: cukup ketik `mbprobe`
        run()
        return
    app()


if __name__ == "__main__":
    main()
