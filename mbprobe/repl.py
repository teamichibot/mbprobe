"""Mode interaktif: ketik `mbprobe` tanpa argumen.

Memakai command CLI yang sama (jaminan read-only identik), ditambah:
- banner + toolbar status koneksi
- autocomplete perintah/opsi/port (bisa diawali '/' seperti Claude Code)
- koneksi aktif disimpan, jadi `read --addr 300` tidak perlu mengulang --rtu/--baud/--id
- setelah scan/sniff, hasilnya ditawarkan untuk langsung dipakai sebagai koneksi
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory, InMemoryHistory
from prompt_toolkit.shortcuts import choice
from prompt_toolkit.styles import Style
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .cli import app, console

BAUDS = ["9600", "19200", "38400", "57600", "115200", "4800", "2400"]
PARITIES = {"N": "None", "E": "Even", "O": "Odd"}
FCS = {"3": "Holding registers", "4": "Input registers", "1": "Coils", "2": "Discrete inputs"}

ALIASES = {"scan": "scan-rtu", "find": "find-value", "?": "help", "quit": "exit", "keluar": "exit",
           "q": "exit", "cls": "clear"}
CONN_CMDS = {"read", "dump", "find-value"}  # butuh --rtu/--tcp
PORT_CMDS = {"sniff", "scan-rtu"}  # butuh --port

LOCAL_CMDS = {
    "connect": "Atur koneksi aktif (RTU/TCP) — tanpa argumen: wizard",
    "status": "Tampilkan koneksi & sesi aktif",
    "label": "Set label sesi, mis. `label ZR250`",
    "timeout": "Set timeout koneksi aktif (detik), mis. `timeout 2` untuk device lambat",
    "open": "Buka folder sesi terakhir",
    "help": "Daftar perintah & contoh",
    "clear": "Bersihkan layar",
    "exit": "Keluar (atau Ctrl+D)",
}

STYLE = Style.from_dict({
    "prompt": "#d97757 bold",
    "bottom-toolbar": "noreverse #888888 bg:default",
    "tb.key": "#d97757",
    "tb.conn": "#5fafd7 bold",
    "tb.none": "#888888 italic",
    "completion-menu.completion": "bg:#262626 #d0d0d0",
    "completion-menu.completion.current": "bg:#d97757 #000000",
    "completion-menu.meta.completion": "bg:#262626 #888888",
    "completion-menu.meta.completion.current": "bg:#d97757 #000000",
})


@dataclass
class Ctx:
    kind: str | None = None  # "rtu" | "tcp"
    port: str = ""
    baud: int = 9600
    parity: str = "N"
    stopbits: float = 1.0
    slave: int = 1
    timeout: float | None = None  # None = default command
    host: str = ""
    tcp_port: int = 502
    label: str = ""
    out: str = "sessions"
    last_session: Path | None = None

    def describe(self) -> str:
        if self.kind == "rtu":
            sb = int(self.stopbits) if self.stopbits == int(self.stopbits) else self.stopbits
            tmo = f" · timeout {self.timeout:g}s" if self.timeout else ""
            return f"RTU {self.port} {self.baud} {self.parity}{sb} · ID {self.slave}{tmo}"
        if self.kind == "tcp":
            return f"TCP {self.host}:{self.tcp_port} · unit {self.slave}"
        if self.port:
            return f"port {self.port} (belum ada device)"
        return ""

    def conn_args(self) -> list[str]:
        t = ["--timeout", f"{self.timeout:g}"] if self.timeout else []
        if self.kind == "rtu":
            return ["--rtu", self.port, "--baud", str(self.baud), "--parity", self.parity,
                    "--stopbits", str(self.stopbits), "--id", str(self.slave), *t]
        if self.kind == "tcp":
            return ["--tcp", self.host, "--tcp-port", str(self.tcp_port), "--unit", str(self.slave), *t]
        return []


# ---------------------------------------------------------------- util


def _group():
    return typer.main.get_group(app)


def _comports():
    try:
        from serial.tools import list_ports
        return sorted(list_ports.comports(), key=lambda p: p.device)
    except Exception:
        return []


def _serial_ports() -> list[tuple[str, str]]:
    return [(p.device, p.description or "") for p in _comports()]


def _likely_adapters(ports: list[tuple[str, str]] | None = None) -> list[tuple[str, str]]:
    """Hanya port USB (punya VID) — sembunyikan Bluetooth/debug port bawaan laptop."""
    return [(p.device, p.description or "") for p in _comports()
            if p.vid is not None and not p.device.startswith("/dev/tty.")]


def _has(tokens: list[str], *opts: str) -> bool:
    return any(t == o or t.startswith(o + "=") for t in tokens for o in opts)


def _sessions(out: str) -> set[Path]:
    p = Path(out)
    return {d for d in p.iterdir() if d.is_dir()} if p.exists() else set()


def _summary(d: Path | None) -> dict:
    import json
    try:
        return json.loads((d / "summary.json").read_text(encoding="utf-8")) if d else {}
    except (OSError, ValueError):
        return {}


def _ask_choice(message: str, options: list[tuple[str, str]], default=None):
    """Menu pilih pakai panah. Return None kalau dibatalkan (Ctrl+C / Esc)."""
    try:
        return choice(message=HTML(f"<b>{message}</b>"), options=[(v, l) for v, l in options], default=default,
                      style=STYLE, symbol="›")
    except (KeyboardInterrupt, EOFError):
        return None


def _ask_text(session: PromptSession, message: str, default: str = "", completer=None) -> str | None:
    try:
        return session.prompt(HTML(f"<prompt>{message}</prompt> "), default=default, completer=completer,
                              bottom_toolbar=None).strip()
    except (KeyboardInterrupt, EOFError):
        return None


def _ask_yes(session: PromptSession, message: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    ans = _ask_text(session, f"{message} [{hint}]")
    if ans is None:
        return False
    if not ans:
        return default
    return ans.lower() in ("y", "ya", "yes", "iya")


@contextmanager
def _no_echo():
    """Saat command jalan, ketikan tidak ditampilkan (tetap ditampung untuk prompt berikutnya)."""
    if os.name == "nt" or not sys.stdin.isatty():
        yield
        return
    import termios
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        yield
        return
    new = list(old)
    new[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(fd, termios.TCSANOW, new)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)


# ---------------------------------------------------------------- completer


class MbCompleter(Completer):
    def __init__(self):
        grp = _group()
        self.cmds: dict[str, str] = {}
        self.opts: dict[str, list[tuple[str, str]]] = {}
        for name, cmd in grp.commands.items():
            self.cmds[name] = (cmd.help or "").strip().splitlines()[0] if cmd.help else ""
            items = []
            for prm in cmd.params:
                for o in getattr(prm, "opts", []):
                    if o.startswith("--"):
                        items.append((o, (getattr(prm, "help", "") or "")))
            self.opts[name] = items
        self.cmds.pop("version", None)
        for k, v in LOCAL_CMDS.items():
            self.cmds[k] = v

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        slash = text.startswith("/")
        body = text[1:] if slash else text
        try:
            words = shlex.split(body) if body.strip() else []
        except ValueError:
            words = body.split()
        if body.endswith(" "):
            words.append("")
        if len(words) <= 1:
            cur = words[0] if words else ""
            for name, meta in self.cmds.items():
                if name.startswith(cur):
                    yield Completion(name, start_position=-len(cur), display=("/" if slash else "") + name,
                                     display_meta=meta)
            return
        cmd = ALIASES.get(words[0], words[0])
        cur, prev = words[-1], words[-2]
        values = self._values(cmd, prev, words)
        if values is not None:
            for v, meta in values:
                if v.lower().startswith(cur.lower()):
                    yield Completion(v, start_position=-len(cur), display_meta=meta)
            return
        if cmd in self.opts and (cur.startswith("-") or cur == ""):
            used = set(words[1:-1])
            for o, meta in self.opts[cmd]:
                if o.startswith(cur) and o not in used:
                    yield Completion(o, start_position=-len(cur), display_meta=meta)

    @staticmethod
    def _values(cmd: str, prev: str, words: list[str]):
        if cmd == "connect":
            pos = len(words) - 2  # index argumen setelah 'connect'
            if pos == 0:
                return [("rtu", "Modbus RTU / RS485"), ("tcp", "Modbus TCP / Ethernet")]
            if pos == 1 and words[1] == "rtu":
                return _serial_ports()
            if pos == 2 and words[1] == "rtu":
                return [(b, "") for b in BAUDS]
            if pos == 3 and words[1] == "rtu":
                return list(PARITIES.items())
            return []
        if prev in ("--port", "--rtu"):
            return _serial_ports()
        if prev in ("--baud", "-b"):
            return [(b, "") for b in BAUDS]
        if prev in ("--bauds",):
            return [("9600,19200,38400", "default"), ("9600,19200,38400,57600,115200", "semua umum")]
        if prev in ("--parity", "-p"):
            return list(PARITIES.items()) + ([("N,E", "default scan"), ("N,E,O", "semua")]
                                             if cmd == "scan-rtu" else [])
        if prev == "--fc":
            return list(FCS.items())
        if prev == "--ids":
            return [("1-32", "cepat"), ("1-247", "penuh")]
        if prev in ("--config", "-c"):
            files = sorted(str(p) for pat in ("*.yaml", "*.yml", "examples/*.yaml") for p in Path(".").glob(pat))
            return [(f, "") for f in files]
        if cmd == "label" and len(words) == 2:
            return []
        return None


# ---------------------------------------------------------------- REPL


class Repl:
    def __init__(self, history_file: Path | None = None, input=None, output=None):
        self.ctx = Ctx()
        self.completer = MbCompleter()
        hist = InMemoryHistory()
        if history_file is not None:
            try:
                history_file.parent.mkdir(parents=True, exist_ok=True)
                hist = FileHistory(str(history_file))
            except OSError:
                pass
        kw = {}
        if input is not None:
            kw["input"] = input
        if output is not None:
            kw["output"] = output
        self.session = PromptSession(history=hist, completer=self.completer, complete_while_typing=True,
                                     style=STYLE, bottom_toolbar=self._toolbar, reserve_space_for_menu=8, **kw)
        self.running = True

    # ------------------------------------------------ tampilan

    def _toolbar(self):
        conn = self.ctx.describe()
        c = f"<tb.conn>{conn}</tb.conn>" if conn else "<tb.none>belum ada koneksi — ketik connect atau scan</tb.none>"
        lab = f" · sesi <b>{self.ctx.label}</b>" if self.ctx.label else ""
        return HTML(f" {c}{lab}   <tb.key>Tab</tb.key> lengkapi · <tb.key>↑</tb.key> riwayat · "
                    f"<tb.key>/help</tb.key> · <tb.key>Ctrl+D</tb.key> keluar")

    def banner(self) -> None:
        ports = _likely_adapters()
        t = Text()
        t.append("✻ ", style="bold #d97757")
        t.append("mbprobe", style="bold")
        t.append(f"  v{__version__}\n\n", style="dim")
        t.append("Modbus probe untuk genba — ", style="")
        t.append("READ-ONLY", style="bold green")
        t.append(" (hanya FC 01/02/03/04)\n", style="")
        t.append(f"cwd: {Path.cwd()}\n", style="dim")
        console.print(Panel(t, border_style="#d97757", padding=(0, 2), expand=False))
        if ports:
            console.print(" [dim]Port serial terdeteksi:[/] " + ", ".join(f"[bold]{d}[/] [dim]{desc}[/]" for d, desc in ports))
        else:
            console.print(" [dim]Belum ada adaptor USB-RS485 terdeteksi.[/]")
        console.print(" [dim]Mulai:[/] [bold]sniff --auto[/] [dim]→[/] [bold]scan[/] [dim]→[/] [bold]read[/] / "
                      "[bold]find --value 82826[/] [dim]→[/] [bold]dump[/]   [dim]· ketik[/] [bold]/help[/] "
                      "[dim]untuk semua perintah[/]\n")

    def help(self) -> None:
        tb = Table(box=None, show_header=False, padding=(0, 2))
        tb.add_column(style="bold #d97757")
        tb.add_column()
        tb.add_column(style="dim")
        rows = [
            ("connect", "Atur koneksi (wizard)", "connect rtu COM5 9600 N 1 · connect tcp 192.168.1.50"),
            ("ports", "Daftar serial port", ""),
            ("sniff", "Dengarkan bus secara pasif", "sniff --auto · sniff --duration 30"),
            ("scan", "Cari device RTU (baud × parity × ID)", "scan · scan --ids 1-247 --parity N,E,O"),
            ("scan-tcp", "Cari device Modbus TCP", "scan-tcp --subnet 192.168.1.0/24"),
            ("read", "Baca blok + semua interpretasi", "read --addr 0 --count 10 --fc 4"),
            ("find", "Cari nilai dari layar controller", "find --value 82826 --value 3.7 --to 2000"),
            ("dump", "Petakan rentang alamat", "dump --from 0 --to 2000 --fc 3"),
            ("poll", "Log berkala dari config YAML", "poll --config unit.yaml --interval 5"),
            ("label", "Label sesi untuk folder hasil", "label ZR250"),
            ("timeout", "Timeout koneksi aktif", "timeout 2  (device lambat)"),
            ("status", "Koneksi & sesi aktif", ""),
            ("open", "Buka folder sesi terakhir", ""),
            ("exit", "Keluar", "atau Ctrl+D"),
        ]
        for r in rows:
            tb.add_row(*r)
        console.print(tb)
        console.print("\n [dim]Koneksi aktif otomatis dipakai. Tambah [/]--help[dim] di belakang perintah untuk semua "
                      "opsi, mis. [/]read --help[dim]. Ctrl+C menghentikan perintah yang sedang jalan.[/]\n")

    def status(self) -> None:
        c = self.ctx
        console.print(f" Koneksi : [bold]{c.describe() or '-'}[/]")
        console.print(f" Label   : {c.label or '-'}")
        console.print(f" Output  : {Path(c.out).resolve()}")
        console.print(f" Sesi terakhir: {c.last_session or '-'}\n")

    # ------------------------------------------------ perintah lokal

    def cmd_connect(self, args: list[str]) -> None:
        c = self.ctx
        if args and args[0] == "rtu":
            try:
                c.port = args[1] if len(args) > 1 else c.port
                c.baud = int(args[2]) if len(args) > 2 else c.baud
                c.parity = args[3].upper() if len(args) > 3 else c.parity
                c.slave = int(args[4]) if len(args) > 4 else c.slave
            except ValueError:
                console.print("[red]Format: connect rtu <port> [baud] [parity] [id][/]")
                return
            if not c.port:
                console.print("[red]Port wajib: connect rtu COM5[/]")
                return
            c.kind = "rtu"
        elif args and args[0] == "tcp":
            if len(args) < 2:
                console.print("[red]Format: connect tcp <ip> [port] [unit][/]")
                return
            try:
                c.host = args[1]
                c.tcp_port = int(args[2]) if len(args) > 2 else 502
                c.slave = int(args[3]) if len(args) > 3 else 1
            except ValueError:
                console.print("[red]Format: connect tcp <ip> [port] [unit][/]")
                return
            c.kind = "tcp"
        elif not args:
            if not self._wizard():
                console.print("[dim]Dibatalkan.[/]")
                return
        else:
            console.print("[red]Format: connect rtu <port> [baud] [parity] [id]  ·  connect tcp <ip> [port] [unit][/]")
            return
        console.print(f"[green]✔[/] Koneksi aktif: [bold]{c.describe()}[/]  [dim](port hanya dibuka saat perintah jalan)[/]")

    def _pick_port(self) -> str | None:
        ports = _serial_ports()
        opts = [(d, f"{d}  {desc}") for d, desc in _likely_adapters() or ports]
        opts.append(("__manual__", "Ketik manual…"))
        p = _ask_choice("Serial port", opts, default=self.ctx.port or None)
        if p == "__manual__":
            p = _ask_text(self.session, "Port:", self.ctx.port)
        return p or None

    def _wizard(self) -> bool:
        c = self.ctx
        kind = _ask_choice("Jenis koneksi", [("rtu", "RTU — RS485 (USB-RS485)"), ("tcp", "TCP — Ethernet")],
                           default=c.kind or "rtu")
        if kind is None:
            return False
        if kind == "rtu":
            port = self._pick_port()
            if not port:
                return False
            baud = _ask_choice("Baud rate", [(int(b), b) for b in BAUDS], default=c.baud)
            if baud is None:
                return False
            parity = _ask_choice("Parity", [(k, f"{k} — {v}") for k, v in PARITIES.items()], default=c.parity)
            if parity is None:
                return False
            sid = _ask_text(self.session, "Slave ID:", str(c.slave))
            if sid is None or not sid.isdigit():
                return False
            c.kind, c.port, c.baud, c.parity, c.slave = "rtu", port, baud, parity, int(sid)
            return True
        host = _ask_text(self.session, "IP device:", c.host)
        if not host:
            return False
        port = _ask_text(self.session, "Port TCP:", str(c.tcp_port))
        unit = _ask_text(self.session, "Unit ID:", str(c.slave))
        if not (port or "").isdigit() or not (unit or "").isdigit():
            return False
        c.kind, c.host, c.tcp_port, c.slave = "tcp", host, int(port), int(unit)
        return True

    def cmd_open(self) -> None:
        d = self.ctx.last_session
        if not d or not d.exists():
            console.print("[dim]Belum ada sesi.[/]")
            return
        try:
            if os.name == "nt":
                os.startfile(str(d))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(d)])
            console.print(f"[dim]Membuka {d}[/]")
        except Exception as e:
            console.print(f"[red]Gagal membuka folder: {e}[/]")

    # ------------------------------------------------ jalankan command CLI

    def build_args(self, cmd: str, tokens: list[str]) -> list[str] | None:
        c = self.ctx
        args = list(tokens)
        wants_help = _has(args, "--help")
        if not wants_help:
            if cmd in CONN_CMDS and not _has(args, "--rtu", "--tcp"):
                if not c.kind:
                    console.print("[yellow]Belum ada koneksi.[/] Ketik [bold]connect[/] atau jalankan [bold]scan[/] dulu.")
                    return None
                args += c.conn_args()
            if cmd in PORT_CMDS and not _has(args, "--port"):
                port = c.port or self._pick_port()
                if not port:
                    return None
                c.port = port
                args += ["--port", port]
            if cmd == "sniff" and not _has(args, "--auto", "--baud", "-b") and c.kind == "rtu":
                args += ["--baud", str(c.baud), "--parity", c.parity]
            if cmd == "poll" and not _has(args, "--port") and c.kind == "rtu" and c.port:
                pass  # poll memakai port dari config; override hanya kalau user minta --port
            if cmd != "ports":
                if c.label and not _has(args, "--label", "-l"):
                    args += ["--label", c.label]
                if not _has(args, "--out"):
                    args += ["--out", c.out]
        return args

    def run_cli(self, cmd: str, tokens: list[str]) -> None:
        args = self.build_args(cmd, tokens)
        if args is None:
            return
        before = _sessions(self.ctx.out)
        try:
            with _no_echo():
                _group().main(args=[cmd, *args], prog_name="mbprobe", standalone_mode=False)
        except typer.Abort:
            console.print("[dim]Dibatalkan.[/]")
        except KeyboardInterrupt:
            console.print("[yellow]Dihentikan.[/]")
        except typer._click.exceptions.ClickException as e:
            from typer import rich_utils
            rich_utils.rich_format_error(e)
        except SystemExit:
            pass
        new = sorted(_sessions(self.ctx.out) - before)
        if new:
            self.ctx.last_session = new[-1]
            self.after(cmd, args, new[-1])
        console.print()

    def after(self, cmd: str, args: list[str], d: Path) -> None:
        """Tawarkan langkah berikutnya berdasarkan hasil."""
        s = _summary(d)
        c = self.ctx
        if cmd == "scan-rtu":
            hits = s.get("hits") or []
            if not hits:
                return
            port = args[args.index("--port") + 1]
            if len(hits) == 1:
                h = hits[0]
            else:
                h = _ask_choice("Pakai device mana sebagai koneksi?",
                                [(i, f"{x['baud']} {x['parity']} · ID {x['slave']} · FC{x['fc']:02d} · {x['detail']}")
                                 for i, x in enumerate(hits)] + [(-1, "Tidak sekarang")], default=0)
                if h is None or h == -1:
                    return
                h = hits[h]
            if len(hits) > 1 or _ask_yes(self.session, f"Pakai {h['baud']} {h['parity']} ID {h['slave']} sebagai koneksi?"):
                c.kind, c.port, c.baud, c.parity, c.slave = "rtu", port, h["baud"], h["parity"], h["slave"]
                # device lambat → simpan timeout yang cukup supaya read/find/dump berikutnya andal
                late_ms = [x.get("delay_ms") or 0 for x in s.get("late", [])]
                c.timeout = max(3.0, max(late_ms) / 1000 * 2) if late_ms else None  # None = default 2 s
                console.print(f"[green]✔[/] Koneksi aktif: [bold]{c.describe()}[/]")
                fc = h.get("fc") or 3
                if h.get("status") == "ok":
                    console.print(f" [dim]Lanjut:[/] [bold]read --fc {fc} --addr {s.get('probe_addr', 0)} --count 10[/]"
                                  f"  [dim]atau[/]  [bold]find --fc {fc} --value <angka di layar>[/]")
                else:
                    console.print(f" [dim]Lanjut: petakan alamat valid →[/] [bold]dump --fc 3 --to 100[/]  [dim]lalu[/]  "
                                  "[bold]dump --fc 4 --to 100[/]")
        elif cmd == "scan-tcp":
            found = [(h["host"], m) for h in s.get("hosts", []) for m in h.get("modbus", [])
                     if m.get("status") in ("ok", "exception")]
            if not found:
                return
            mport = int(args[args.index("--modbus-port") + 1]) if "--modbus-port" in args else 502
            pick = _ask_choice("Pakai host mana sebagai koneksi?",
                               [(i, f"{h} · unit {m['unit']} · {m['detail']}") for i, (h, m) in enumerate(found)]
                               + [(-1, "Tidak sekarang")], default=0)
            if pick is None or pick == -1:
                return
            host, m = found[pick]
            c.kind, c.host, c.tcp_port, c.slave = "tcp", host, mport, m["unit"]
            console.print(f"[green]✔[/] Koneksi aktif: [bold]{c.describe()}[/]")
        elif cmd == "sniff" and s.get("best"):
            b = s["best"]
            if _ask_yes(self.session, f"Simpan {b['baud']} {b['parity']} sebagai setting port? (bus dipakai master lain — "
                                      "hati-hati polling)", default=False):
                c.baud, c.parity = b["baud"], b["parity"]
                port = args[args.index("--port") + 1]
                c.port = port
                slaves = next((r["slaves"] for r in s.get("results", [])
                               if (r["baud"], r["parity"]) == (b["baud"], b["parity"])), [])
                if slaves:
                    c.kind, c.slave = "rtu", slaves[0]
                console.print(f"[green]✔[/] {c.describe()}")

    # ------------------------------------------------ loop

    def handle(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if line.startswith("/"):
            line = line[1:]
        try:
            tokens = shlex.split(line, posix=os.name != "nt")
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            return
        if os.name == "nt":
            tokens = [t.strip('"') for t in tokens]
        cmd, rest = ALIASES.get(tokens[0], tokens[0]), tokens[1:]
        if cmd == "exit":
            self.running = False
        elif cmd == "help":
            self.help()
        elif cmd == "clear":
            console.clear()
        elif cmd == "status":
            self.status()
        elif cmd == "connect":
            self.cmd_connect(rest)
        elif cmd == "timeout":
            try:
                self.ctx.timeout = float(rest[0]) if rest else None
                console.print(f"[green]✔[/] Timeout: [bold]{self.ctx.timeout or 'default'}[/]")
            except ValueError:
                console.print("[red]Format: timeout 2[/]")
        elif cmd == "label":
            self.ctx.label = " ".join(rest)
            console.print(f"[green]✔[/] Label sesi: [bold]{self.ctx.label or '-'}[/]")
        elif cmd == "open":
            self.cmd_open()
        elif cmd in _group().commands:
            self.run_cli(cmd, rest)
        else:
            console.print(f"[red]Perintah tidak dikenal:[/] {tokens[0]}  [dim]· ketik /help[/]")

    def loop(self) -> None:
        self.banner()
        while self.running:
            try:
                console.rule(style="#3a3a3a")
                line = self.session.prompt(HTML("<prompt>›</prompt> "))
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            self.handle(line)
        console.print("[dim]Sampai jumpa. Hasil ada di folder sessions/.[/]")


def run() -> None:
    from . import cli
    cli.INTERACTIVE = True
    hist = Path.home() / ".mbprobe" / "history"
    Repl(history_file=hist).loop()
