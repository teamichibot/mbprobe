"""scan-rtu, scan-tcp, dan pembacaan rentang register (dump/find-value)."""
from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .protocol import EXCEPTION_NAMES, Result, max_count
from .transport_rtu import RtuTransport
from .transport_tcp import TcpTransport, port_open

# Batas minimum yang tidak bisa diturunkan lewat opsi CLI.
MIN_POLL_INTERVAL = 0.5
MIN_SCAN_DELAY = 0.05
DEFAULT_SCAN_DELAY = 0.1
DEFAULT_POLL_INTERVAL = 5.0


def clamp_delay(value: float, minimum: float, name: str, warn: Callable[[str], None] | None = None) -> float:
    if value < minimum:
        if warn:
            warn(f"{name} {value}s di bawah batas aman, dinaikkan ke {minimum}s.")
        return minimum
    return value


def parse_int_list(spec: str, lo: int = 0, hi: int = 0xFFFF) -> list[int]:
    """'1-5,10,247' → [1,2,3,4,5,10,247]"""
    out: list[int] = []
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            out.extend(range(a, b + 1))
        else:
            out.append(int(part))
    bad = [x for x in out if not lo <= x <= hi]
    if bad:
        raise ValueError(f"nilai {bad[:5]} di luar {lo}..{hi}")
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- scan RTU

@dataclass
class RtuHit:
    baud: int
    parity: str
    slave: int
    fc: int
    status: str
    detail: str
    values: list[int] = field(default_factory=list)
    exc_code: int | None = None


@dataclass
class ScanReport:
    hits: list = field(default_factory=list)
    crc_hints: dict = field(default_factory=dict)  # (baud, parity) -> jumlah crc_error
    echo: bool = False
    attempts: int = 0
    interrupted: bool = False
    error: str = ""
    extra: dict = field(default_factory=dict)


def _hit_detail(r: Result) -> str:
    if r.status == "ok":
        return f"OK value={r.values}"
    return f"EXCEPTION {r.exc_code:02d} {EXCEPTION_NAMES.get(r.exc_code, '?')}"


def scan_rtu(port: str, bauds: list[int], parities: list[str], ids: list[int], timeout: float,
             delay: float, stopbits: float = 1, stop_on_first: bool = False, session=None,
             on_hit: Callable[[RtuHit], None] | None = None,
             on_attempt: Callable[[int, str], None] | None = None) -> ScanReport:
    rep = ScanReport()
    try:
        for baud in bauds:
            for parity in parities:
                key = (baud, parity)
                if session:
                    session.log(f"SCAN combo {baud} {parity}")
                with RtuTransport(port, baud, parity, stopbits, timeout, session=session) as t:
                    for sid in ids:
                        hit = None
                        for fc in (3, 4):
                            r = t.request(sid, fc, 0, 1)
                            rep.attempts += 1
                            if r.status == "crc_error":
                                rep.crc_hints[key] = rep.crc_hints.get(key, 0) + 1
                            if r.responded:
                                hit = RtuHit(baud, parity, sid, fc, r.status, _hit_detail(r), r.values, r.exc_code)
                                break
                            time.sleep(delay)
                        if on_attempt:
                            on_attempt(sid, f"{baud} {parity}")
                        if hit:
                            rep.hits.append(hit)
                            if on_hit:
                                on_hit(hit)
                            if stop_on_first:
                                rep.echo = rep.echo or t.echo_seen
                                return rep
                            time.sleep(delay)
                    rep.echo = rep.echo or t.echo_seen
    except KeyboardInterrupt:
        rep.interrupted = True
    return rep


def estimate_rtu_seconds(n_combos: int, n_ids: int, timeout: float, delay: float) -> float:
    """Worst case: tiap ID tidak menjawab FC03 dan FC04."""
    return n_combos * n_ids * 2 * (timeout + delay)


# ---------------------------------------------------------------- scan TCP

@dataclass
class TcpHost:
    host: str
    open_ports: list[int]
    modbus: list[dict] = field(default_factory=list)  # [{unit, fc, status, detail}]


def expand_hosts(subnet: str | None, host: str | None) -> list[str]:
    if host:
        return [host]
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > 4096:
        raise ValueError(f"subnet {subnet} terlalu besar ({net.num_addresses} alamat); maksimum /20")
    hosts = list(net.hosts()) or [net.network_address]
    return [str(h) for h in hosts]


def scan_tcp(hosts: list[str], ports: list[int], unit_ids: list[int], connect_timeout: float,
             timeout: float, delay: float, modbus_port: int = 502, workers: int = 32, session=None,
             on_host: Callable[[TcpHost], None] | None = None,
             on_progress: Callable[[int], None] | None = None) -> ScanReport:
    rep = ScanReport()
    found: list[TcpHost] = []
    check_ports = list(dict.fromkeys(ports + [modbus_port]))

    def probe(h: str) -> TcpHost | None:
        opened = [p for p in check_ports if port_open(h, p, connect_timeout)]
        return TcpHost(h, opened) if opened else None

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for h in ex.map(probe, hosts):
                if on_progress:
                    on_progress(1)
                if h:
                    found.append(h)
                    if session:
                        session.log(f"TCP host {h.host} port terbuka {h.open_ports}")
        for h in found:
            if modbus_port in h.open_ports:
                with TcpTransport(h.host, modbus_port, timeout, session=session) as t:
                    for unit in unit_ids:
                        for fc in (3, 4):
                            r = t.request(unit, fc, 0, 1)
                            rep.attempts += 1
                            time.sleep(delay)
                            entry = {"unit": unit, "fc": fc, "status": r.status,
                                     "detail": _hit_detail(r) if r.responded else r.describe()}
                            if r.responded:
                                h.modbus.append(entry)
                                break
                            if fc == 4:
                                h.modbus.append(entry)
            rep.hits.append(h)
            if on_host:
                on_host(h)
    except KeyboardInterrupt:
        rep.interrupted = True
        for h in found:
            if h not in rep.hits:
                rep.hits.append(h)
    return rep


# ---------------------------------------------------------------- dump / range read

@dataclass
class RegRow:
    addr: int
    value: int | None
    status: str  # ok | exception | timeout | crc_error | ...
    exc_code: int | None = None


class DeviceSilent(Exception):
    pass


def read_range(t, slave: int, fc: int, start: int, end: int, block: int, delay: float,
               on_row: Callable[[RegRow], None], max_silent: int = 6,
               on_progress: Callable[[int], None] | None = None, stats: dict | None = None) -> dict:
    """Baca start..end (inklusif) per blok; blok yang exception/timeout dipecah sampai per register.

    Return statistik. Lempar DeviceSilent bila device tidak menjawab berturut-turut.
    """
    block = max(1, min(block, max_count(fc)))
    if stats is None:
        stats = {}
    for k in ("requests", "ok", "exception", "timeout", "crc_error", "other"):
        stats.setdefault(k, 0)
    silent = 0

    def do(addr: int, count: int, retried: bool = False):
        nonlocal silent
        r = t.request(slave, fc, addr, count)
        stats["requests"] += 1
        time.sleep(delay)
        if r.status == "ok":
            silent = 0
            for i, v in enumerate(r.values):
                on_row(RegRow(addr + i, v, "ok"))
            stats["ok"] += count
            if on_progress:
                on_progress(count)
            return
        if r.status == "exception":
            silent = 0
            if count > 1:
                half = count // 2
                do(addr, half)
                do(addr + half, count - half)
                return
            on_row(RegRow(addr, None, "exception", r.exc_code))
            stats["exception"] += 1
            if on_progress:
                on_progress(1)
            return
        # timeout / crc_error / invalid / port_error
        silent += 1
        if silent >= max_silent:
            raise DeviceSilent(
                f"{silent} request berturut-turut tanpa jawaban valid (terakhir: {r.status} di alamat {addr})."
            )
        if not retried:
            return do(addr, count, True)
        if count > 1:
            half = count // 2
            do(addr, half)
            do(addr + half, count - half)
            return
        key = r.status if r.status in stats else "other"
        stats[key] += 1
        on_row(RegRow(addr, None, r.status))
        if on_progress:
            on_progress(1)

    a = start
    while a <= end:
        n = min(block, end - a + 1)
        do(a, n)
        a += n
    return stats


def compress_ranges(rows: list[RegRow]) -> list[dict]:
    """Kompres baris per alamat menjadi rentang berurutan dengan status sama."""
    out: list[dict] = []
    for row in sorted(rows, key=lambda r: r.addr):
        st = row.status if row.status != "exception" else f"exception {row.exc_code}"
        if out and out[-1]["status"] == st and out[-1]["to"] == row.addr - 1:
            out[-1]["to"] = row.addr
        else:
            out.append({"from": row.addr, "to": row.addr, "status": st})
    return out
