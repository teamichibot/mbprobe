"""Sniff pasif: HANYA membaca serial port, tidak pernah mengirim byte apa pun.

File ini sengaja tidak memanggil method kirim apa pun pada port (dicek oleh
tests/test_readonly.py).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

import serial

from .decode import Frame, parse_rtu_stream
from .protocol import hexs
from .transport_rtu import PortError, char_time, open_serial


@dataclass
class SniffStats:
    baud: int
    parity: str
    bytes_rx: int = 0
    frames: list[Frame] = field(default_factory=list)
    junk: list[bytes] = field(default_factory=list)
    duration: float = 0.0
    interrupted: bool = False

    @property
    def junk_bytes(self) -> int:
        return sum(len(j) for j in self.junk)

    @property
    def valid(self) -> int:
        return len(self.frames)

    def verdict(self) -> str:
        if self.bytes_rx == 0:
            return "sepi (tidak ada lalu lintas)"
        if self.valid == 0:
            return "ada lalu lintas non-Modbus atau baud/parity tidak cocok"
        if self.junk_bytes > self.bytes_rx // 2:
            return "ada frame Modbus valid, tapi banyak byte sampah (cek baud/parity/wiring)"
        return "lalu lintas Modbus RTU valid"


def sniff(port: str, baud: int, parity: str, duration: float, stopbits: float = 1,
          gap_ms: float | None = None, on_frame: Callable[[Frame], None] | None = None,
          on_junk: Callable[[bytes], None] | None = None, session=None,
          should_stop: Callable[[], bool] | None = None) -> SniffStats:
    """Dengarkan bus selama `duration` detik. Frame dipisah berdasarkan jeda antar byte."""
    tc = char_time(baud, parity, stopbits)
    t35 = max(3.5 * tc, 0.0015)
    # jeda untuk "flush" buffer: cukup panjang agar latency USB (≈16 ms FTDI) tidak memotong frame
    flush_gap = (gap_ms / 1000) if gap_ms else max(t35, 0.03)
    link = f"rtu:{port}@{baud}{parity}"
    stats = SniffStats(baud, parity)
    ser = open_serial(port, baud, parity, stopbits, timeout=min(0.01, t35))
    if session:
        session.log(f"SNIFF start {link} durasi={duration}s (pasif, tidak mengirim apa pun)")
    pending = bytearray()
    boundaries: list[int] = []
    t_first = None
    last_rx = 0.0
    t_start = time.monotonic()

    def flush():
        nonlocal pending, boundaries, t_first
        if not pending:
            return
        data = bytes(pending)
        frames, junk = parse_rtu_stream(data, boundaries)
        for f in frames:
            f.t = t_first
            stats.frames.append(f)
            if session:
                session.log(f"SNIFF {link} {f.kind} | {hexs(f.raw)}")
            if on_frame:
                on_frame(f)
        for _, j in junk:
            stats.junk.append(j)
            if session:
                session.log(f"SNIFF {link} raw/non-valid | {hexs(j)}")
            if on_junk:
                on_junk(j)
        pending = bytearray()
        boundaries = []
        t_first = None

    try:
        while time.monotonic() - t_start < duration:
            if should_stop and should_stop():
                break
            chunk = ser.read(ser.in_waiting or 1)
            now = time.monotonic()
            if chunk:
                if pending and now - last_rx >= flush_gap:
                    flush()
                elif pending and now - last_rx >= t35:
                    boundaries.append(len(pending))
                if t_first is None:
                    t_first = time.time()
                pending += chunk
                stats.bytes_rx += len(chunk)
                last_rx = now
            elif pending and now - last_rx >= flush_gap:
                flush()
        flush()
    except KeyboardInterrupt:
        flush()
        stats.interrupted = True
    except serial.SerialException as e:
        flush()
        raise PortError(f"Port {port} error/terputus saat sniff: {e}") from e
    finally:
        stats.duration = time.monotonic() - t_start
        ser.close()
        if session:
            session.log(
                f"SNIFF stop {link} bytes={stats.bytes_rx} frame_valid={stats.valid} "
                f"sampah={stats.junk_bytes}B → {stats.verdict()}"
            )
    return stats
