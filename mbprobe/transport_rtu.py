"""Modbus RTU master read-only di atas pyserial.

Membedakan ok / exception / timeout / crc_error, dan otomatis membuang echo
dari adaptor RS485 yang memantulkan byte yang dikirim.
"""
from __future__ import annotations

import os
import subprocess
import time

import serial

from .protocol import (
    Result,
    build_rtu_request,
    check_read_fc,
    crc_ok,
    expected_rtu_len,
    parse_pdu_response,
)

PARITY = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}


class PortError(Exception):
    """Port serial tidak bisa dibuka / terputus. Pesan sudah ramah pengguna."""


def char_time(baud: int, parity: str = "N", stopbits: float = 1) -> float:
    bits = 1 + 8 + (0 if parity.upper() == "N" else 1) + stopbits
    return bits / baud


def open_serial(port: str, baud: int, parity: str, stopbits: float = 1, timeout: float = 0.02) -> serial.Serial:
    parity = parity.upper()
    if parity not in PARITY:
        raise ValueError(f"Parity '{parity}' tidak dikenal (pakai N, E, atau O)")
    try:
        return serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=8,
            parity=PARITY[parity],
            stopbits=stopbits,
            timeout=timeout,
        )
    except serial.SerialException as e:
        msg = str(e)
        hint = "Cek nama port dengan `mbprobe ports`."
        low = msg.lower()
        if "busy" in low or "access is denied" in low or "in use" in low:
            owners = port_owners(port)
            who = f" Dipegang oleh: {', '.join(owners)}." if owners else ""
            hint = ("Port sedang dipakai program lain (Node-RED, Modbus Poll, PuTTY, Arduino IDE, "
                    f"atau mbprobe lain) — tutup/stop dulu.{who}")
        elif "permission" in low:
            hint = "Tidak ada izin akses port. Di Linux: sudo usermod -aG dialout $USER lalu login ulang."
        raise PortError(f"Tidak bisa membuka {port}: {msg}. {hint}") from e


def port_owners(port: str) -> list[str]:
    """Nama proses yang sedang membuka port (Linux/macOS via lsof). Di macOS cek juga pasangan tty/cu."""
    if os.name == "nt":
        return []
    paths = {port}
    if port.startswith("/dev/cu."):
        paths.add(port.replace("/dev/cu.", "/dev/tty.", 1))
    elif port.startswith("/dev/tty."):
        paths.add(port.replace("/dev/tty.", "/dev/cu.", 1))
    try:
        out = subprocess.run(["lsof", "-Fpc", *sorted(paths)], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    owners, pid = [], ""
    for line in out.splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("c"):
            owners.append(f"{line[1:]} (PID {pid})")
    return list(dict.fromkeys(owners))


class RtuTransport:
    kind = "rtu"

    def __init__(self, port: str, baud: int = 9600, parity: str = "N", stopbits: float = 1,
                 timeout: float = 1.0, session=None):
        self.port = port
        self.baud = baud
        self.parity = parity.upper()
        self.stopbits = stopbits
        self.timeout = timeout
        self.session = session
        self.echo_seen = False
        self._ser = open_serial(port, baud, self.parity, stopbits)
        self._t_char = char_time(baud, self.parity, stopbits)
        self._last_io = 0.0
        self._prev: tuple[int, int, float] | None = None  # (slave, fc, waktu kirim) request sebelumnya
        self.late: list[dict] = []  # balasan yang datang setelah timeout

    @property
    def link(self) -> str:
        sb = int(self.stopbits) if self.stopbits == int(self.stopbits) else self.stopbits
        return f"rtu:{self.port}@{self.baud}{self.parity}{sb}"

    def close(self) -> None:
        try:
            self._ser.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _silence(self) -> None:
        """Jaga jeda >= 3,5 karakter antar frame."""
        gap = max(3.5 * self._t_char, 0.002)
        wait = self._last_io + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def request(self, slave: int, fc: int, addr: int, count: int) -> Result:
        check_read_fc(fc)
        tx = build_rtu_request(slave, fc, addr, count)
        if tx[1] not in (1, 2, 3, 4):  # pertahanan berlapis: frame tulis tidak pernah dikirim
            raise AssertionError("frame non-read")
        r = Result(status="timeout", fc=fc, addr=addr, count=count, slave=slave, tx=tx)
        t0 = time.monotonic()
        try:
            self._silence()
            self._check_stale()
            self._ser.reset_input_buffer()
            if self.session:
                self.session.log_tx(self.link, tx, f"id={slave} fc={fc} addr={addr} count={count}")
            self._ser.write(tx)
            self._ser.flush()
            t_sent = time.monotonic()
            buf = bytearray()
            # waktu kirim request + estimasi panjang response maksimum + timeout pengguna
            exp_bytes = 5 + (2 * count if fc in (3, 4) else (count + 7) // 8)
            deadline = time.monotonic() + self.timeout + (len(tx) + exp_bytes) * self._t_char
            while True:
                chunk = self._ser.read(self._ser.in_waiting or 1)
                if chunk:
                    buf += chunk
                    done = self._try_parse(bytes(buf), tx, r)
                    if done:
                        break
                if time.monotonic() > deadline:
                    self._classify_failure(bytes(buf), tx, r)
                    break
        except serial.SerialException as e:
            raise PortError(
                f"Port {self.port} error/terputus: {e}. Cek kabel USB adaptor, lalu jalankan ulang."
            ) from e
        except OSError as e:
            raise PortError(f"Port {self.port} error/terputus: {e}.") from e
        finally:
            self._last_io = time.monotonic()
        r.elapsed_ms = (time.monotonic() - t0) * 1000
        self._prev = (slave, fc, t_sent) if r.status in ("timeout", "crc_error") else None
        if r.status == "late":
            self._record_late(slave, r.message, None)
        if r.echo:
            self.echo_seen = True
        if self.session:
            self.session.log_rx(self.link, r)
        return r

    def _record_late(self, slave: int, what: str, delay_ms: float | None) -> None:
        info = {"slave": slave, "baud": self.baud, "parity": self.parity, "detail": what, "delay_ms": delay_ms}
        self.late.append(info)
        if self.session:
            d = f" ±{delay_ms:.0f} ms setelah request" if delay_ms else ""
            self.session.log(f"RX-LATE {self.link} id={slave}{d}: {what}")

    def drain_late(self, wait: float = 1.0) -> list[dict]:
        """Setelah timeout: tunggu sebentar, laporkan kalau balasan ternyata datang terlambat."""
        n = len(self.late)
        if self._prev:
            time.sleep(wait)
            try:
                self._check_stale()
            except (serial.SerialException, OSError):
                pass
        return self.late[n:]

    def _check_stale(self) -> None:
        """Byte yang masuk di antara request = balasan telat untuk request sebelumnya."""
        if not self._ser.in_waiting:
            return
        stale = self._ser.read(self._ser.in_waiting)
        if self.session:
            self.session.log(f"RX-STALE {self.link} | {stale.hex(' ').upper()}")
        if self._prev and stale:
            slave, fc, t_sent = self._prev
            k = stale.find(bytes([slave]))
            if k >= 0 and crc_ok(stale[k:]):
                self._record_late(slave, f"balasan FC{stale[k + 1]:02d} datang setelah timeout "
                                         f"(raw {stale[k:].hex(' ').upper()})",
                                  (time.monotonic() - t_sent) * 1000)
        self._prev = None

    @staticmethod
    def _candidates(buf: bytes, slave: int, fc: int):
        for k in range(0, max(0, len(buf) - 1)):
            if buf[k] == slave and buf[k + 1] in (fc, fc | 0x80):
                yield k

    def _try_parse(self, buf: bytes, tx: bytes, r: Result) -> bool:
        for k in self._candidates(buf, r.slave, r.fc):
            n = expected_rtu_len(buf[k:], r.fc)
            if n is None or len(buf) - k < n:
                continue
            frame = buf[k:k + n]
            if not crc_ok(frame):
                continue
            status, values, exc, msg = parse_pdu_response(r.fc, r.count, frame[1:-2])
            if status == "invalid":
                continue
            r.status, r.values, r.exc_code, r.message = status, values, exc, msg
            r.rx = buf
            r.echo = k >= len(tx) and buf[:len(tx)] == tx
            if k and not r.echo:
                r.message = f"{k} byte sampah sebelum frame dibuang"
            elif k > len(tx):
                r.message = f"{k - len(tx)} byte sampah setelah echo dibuang"
            return True
        rest = buf[len(tx):] if buf.startswith(tx) else buf
        if len(rest) >= 4 and rest[0] == r.slave and crc_ok(rest):
            rfc = rest[1]
            r.rx, r.echo = buf, rest is not buf
            if (rfc & 0x7F) in (1, 2, 3, 4):
                # FC baca lain dari slave yang sama → jawaban telat untuk request sebelumnya
                r.status = "late"
                r.message = (f"balasan FC{rfc & 0x7F:02d} untuk request sebelumnya datang terlambat — "
                             "device lambat, naikkan --timeout")
            else:
                r.status = "nonstandard"
                r.message = (f"device menjawab dengan frame non-standar FC 0x{rfc:02X} "
                             f"(data {rest[2:-2].hex(' ').upper() or '-'}) — device hidup, tapi alamat/FC ini "
                             "kemungkinan tidak didukung")
            return True
        return False

    def _classify_failure(self, buf: bytes, tx: bytes, r: Result) -> None:
        r.rx = buf
        if not buf:
            r.status = "timeout"
            return
        if buf == tx:
            r.status = "timeout"
            r.echo = True
            r.message = "hanya echo adaptor, device tidak menjawab"
            return
        rest = buf[len(tx):] if buf.startswith(tx) else buf
        r.echo = rest is not buf
        if len(rest) >= 4 and crc_ok(rest):
            if self._prev and rest[0] == self._prev[0]:
                # jawaban telat dari slave request sebelumnya (mis. scan ID berikutnya)
                self._record_late(rest[0], f"balasan FC{rest[1]:02d} datang setelah timeout "
                                           f"(raw {rest.hex(' ').upper()})", None)
            r.status = "invalid"
            r.message = (f"frame Modbus valid dari slave {rest[0]} FC {rest[1]}, bukan jawaban request ini "
                         "(ada master/device lain di bus?)")
            return
        r.status = "crc_error"
        r.message = (
            f"{len(rest)} byte diterima tapi CRC/format tidak valid "
            "(baud/parity salah, noise, atau masalah wiring)"
        )
