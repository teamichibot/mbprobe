"""Modbus TCP client read-only di atas socket biasa."""
from __future__ import annotations

import socket
import struct
import time

from .protocol import Result, build_tcp_request, check_read_fc, parse_pdu_response


class TcpTransport:
    kind = "tcp"

    def __init__(self, host: str, port: int = 502, timeout: float = 2.0, session=None,
                 connect_timeout: float | None = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout or timeout
        self.session = session
        self.echo_seen = False
        self._sock: socket.socket | None = None
        self._tid = 0

    @property
    def link(self) -> str:
        return f"tcp:{self.host}:{self.port}"

    def connect(self) -> None:
        if self._sock is None:
            s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
            s.settimeout(self.timeout)
            self._sock = s

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _recv_exact(self, n: int, buf: bytearray) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self._sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("koneksi ditutup oleh device")
            out += chunk
            buf += chunk
        return bytes(out)

    def request(self, slave: int, fc: int, addr: int, count: int) -> Result:
        check_read_fc(fc)
        self._tid = (self._tid + 1) & 0xFFFF
        tx = build_tcp_request(self._tid, slave, fc, addr, count)
        if tx[7] not in (1, 2, 3, 4):  # pertahanan berlapis
            raise AssertionError("frame non-read")
        r = Result(status="timeout", fc=fc, addr=addr, count=count, slave=slave, tx=tx)
        t0 = time.monotonic()
        rx = bytearray()
        try:
            self.connect()
            if self.session:
                self.session.log_tx(self.link, tx, f"id={slave} fc={fc} addr={addr} count={count}")
            self._sock.sendall(tx)
            while True:
                hdr = self._recv_exact(7, rx)
                tid, proto, length, unit = struct.unpack(">HHHB", hdr)
                if length < 2 or length > 260:
                    r.status, r.message = "invalid", f"MBAP length {length} tidak wajar"
                    self.close()
                    break
                pdu = self._recv_exact(length - 1, rx)
                if tid != self._tid:
                    continue  # response basi dari request sebelumnya
                if proto != 0:
                    r.status, r.message = "invalid", f"protocol id {proto} != 0 (bukan Modbus TCP?)"
                    break
                st, values, exc, msg = parse_pdu_response(fc, count, pdu)
                r.status, r.values, r.exc_code, r.message = st, values, exc, msg
                if unit != slave:
                    r.message = (r.message + f" unit id balasan {unit}").strip()
                break
        except socket.timeout:
            r.status = "timeout"
            self.close()  # jangan pakai lagi koneksi yang mungkin menyisakan response telat
        except (ConnectionError, OSError) as e:
            r.status = "port_error"
            r.message = f"{type(e).__name__}: {e}"
            self.close()
        r.rx = bytes(rx)
        r.elapsed_ms = (time.monotonic() - t0) * 1000
        if self.session:
            self.session.log_rx(self.link, r)
        return r


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
