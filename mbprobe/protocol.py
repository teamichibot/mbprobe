"""Modbus framing — READ-ONLY.

Hanya function code 01, 02, 03, 04 yang bisa dibangun di sini. Tidak ada
builder untuk function code tulis, dan transport menolak mengirim frame
dengan function code di luar READ_FUNCTION_CODES.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

READ_FUNCTION_CODES = frozenset({1, 2, 3, 4})

FC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
}

EXCEPTION_NAMES = {
    1: "ILLEGAL FUNCTION",
    2: "ILLEGAL DATA ADDRESS",
    3: "ILLEGAL DATA VALUE",
    4: "SERVER DEVICE FAILURE",
    5: "ACKNOWLEDGE",
    6: "SERVER DEVICE BUSY",
    8: "MEMORY PARITY ERROR",
    10: "GATEWAY PATH UNAVAILABLE",
    11: "GATEWAY TARGET FAILED TO RESPOND",
}

MAX_REGISTERS = 125  # batas spesifikasi untuk FC03/FC04
MAX_BITS = 2000  # batas spesifikasi untuk FC01/FC02


class NotReadOnlyError(ValueError):
    """Dilempar kalau ada upaya membangun/mengirim function code non-read."""


def check_read_fc(fc: int) -> None:
    if fc not in READ_FUNCTION_CODES:
        raise NotReadOnlyError(
            f"Function code {fc} ditolak: mbprobe hanya mendukung FC 01/02/03/04 (read-only)."
        )


def max_count(fc: int) -> int:
    return MAX_BITS if fc in (1, 2) else MAX_REGISTERS


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def crc_bytes(data: bytes) -> bytes:
    return struct.pack("<H", crc16(data))


def crc_ok(frame: bytes) -> bool:
    return len(frame) >= 4 and crc16(frame[:-2]) == struct.unpack("<H", frame[-2:])[0]


def build_read_pdu(fc: int, addr: int, count: int) -> bytes:
    check_read_fc(fc)
    if not 0 <= addr <= 0xFFFF:
        raise ValueError(f"Alamat {addr} di luar 0..65535")
    if not 1 <= count <= max_count(fc):
        raise ValueError(f"Count {count} di luar 1..{max_count(fc)} untuk FC{fc:02d}")
    if addr + count > 0x10000:
        raise ValueError("Rentang alamat melewati 65535")
    return struct.pack(">BHH", fc, addr, count)


def build_rtu_request(slave: int, fc: int, addr: int, count: int) -> bytes:
    if not 0 <= slave <= 247:
        raise ValueError(f"Slave ID {slave} di luar 0..247")
    body = bytes([slave]) + build_read_pdu(fc, addr, count)
    return body + crc_bytes(body)


def build_tcp_request(tid: int, unit: int, fc: int, addr: int, count: int) -> bytes:
    pdu = build_read_pdu(fc, addr, count)
    return struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, unit & 0xFF) + pdu


@dataclass
class Result:
    """Hasil satu request.

    status: ok | exception | nonstandard | late | timeout | crc_error | invalid | port_error
    """

    status: str
    fc: int
    addr: int
    count: int
    slave: int = 0
    values: list[int] = field(default_factory=list)
    exc_code: int | None = None
    tx: bytes = b""
    rx: bytes = b""
    echo: bool = False
    message: str = ""
    elapsed_ms: float = 0.0

    @property
    def responded(self) -> bool:
        """Jawaban Modbus valid untuk request INI (ok atau exception)."""
        return self.status in ("ok", "exception")

    @property
    def alive(self) -> bool:
        """Ada device di ID ini: jawaban valid, frame non-standar, atau jawaban telat (CRC valid)."""
        return self.status in ("ok", "exception", "nonstandard", "late")

    def describe(self) -> str:
        if self.status == "ok":
            return f"OK {self.values[:8]}{'…' if len(self.values) > 8 else ''}"
        if self.status == "exception":
            return f"EXCEPTION {self.exc_code:02d} {EXCEPTION_NAMES.get(self.exc_code, '?')}"
        return f"{self.status.upper()} {self.message}".strip()


def parse_pdu_response(fc: int, count: int, pdu: bytes) -> tuple[str, list[int], int | None, str]:
    """Parse PDU response (tanpa slave/CRC/MBAP). Return (status, values, exc_code, msg)."""
    if len(pdu) < 2:
        return "invalid", [], None, "PDU terlalu pendek"
    rfc = pdu[0]
    if rfc == (fc | 0x80):
        return "exception", [], pdu[1], ""
    if rfc != fc:
        return "invalid", [], None, f"FC response {rfc} != request {fc}"
    bc = pdu[1]
    data = pdu[2:]
    if len(data) != bc:
        return "invalid", [], None, f"byte count {bc} tapi data {len(data)} byte"
    if fc in (3, 4):
        if bc != 2 * count:
            return "invalid", [], None, f"byte count {bc}, harusnya {2 * count}"
        return "ok", list(struct.unpack(f">{count}H", data)), None, ""
    # FC01/02: bit-packed
    if bc != (count + 7) // 8:
        return "invalid", [], None, f"byte count {bc}, harusnya {(count + 7) // 8}"
    bits = [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]
    return "ok", bits, None, ""


def expected_rtu_len(buf: bytes, fc: int) -> int | None:
    """Panjang frame RTU response yang diharapkan dari header, atau None kalau belum cukup."""
    if len(buf) < 2:
        return None
    if buf[1] == (fc | 0x80):
        return 5
    if len(buf) < 3:
        return None
    return 3 + buf[2] + 2


def hexs(data: bytes) -> str:
    return data.hex(" ").upper()
