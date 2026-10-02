"""Interpretasi nilai register dan decoder frame RTU (untuk sniff)."""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field

from .protocol import crc_ok, hexs

WORD_ORDERS = ("ABCD", "CDAB", "BADC", "DCBA")
TYPES_16 = ("uint16", "int16")
TYPES_32 = ("uint32", "int32", "float32")
ALL_TYPES = TYPES_16 + TYPES_32


# ---------------------------------------------------------------- nilai register

def regs_to_bytes(r0: int, r1: int, order: str) -> bytes:
    """r0 = register alamat lebih kecil = byte A B, r1 = C D. Return 4 byte big-endian sesuai order."""
    a, b = (r0 >> 8) & 0xFF, r0 & 0xFF
    c, d = (r1 >> 8) & 0xFF, r1 & 0xFF
    m = {"A": a, "B": b, "C": c, "D": d}
    order = order.upper()
    if sorted(order) != ["A", "B", "C", "D"]:
        raise ValueError(f"word_order '{order}' tidak valid (pakai ABCD/CDAB/BADC/DCBA)")
    return bytes(m[ch] for ch in order)


def to_int16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def decode_32(r0: int, r1: int, order: str, typ: str) -> float | int:
    raw = regs_to_bytes(r0, r1, order)
    if typ == "uint32":
        return struct.unpack(">I", raw)[0]
    if typ == "int32":
        return struct.unpack(">i", raw)[0]
    if typ == "float32":
        return struct.unpack(">f", raw)[0]
    raise ValueError(typ)


def decode_value(regs: list[int], typ: str, word_order: str = "ABCD") -> float | int:
    typ = typ.lower()
    if typ == "uint16":
        return regs[0]
    if typ == "int16":
        return to_int16(regs[0])
    if typ in TYPES_32:
        if len(regs) < 2:
            raise ValueError(f"{typ} butuh 2 register")
        return decode_32(regs[0], regs[1], word_order, typ)
    raise ValueError(f"tipe '{typ}' tidak dikenal (pakai {', '.join(ALL_TYPES)})")


def reg_count(typ: str) -> int:
    return 2 if typ.lower() in TYPES_32 else 1


def fmt_num(v) -> str:
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return str(v)
        if v != 0 and (abs(v) >= 1e9 or abs(v) < 1e-4):
            return f"{v:.6g}"
        return f"{v:.6g}" if abs(v) >= 1e6 else f"{v:.4f}".rstrip("0").rstrip(".")
    return str(v)


def interpret_16(addr: int, v: int) -> dict:
    return {
        "addr": addr,
        "uint16": v,
        "int16": to_int16(v),
        "hex": f"0x{v:04X}",
        "div10": v / 10,
        "div100": v / 100,
    }


def interpret_32(addr: int, r0: int, r1: int) -> dict:
    row: dict = {"addr": addr}
    for order in WORD_ORDERS:
        for typ in TYPES_32:
            row[f"{typ}_{order}"] = decode_32(r0, r1, order, typ)
    return row


# ---------------------------------------------------------------- find-value

@dataclass
class Match:
    addr: int
    typ: str
    order: str
    raw: float | int
    scale: float
    value: float

    def describe(self) -> str:
        o = f" {self.order}" if self.order else ""
        s = "" if self.scale == 1 else f" ×{self.scale:g}"
        return f"addr {self.addr}: {self.typ}{o} raw={fmt_num(self.raw)}{s} → {fmt_num(self.value)}"


SCALES = (1, 0.1, 0.01, 0.001, 10)


def _close(v: float, target: float, tol: float) -> bool:
    if math.isnan(v) or math.isinf(v):
        return False
    if tol > 0:
        return abs(v - target) <= tol + 1e-9
    return abs(v - target) <= max(1e-9, abs(target) * 1e-9)


def find_value(regs: dict[int, int], target: float, tolerance: float = 0.0,
               scales=SCALES, float_rel: float = 1e-4) -> list[Match]:
    """Cari target di peta {alamat: nilai}. Coba 16-bit & 32-bit (4 urutan), dengan beberapa skala.

    Contoh: target 3.7 cocok dengan raw 37 (×0.1) atau 370 (×0.01).
    """
    out: list[Match] = []
    for a in sorted(regs):
        v = regs[a]
        for typ, raw in (("uint16", v), ("int16", to_int16(v))):
            if typ == "int16" and raw == v:
                continue  # nilai positif: sama dengan uint16, jangan dobel
            for sc in scales:
                if _close(raw * sc, target, tolerance):
                    out.append(Match(a, typ, "", raw, sc, raw * sc))
        if a + 1 not in regs:
            continue
        r1 = regs[a + 1]
        for order in WORD_ORDERS:
            for typ in ("uint32", "int32"):
                raw = decode_32(v, r1, order, typ)
                if typ == "int32" and raw >= 0:
                    continue
                for sc in scales:
                    if _close(raw * sc, target, tolerance):
                        out.append(Match(a, typ, order, raw, sc, raw * sc))
            f = decode_32(v, r1, order, "float32")
            if math.isfinite(f) and target != 0:
                tol = tolerance if tolerance > 0 else abs(target) * float_rel
                if abs(f - target) <= tol:
                    out.append(Match(a, "float32", order, f, 1, f))
    return out


# ---------------------------------------------------------------- frame RTU (sniff)

@dataclass
class Frame:
    offset: int
    raw: bytes
    slave: int
    fc: int
    kind: str  # request | response | exception | other
    addr: int | None = None
    count: int | None = None
    byte_count: int | None = None
    exc_code: int | None = None
    values: list[int] = field(default_factory=list)
    t: float = 0.0

    def describe(self) -> str:
        if self.kind == "request":
            return f"REQ  id={self.slave} fc={self.fc:02d} addr={self.addr} count={self.count}"
        if self.kind == "response":
            v = f" {self.values[:6]}{'…' if len(self.values) > 6 else ''}" if self.values else ""
            return f"RESP id={self.slave} fc={self.fc:02d} bytes={self.byte_count}{v}"
        if self.kind == "exception":
            return f"EXC  id={self.slave} fc={self.fc & 0x7F:02d} code={self.exc_code}"
        return f"FRAME id={self.slave} fc={self.fc} (tidak didekode) {hexs(self.raw)}"


def _mk_frame(data: bytes, i: int, n: int, kind: str) -> Frame:
    raw = data[i:i + n]
    f = Frame(offset=i, raw=raw, slave=raw[0], fc=raw[1], kind=kind)
    if kind == "request":
        f.addr, f.count = struct.unpack(">HH", raw[2:6])
    elif kind == "response":
        f.byte_count = raw[2]
        payload = raw[3:-2]
        if f.fc in (3, 4) and len(payload) % 2 == 0:
            f.values = list(struct.unpack(f">{len(payload) // 2}H", payload))
    elif kind == "exception":
        f.exc_code = raw[2]
    return f


def parse_rtu_stream(data: bytes, boundaries: list[int] | None = None) -> tuple[list[Frame], list[tuple[int, bytes]]]:
    """Pisahkan stream byte menjadi frame RTU valid (CRC benar) + potongan sampah.

    boundaries: offset tempat terjadi jeda >= 3,5 karakter (petunjuk untuk frame FC yang
    tidak dikenal strukturnya). Frame FC01-04 dipisah berdasarkan struktur + CRC, jadi
    tetap terbaca walau beberapa frame tergabung dalam satu chunk USB.
    """
    bset = sorted(set(b for b in (boundaries or []) if 0 < b < len(data)))
    frames: list[Frame] = []
    junk: list[tuple[int, bytes]] = []
    junk_start = None
    i = 0
    n_data = len(data)
    while i < n_data:
        found = None
        if n_data - i >= 4 and data[i] <= 247:
            fc = data[i + 1]
            cands: list[tuple[int, str]] = []
            if fc in (1, 2, 3, 4):
                prev = frames[-1] if frames else None
                resp_len = 3 + data[i + 2] + 2 if n_data - i >= 3 else 0
                req_first = not (prev and prev.kind == "request" and prev.slave == data[i] and prev.fc == fc)
                pair = [(8, "request"), (resp_len, "response")]
                cands += pair if req_first else pair[::-1]
            elif fc & 0x80 and (fc & 0x7F) in range(1, 128):
                cands.append((5, "exception"))
            nxt = next((b for b in bset if b > i), n_data)
            cands.append((nxt - i, "other"))
            for n, kind in cands:
                if 4 <= n <= 256 and i + n <= n_data and crc_ok(data[i:i + n]):
                    if kind == "other" and fc in (1, 2, 3, 4):
                        continue
                    found = _mk_frame(data, i, n, kind)
                    break
        if found:
            if junk_start is not None:
                junk.append((junk_start, data[junk_start:i]))
                junk_start = None
            frames.append(found)
            i += len(found.raw)
        else:
            if junk_start is None:
                junk_start = i
            i += 1
    if junk_start is not None:
        junk.append((junk_start, data[junk_start:]))
    return frames, junk
