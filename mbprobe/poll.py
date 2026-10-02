"""Polling register yang sudah teridentifikasi (dari config YAML)."""
from __future__ import annotations

import time
from dataclasses import dataclass

from .config import RegisterDef, UnitConfig
from .decode import decode_value
from .protocol import max_count

MERGE_GAP = 8  # register kosong maksimum yang boleh "ikut dibaca" saat menggabung blok


@dataclass
class Block:
    fc: int
    addr: int
    count: int
    regs: list[RegisterDef]


def plan_blocks(regs: list[RegisterDef], merge: bool = True) -> list[Block]:
    """Gabung register berdekatan dengan FC sama menjadi satu request, supaya request per siklus sedikit."""
    blocks: list[Block] = []
    for fc in sorted({r.fc for r in regs}):
        items = sorted((r for r in regs if r.fc == fc), key=lambda r: r.addr)
        cur: Block | None = None
        for r in items:
            end = r.addr + r.count
            if (merge and cur and r.addr - (cur.addr + cur.count) <= MERGE_GAP
                    and max(end, cur.addr + cur.count) - cur.addr <= max_count(fc)):
                cur.count = max(end, cur.addr + cur.count) - cur.addr
                cur.regs.append(r)
            else:
                cur = Block(fc, r.addr, r.count, [r])
                blocks.append(cur)
    return blocks


def scaled(r: RegisterDef, raw_regs: list[int]):
    v = decode_value(raw_regs, "uint16" if r.fc in (1, 2) else r.type, r.word_order)
    if r.scale == 1 and r.offset == 0:
        return v
    return round(v * r.scale + r.offset, 6)


class Poller:
    def __init__(self, cfg: UnitConfig, transport, request_delay: float):
        self.cfg = cfg
        self.t = transport
        self.delay = request_delay
        self.blocks = plan_blocks(cfg.registers)
        self._split: set[int] = set()  # index blok yang ternyata harus dibaca per register

    def cycle(self) -> dict[str, tuple[object, str]]:
        """Return {nama: (nilai|None, status)}."""
        out: dict[str, tuple[object, str]] = {}
        sid = self.cfg.connection.slave_id
        for bi, b in enumerate(self.blocks):
            if bi not in self._split:
                r = self.t.request(sid, b.fc, b.addr, b.count)
                time.sleep(self.delay)
                if r.status == "ok":
                    for reg in b.regs:
                        o = reg.addr - b.addr
                        out[reg.name] = (scaled(reg, r.values[o:o + reg.count]), "ok")
                    continue
                if r.status == "exception" and len(b.regs) > 1:
                    self._split.add(bi)  # blok gabungan menyentuh alamat invalid → baca terpisah
                else:
                    st = f"exception {r.exc_code}" if r.status == "exception" else r.status
                    for reg in b.regs:
                        out[reg.name] = (None, st)
                    continue
            for reg in b.regs:
                r = self.t.request(sid, reg.fc, reg.addr, reg.count)
                time.sleep(self.delay)
                if r.status == "ok":
                    out[reg.name] = (scaled(reg, r.values), "ok")
                else:
                    out[reg.name] = (None, f"exception {r.exc_code}" if r.status == "exception" else r.status)
        return out
