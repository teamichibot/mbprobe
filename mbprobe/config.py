"""Config YAML per unit (dipakai `poll`, dan nanti bisa dipakai ulang untuk gateway/dashboard)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .decode import ALL_TYPES, WORD_ORDERS, reg_count
from .protocol import READ_FUNCTION_CODES


class ConfigError(ValueError):
    pass


@dataclass
class Connection:
    type: str  # rtu | tcp
    port: str = ""
    baud: int = 9600
    parity: str = "N"
    stopbits: float = 1
    slave_id: int = 1
    host: str = ""
    tcp_port: int = 502
    timeout: float = 1.0


@dataclass
class RegisterDef:
    name: str
    fc: int
    addr: int
    type: str = "uint16"
    word_order: str = "ABCD"
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""

    @property
    def count(self) -> int:
        return 1 if self.fc in (1, 2) else reg_count(self.type)


@dataclass
class UnitConfig:
    name: str
    connection: Connection
    registers: list[RegisterDef] = field(default_factory=list)


def load_config(path: str | Path) -> UnitConfig:
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"File config {p} tidak ditemukan")
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML tidak valid di {p}: {e}")
    if not isinstance(raw, dict):
        raise ConfigError("Config harus berupa mapping YAML")
    c = raw.get("connection") or {}
    ctype = str(c.get("type", "")).lower()
    if ctype not in ("rtu", "tcp"):
        raise ConfigError("connection.type harus 'rtu' atau 'tcp'")
    conn = Connection(
        type=ctype,
        port=str(c.get("port", "")),
        baud=int(c.get("baud", 9600)),
        parity=str(c.get("parity", "N")).upper(),
        stopbits=float(c.get("stopbits", 1)),
        slave_id=int(c.get("slave_id", c.get("unit_id", 1))),
        host=str(c.get("host", "")),
        tcp_port=int(c.get("tcp_port", 502)),
        timeout=float(c.get("timeout", 1.0)),
    )
    if ctype == "rtu" and not conn.port:
        raise ConfigError("connection.port wajib untuk rtu (mis. COM5 atau /dev/ttyUSB0)")
    if ctype == "tcp" and not conn.host:
        raise ConfigError("connection.host wajib untuk tcp")
    regs = []
    for i, r in enumerate(raw.get("registers") or []):
        where = f"registers[{i}]"
        try:
            rd = RegisterDef(
                name=str(r["name"]),
                fc=int(r.get("fc", 3)),
                addr=int(r["addr"]),
                type=str(r.get("type", "uint16")).lower(),
                word_order=str(r.get("word_order", "ABCD")).upper(),
                scale=float(r.get("scale", 1)),
                offset=float(r.get("offset", 0)),
                unit=str(r.get("unit", "")),
            )
        except KeyError as e:
            raise ConfigError(f"{where}: field {e} wajib ada")
        if rd.fc not in READ_FUNCTION_CODES:
            raise ConfigError(f"{where} ({rd.name}): fc {rd.fc} ditolak — hanya 1/2/3/4 (read-only)")
        if rd.type not in ALL_TYPES:
            raise ConfigError(f"{where} ({rd.name}): type '{rd.type}' tidak dikenal ({', '.join(ALL_TYPES)})")
        if rd.word_order not in WORD_ORDERS:
            raise ConfigError(f"{where} ({rd.name}): word_order harus salah satu {WORD_ORDERS}")
        regs.append(rd)
    if not regs:
        raise ConfigError("Tidak ada register di config")
    names = [r.name for r in regs]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise ConfigError(f"Nama register dobel: {sorted(dup)}")
    return UnitConfig(name=str(raw.get("name", p.stem)), connection=conn, registers=regs)
