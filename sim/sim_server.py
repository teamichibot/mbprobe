"""Simulator device Modbus (pymodbus) untuk menguji mbprobe tanpa hardware.

RTU (perlu pasangan serial virtual: sim/virtual_bus.py di Linux/macOS, com0com di Windows):
    python sim/sim_server.py rtu --port /dev/ttys005 --baud 19200 --parity E --id 7

TCP:
    python sim/sim_server.py tcp --host 127.0.0.1 --port 5020

Peta register uji (sama untuk RTU & TCP) — lihat REGISTER_MAP di bawah.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import struct

from pymodbus.constants import ExcCodes
from pymodbus.exceptions import NoSuchIdException
from pymodbus.server import ModbusSerialServer, ModbusTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.simulator.simcore import SimCore


def _get_device(self, device_id):
    # pymodbus 3.15: SimCore melempar KeyError untuk ID tak dikenal, sehingga server membalas
    # exception 04 dan ignore_missing_devices tidak berfungsi. Slave RTU asli justru diam.
    if device_id in self.devices:
        return self.devices[device_id]
    if 0 in self.devices:
        return self.devices[0]
    raise NoSuchIdException(f"device_id {device_id} tidak ada")


SimCore._SimCore__get_device = _get_device


def u32_words(value: int, order: str) -> list[int]:
    """Pecah uint32 ke 2 register sesuai urutan (ABCD/CDAB/BADC/DCBA)."""
    b = struct.pack(">I", value)
    m = dict(zip("ABCD", b))
    o = bytes(m[ch] for ch in order)
    return [o[0] << 8 | o[1], o[2] << 8 | o[3]]


def f32_words(value: float, order: str) -> list[int]:
    b = struct.pack(">f", value)
    m = dict(zip("ABCD", b))
    o = bytes(m[ch] for ch in order)
    return [o[0] << 8 | o[1], o[2] << 8 | o[3]]


# Nilai uji (meniru layar controller compressor)
RUNNING_HOURS = 82826  # uint32 CDAB @ HR 300
LOAD_HOURS = 70335  # uint32 CDAB @ HR 302
PRESSURE_RAW = 370  # int16 ×0.01 = 3,70 bar @ HR 120
TEMP_C = 82.5  # float32 ABCD @ HR 310

# Holding registers (FC03). Alamat yang TIDAK didefinisikan → exception 02 (ILLEGAL DATA ADDRESS).
HOLDING: dict[int, list[int]] = {
    0: [1000 + i for i in range(100)],  # 0..99 valid (nilai 1000..1099)
    # 100..119 TIDAK ada → exception
    120: [PRESSURE_RAW, 42, 0xFFFE] + [0] * 77,  # 120..199 valid; 122 = int16 -2
    # 200..299 TIDAK ada → exception
    300: u32_words(RUNNING_HOURS, "CDAB") + u32_words(LOAD_HOURS, "CDAB")
    + [0] * 6 + f32_words(TEMP_C, "ABCD") + [0] * 38,  # 300..349 valid
    # 350..65535 TIDAK ada → exception
}
# Input registers (FC04)
INPUT: dict[int, list[int]] = {0: [2000 + i for i in range(50)]}  # 0..49 valid
COILS: dict[int, list[bool]] = {0: [bool(i % 3 == 0) for i in range(16)]}
DISCRETE: dict[int, list[bool]] = {0: [bool(i % 2) for i in range(16)]}


def _block(regs: dict, bits: bool) -> list[SimData]:
    dt = DataType.BITS if bits else DataType.REGISTERS
    return [SimData(address=a, values=list(v), datatype=dt) for a, v in sorted(regs.items())]


RESPONSE_DELAY = 0.0  # detik; --delay-ms meniru device lambat (mis. sensor SHT20/MD02 ±600 ms)


async def _reject_writes(function_code, start_address, address, count, current_registers, set_values):
    if RESPONSE_DELAY:
        await asyncio.sleep(RESPONSE_DELAY)
    # Simulator juga read-only: tolak semua request tulis.
    if set_values is not None:
        return ExcCodes.ILLEGAL_FUNCTION
    return None


def make_device(device_id: int) -> SimDevice:
    return SimDevice(
        id=device_id,
        simdata=(_block(COILS, True), _block(DISCRETE, True), _block(HOLDING, False), _block(INPUT, False)),
        action=_reject_writes,
    )


async def run_rtu(port: str, baud: int, parity: str, device_id: int, echo: bool = False) -> None:
    server = ModbusSerialServer(
        make_device(device_id), port=port, baudrate=baud, parity=parity, stopbits=1, bytesize=8,
        handle_local_echo=echo,
        ignore_missing_devices=True,  # slave RTU asli diam kalau ID bukan miliknya
    )
    print(f"[sim] RTU device id={device_id} di {port} {baud} {parity}8 1", flush=True)
    await server.serve_forever()


async def run_tcp(host: str, port: int, unit_ids: list[int]) -> None:
    devices = [make_device(u) for u in unit_ids]
    server = ModbusTcpServer(devices if len(devices) > 1 else devices[0], address=(host, port))
    print(f"[sim] TCP device unit={unit_ids} di {host}:{port}", flush=True)
    await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--delay-ms", type=float, default=0, help="Tunda setiap jawaban (meniru device lambat)")
    sub = ap.add_subparsers(dest="mode", required=True)
    r = sub.add_parser("rtu", parents=[common])
    r.add_argument("--port", required=True)
    r.add_argument("--baud", type=int, default=19200)
    r.add_argument("--parity", default="E", choices=["N", "E", "O"])
    r.add_argument("--id", type=int, default=7)
    t = sub.add_parser("tcp", parents=[common])
    t.add_argument("--host", default="127.0.0.1")
    t.add_argument("--port", type=int, default=5020)
    t.add_argument("--unit", type=int, nargs="+", default=[1])
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    global RESPONSE_DELAY
    RESPONSE_DELAY = a.delay_ms / 1000
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.ERROR)
    logging.getLogger("pymodbus").setLevel(logging.DEBUG if a.verbose else logging.CRITICAL)
    try:
        if a.mode == "rtu":
            asyncio.run(run_rtu(a.port, a.baud, a.parity, a.id))
        else:
            asyncio.run(run_tcp(a.host, a.port, a.unit))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
