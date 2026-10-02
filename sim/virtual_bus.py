"""Bus RS485 virtual untuk Linux/macOS (pengganti socat/com0com saat testing).

Membuat N serial port virtual (pty). Byte yang ditulis satu endpoint diteruskan ke
SEMUA endpoint lain, seperti bus RS485 multi-drop. Setting baud/parity tiap endpoint
dibaca dari termios: kalau pengirim dan penerima beda baud/parity, byte dirusak
(meniru UART yang salah setting), sehingga scan baud/parity benar-benar teruji.

    python sim/virtual_bus.py --endpoints 3 [--echo 1]

--echo i : endpoint i menerima kembali byte yang ia kirim (meniru adaptor yang echo).
"""
from __future__ import annotations

import argparse
import os
import select
import termios
import threading
import time
import tty

BAUD_CONST = {
    getattr(termios, f"B{b}"): b
    for b in (1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400)
    if hasattr(termios, f"B{b}")
}


def _line_setting(fd: int) -> tuple[int, str]:
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(fd)
    baud = BAUD_CONST.get(ospeed, ospeed)  # macOS menyimpan baud apa adanya
    if cflag & termios.PARENB:
        parity = "O" if cflag & termios.PARODD else "E"
    else:
        parity = "N"
    return baud, parity


def _parity_bit(b: int, parity: str) -> int:
    ones = bin(b).count("1")
    return ones % 2 if parity == "E" else 1 - ones % 2


def corrupt(data: bytes, tx: tuple[int, str], rx: tuple[int, str]) -> bytes:
    """Rusak byte seperti UART penerima yang setting-nya tidak cocok."""
    if tx == rx:
        return data
    (tb, tp), (rb, rp) = tx, rx
    if tb != rb:
        # baud salah: jumlah & isi byte kacau
        ratio = rb / tb
        n = max(1, round(len(data) * min(ratio, 1 / ratio) * 1.3))
        return bytes(((x * 73 + i * 151 + tb // 100) ^ 0x5A) & 0xFF for i, x in enumerate((data * 3)[:n]))
    out = bytearray()
    for b in data:
        if rp == "N":  # pengirim pakai parity: bit parity dibaca sebagai stop bit
            out.append(b if _parity_bit(b, tp) == 1 else 0x00)  # 0 = framing error → 0x00
        elif tp == "N":  # penerima cek parity, pengirim tidak mengirim parity (stop bit = 1)
            out.append(b if _parity_bit(b, rp) == 1 else 0x00)
        else:  # E vs O: parity selalu salah
            out.append(0x00)
    return bytes(out)


class VirtualBus:
    def __init__(self, endpoints: int = 2, echo: set[int] | None = None):
        self.echo = echo or set()
        self.masters: list[int] = []
        self.slave_fds: list[int] = []
        self.paths: list[str] = []
        for _ in range(endpoints):
            m, s = os.openpty()
            tty.setraw(m)
            tty.setraw(s)
            os.set_blocking(m, False)
            self.masters.append(m)
            self.slave_fds.append(s)  # tetap dibuka supaya termios bisa dibaca & pty tidak EOF
            self.paths.append(os.ttyname(s))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.traffic = 0

    def start(self) -> "VirtualBus":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        for fd in self.masters + self.slave_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def _run(self) -> None:
        while not self._stop.is_set():
            r, _, _ = select.select(self.masters, [], [], 0.05)
            for m in r:
                try:
                    data = os.read(m, 4096)
                except (BlockingIOError, OSError):
                    continue
                if not data:
                    continue
                self.traffic += len(data)
                i = self.masters.index(m)
                tx = _line_setting(self.slave_fds[i])
                for j, other in enumerate(self.masters):
                    if j == i and j not in self.echo:
                        continue
                    payload = data if j == i else corrupt(data, tx, _line_setting(self.slave_fds[j]))
                    try:
                        os.write(other, payload)
                    except OSError:
                        pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoints", type=int, default=3)
    ap.add_argument("--echo", type=int, action="append", default=[])
    a = ap.parse_args()
    bus = VirtualBus(a.endpoints, set(a.echo)).start()
    for i, p in enumerate(bus.paths):
        print(f"endpoint {i}: {p}{'  (echo)' if i in bus.echo else ''}", flush=True)
    print("Bus jalan. Ctrl+C untuk berhenti.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bus.stop()


if __name__ == "__main__":
    main()
