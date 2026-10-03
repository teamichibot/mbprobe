"""Perilaku transport RTU pada device 'aneh' yang ditemui di hardware nyata (sensor SHT20/MD02):
jawaban lambat dan frame error non-standar. Pakai port serial palsu supaya deterministik."""
import time

from mbprobe.protocol import build_rtu_request, crc_bytes
from mbprobe.transport_rtu import RtuTransport


def frame(*b):
    body = bytes(b)
    return body + crc_bytes(body)


class FakeSerial:
    """Device palsu: script = list (delay_detik, bytes balasan) per request yang ditulis."""

    def __init__(self, script):
        self.script = list(script)
        self.pending = []  # (waktu_tersedia, bytes)
        self.written = []

    @property
    def in_waiting(self):
        now = time.monotonic()
        return sum(len(b) for t, b in self.pending if t <= now)

    def read(self, n=1):
        now = time.monotonic()
        out = bytearray()
        keep = []
        for t, b in self.pending:
            if t <= now and len(out) < n:
                take = b[: n - len(out)]
                out += take
                if len(take) < len(b):
                    keep.append((t, b[len(take):]))
            else:
                keep.append((t, b))
        self.pending = keep
        if not out:
            time.sleep(0.005)
        return bytes(out)

    def reset_input_buffer(self):
        now = time.monotonic()
        self.pending = [(t, b) for t, b in self.pending if t > now]

    def write(self, data):
        self.written.append(bytes(data))
        if self.script:
            delay, reply = self.script.pop(0)
            if reply:
                self.pending.append((time.monotonic() + delay, reply))

    def flush(self):
        pass

    def close(self):
        pass


def make(script, timeout=0.3):
    t = RtuTransport.__new__(RtuTransport)
    t.port, t.baud, t.parity, t.stopbits, t.timeout = "FAKE", 9600, "N", 1, timeout
    t.session, t.echo_seen, t._last_io, t._prev, t.late = None, False, 0.0, None, []
    t._t_char = 11 / 9600
    t._ser = FakeSerial(script)
    return t


SHT_ERR = frame(1, 0x09, 0x02)  # balasan sensor untuk alamat tidak didukung


def test_nonstandard_reply_counts_as_alive():
    t = make([(0.05, SHT_ERR)])
    r = t.request(1, 3, 0, 1)
    assert r.status == "nonstandard" and r.alive and not r.responded
    assert "0x09" in r.message


def test_nonstandard_from_other_slave_is_not_alive():
    t = make([(0.05, frame(2, 0x09, 0x02))])
    r = t.request(1, 3, 0, 1)
    assert not r.alive


def test_slow_reply_ok_when_timeout_long_enough():
    ok = frame(1, 4, 2, 0x0C, 0xA8)
    t = make([(0.6, ok)], timeout=1.0)
    r = t.request(1, 4, 1, 1)
    assert r.status == "ok" and r.values == [3240] and r.elapsed_ms >= 550


def test_late_reply_detected_between_requests():
    ok = frame(1, 4, 2, 0x0C, 0xA8)
    t = make([(0.45, ok), (0.05, None)], timeout=0.3)
    r = t.request(1, 4, 1, 1)
    assert r.status == "timeout"
    time.sleep(0.25)  # balasan masuk saat jeda antar request
    t.request(1, 4, 1, 1)
    assert len(t.late) == 1 and t.late[0]["slave"] == 1 and t.late[0]["delay_ms"] > 400


def test_late_reply_inside_next_window_is_flagged_not_misread():
    late_fc3 = frame(1, 3, 2, 0, 7)
    t = make([(0.35, late_fc3), (0, None)], timeout=0.3)
    assert t.request(1, 3, 0, 1).status == "timeout"
    r = t.request(1, 4, 0, 1)  # balasan FC03 telat jatuh di jendela request FC04
    assert r.status == "late" and r.alive and r.values == []


def test_drain_late_after_single_read():
    t = make([(0.5, frame(1, 4, 2, 0, 1))], timeout=0.3)
    assert t.request(1, 4, 1, 1).status == "timeout"
    got = t.drain_late(0.4)
    assert got and got[0]["delay_ms"] > 400


def test_request_frame_is_read_only():
    t = make([(0.01, SHT_ERR)])
    t.request(1, 4, 1, 1)
    assert t._ser.written == [build_rtu_request(1, 4, 1, 1)]
