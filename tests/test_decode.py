import math

from mbprobe.decode import decode_value, find_value, parse_rtu_stream, regs_to_bytes
from mbprobe.protocol import build_rtu_request, crc_bytes


def words(value_bytes: bytes, order: str):
    """Kebalikan regs_to_bytes: susun 2 register dari 4 byte ABCD menurut order."""
    m = dict(zip("ABCD", value_bytes))
    o = [m[c] for c in order]
    return [o[0] << 8 | o[1], o[2] << 8 | o[3]]


def test_regs_to_bytes_orders():
    r0, r1 = 0x0102, 0x0304  # A=01 B=02 C=03 D=04
    assert regs_to_bytes(r0, r1, "ABCD") == bytes([1, 2, 3, 4])
    assert regs_to_bytes(r0, r1, "CDAB") == bytes([3, 4, 1, 2])
    assert regs_to_bytes(r0, r1, "BADC") == bytes([2, 1, 4, 3])
    assert regs_to_bytes(r0, r1, "DCBA") == bytes([4, 3, 2, 1])


def test_uint32_all_orders_roundtrip():
    raw = (82826).to_bytes(4, "big")
    for order in ("ABCD", "CDAB", "BADC", "DCBA"):
        assert decode_value(words(raw, order), "uint32", order) == 82826


def test_cdab_known_words():
    # 82826 = 0x0001438A → CDAB: reg N = 0x438A, reg N+1 = 0x0001
    assert decode_value([0x438A, 0x0001], "uint32", "CDAB") == 82826
    assert decode_value([0x0001, 0x438A], "uint32", "ABCD") == 82826


def test_int16_int32_float():
    assert decode_value([0xFFFE], "int16") == -2
    assert decode_value([0xFFFF, 0xFFFF], "int32", "ABCD") == -1
    assert math.isclose(decode_value([0x42A5, 0x0000], "float32", "ABCD"), 82.5)
    assert math.isclose(decode_value([0x0000, 0x42A5], "float32", "CDAB"), 82.5)


def test_find_value_scales_and_orders():
    regs = {120: 370, 121: 37, 300: 0x438A, 301: 0x0001, 500: 0x42A5, 501: 0}
    hits = find_value(regs, 3.7)
    got = {(m.addr, m.typ, m.scale) for m in hits}
    assert (120, "uint16", 0.01) in got and (121, "uint16", 0.1) in got
    assert any(m.addr == 300 and m.order == "CDAB" and m.typ == "uint32" for m in find_value(regs, 82826))
    assert any(m.addr == 500 and m.typ == "float32" for m in find_value(regs, 82.5))
    assert find_value(regs, 82827) == []
    assert any(m.addr == 300 for m in find_value(regs, 82827, tolerance=1))


def _resp(slave, fc, regs):
    body = bytes([slave, fc, 2 * len(regs)]) + b"".join(r.to_bytes(2, "big") for r in regs)
    return body + crc_bytes(body)


def test_parse_stream_merged_frames_and_junk():
    req = build_rtu_request(7, 3, 120, 2)
    resp = _resp(7, 3, [370, 42])
    exc = bytes([7, 0x83, 2]) + crc_bytes(bytes([7, 0x83, 2]))
    data = b"\x00\xff" + req + resp + req + exc
    frames, junk = parse_rtu_stream(data)
    kinds = [f.kind for f in frames]
    assert kinds == ["request", "response", "request", "exception"]
    assert frames[0].addr == 120 and frames[0].count == 2
    assert frames[1].values == [370, 42]
    assert frames[3].exc_code == 2
    assert junk == [(0, b"\x00\xff")]


def test_parse_stream_no_valid_crc():
    frames, junk = parse_rtu_stream(bytes(range(40)))
    assert frames == [] and sum(len(j) for _, j in junk) == 40


def test_parse_stream_unknown_fc_uses_gap_boundary():
    body = bytes([1, 0x11])  # FC17 (report slave id) — tidak didekode, tapi terpisah via jeda
    f = body + crc_bytes(body)
    frames, junk = parse_rtu_stream(f + b"\x99", boundaries=[len(f)])
    assert len(frames) == 1 and frames[0].kind == "other"
