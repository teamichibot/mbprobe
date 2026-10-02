import struct

import pytest

from mbprobe.protocol import (NotReadOnlyError, build_rtu_request, build_tcp_request, crc16,
                              crc_ok, parse_pdu_response)


def test_crc_known_vector():
    # 01 03 00 00 00 01 → CRC 84 0A (vektor standar)
    assert build_rtu_request(1, 3, 0, 1).hex(" ").upper() == "01 03 00 00 00 01 84 0A"
    assert crc16(bytes.fromhex("010400000001")) == 0xCA31


def test_crc_ok_detects_corruption():
    f = bytearray(build_rtu_request(7, 4, 100, 10))
    assert crc_ok(bytes(f))
    f[3] ^= 0x01
    assert not crc_ok(bytes(f))


def test_tcp_request_layout():
    f = build_tcp_request(0x1234, 1, 4, 100, 20)
    tid, proto, length, unit, fc, addr, count = struct.unpack(">HHHBBHH", f)
    assert (tid, proto, length, unit, fc, addr, count) == (0x1234, 0, 6, 1, 4, 100, 20)


def test_parse_registers_and_exception():
    assert parse_pdu_response(3, 2, bytes([3, 4, 0x01, 0x72, 0xFF, 0xFE]))[:2] == ("ok", [370, 0xFFFE])
    st, _, exc, _ = parse_pdu_response(3, 1, bytes([0x83, 2]))
    assert (st, exc) == ("exception", 2)
    assert parse_pdu_response(3, 2, bytes([3, 2, 0, 1]))[0] == "invalid"


def test_parse_bits():
    st, bits, _, _ = parse_pdu_response(1, 10, bytes([1, 2, 0b10000101, 0b10]))
    assert st == "ok" and bits == [1, 0, 1, 0, 0, 0, 0, 1, 0, 1]


@pytest.mark.parametrize("fc", [5, 6, 15, 16, 22, 23, 8, 43, 0])
def test_builders_reject_non_read_fc(fc):
    with pytest.raises(NotReadOnlyError):
        build_rtu_request(1, fc, 0, 1)
    with pytest.raises(NotReadOnlyError):
        build_tcp_request(1, 1, fc, 0, 1)


def test_count_limits():
    with pytest.raises(ValueError):
        build_rtu_request(1, 3, 0, 126)
    with pytest.raises(ValueError):
        build_rtu_request(1, 3, 0, 0)
    build_rtu_request(1, 1, 0, 2000)
