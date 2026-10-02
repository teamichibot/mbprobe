"""Bukti bahwa mbprobe READ-ONLY di level kode.

1. Tidak ada identifier/fungsi tulis Modbus di source (write_register, write_coil, dll).
2. Tidak memakai client pymodbus (yang punya method tulis).
3. Semua pemanggilan .request(...) / build_*_request(...) dengan FC literal hanya memakai 1-4.
4. Hanya transport yang boleh mengirim byte; sniff.py tidak mengirim apa pun.
5. Builder dan transport menolak FC tulis saat runtime.
"""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "mbprobe"
SOURCES = sorted(PKG.glob("*.py"))

FORBIDDEN = re.compile(
    r"write_(single_|multiple_)?(register|registers|coil|coils)"
    r"|mask_write|readwrite|read_write|write_file_record|WriteSingle|WriteMultiple"
    r"|MaskWrite|ReadWriteMultiple|FC_WRITE|WRITE_FC",
    re.IGNORECASE,
)
WRITE_FCS = {5, 6, 15, 16, 22, 23}
SEND_METHODS = {"write", "writelines", "send", "sendall", "sendto"}


def _trees():
    for p in SOURCES:
        yield p, ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_sources_found():
    names = {p.name for p in SOURCES}
    assert {"cli.py", "transport_rtu.py", "transport_tcp.py", "sniff.py", "scan.py", "decode.py"} <= names


def test_no_write_identifiers_in_codebase():
    hits = []
    for p in SOURCES:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if FORBIDDEN.search(line):
                hits.append(f"{p.name}:{i}: {line.strip()}")
    assert not hits, "Identifier tulis ditemukan:\n" + "\n".join(hits)


def test_no_pymodbus_client_import():
    for p, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mod = getattr(node, "module", None) or ""
                names = [a.name for a in node.names]
                assert "pymodbus" not in mod and not any("pymodbus" in n for n in names), \
                    f"{p.name} mengimpor pymodbus (client punya method tulis); pakai transport sendiri"


def test_read_function_code_set_is_exactly_1_to_4():
    from mbprobe.protocol import READ_FUNCTION_CODES
    assert READ_FUNCTION_CODES == frozenset({1, 2, 3, 4})


def _fc_arg(call: ast.Call, pos: int):
    for kw in call.keywords:
        if kw.arg == "fc":
            return kw.value
    return call.args[pos] if len(call.args) > pos else None


def test_literal_function_codes_are_read_only():
    """Setiap .request(slave, fc, ...) / build_*(…, fc, …) dengan FC literal harus 1-4."""
    positions = {"request": 1, "build_rtu_request": 1, "build_tcp_request": 2, "build_read_pdu": 0}
    checked = 0
    for p, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Call, ast.For)):
                continue
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in positions:
                    arg = _fc_arg(node, positions[name])
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                        checked += 1
                        assert arg.value in (1, 2, 3, 4), f"{p.name}:{node.lineno} memakai FC {arg.value}"
            # pola `for fc in (3, 4): ...`
            if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == "fc" \
                    and isinstance(node.iter, (ast.Tuple, ast.List, ast.Set)):
                vals = [e.value for e in node.iter.elts if isinstance(e, ast.Constant)]
                checked += len(vals)
                assert set(vals) <= {1, 2, 3, 4}, f"{p.name}:{node.lineno} loop FC {vals}"
    assert checked >= 2  # scan memakai FC03/FC04


def test_no_write_fc_constant_in_frame_builders():
    """protocol.py & transport tidak boleh berisi literal 5/6/15/16/22/23 sebagai elemen set/list FC."""
    for name in ("protocol.py", "transport_rtu.py", "transport_tcp.py"):
        tree = ast.parse((PKG / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
                vals = {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, int)}
                if vals and vals <= set(range(0, 128)) and vals & WRITE_FCS and vals & {1, 2, 3, 4}:
                    pytest.fail(f"{name}:{node.lineno} kumpulan FC berisi FC tulis {vals & WRITE_FCS}")


def test_only_transports_send_bytes():
    allowed = {"transport_rtu.py", "transport_tcp.py", "logging_utils.py", "cli.py"}
    for p, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in SEND_METHODS:
                assert p.name in allowed, f"{p.name}:{node.lineno} memanggil .{node.func.attr}()"
                if p.name in ("logging_utils.py", "cli.py"):
                    # hanya file/CSV, bukan port: objeknya bukan serial/socket
                    src = ast.unparse(node.func.value)
                    assert "ser" not in src.lower() and "sock" not in src.lower(), f"{p.name}:{node.lineno} {src}"


def test_sniff_is_passive():
    tree = ast.parse((PKG / "sniff.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in SEND_METHODS | {"flush", "send_break", "reset_output_buffer"}, \
                f"sniff.py:{node.lineno} memanggil .{node.func.attr}()"
            assert "request" not in node.func.attr, f"sniff.py:{node.lineno} memanggil request"


def test_transport_rejects_write_fc_at_runtime():
    from mbprobe.protocol import NotReadOnlyError
    from mbprobe.transport_tcp import TcpTransport
    t = TcpTransport("127.0.0.1", 1)
    for fc in sorted(WRITE_FCS):
        with pytest.raises(NotReadOnlyError):
            t.request(1, fc, 0, 1)


def test_config_rejects_write_fc(tmp_path):
    from mbprobe.config import ConfigError, load_config
    f = tmp_path / "u.yaml"
    f.write_text("name: x\nconnection: {type: tcp, host: 1.2.3.4}\nregisters:\n  - {name: a, fc: 6, addr: 1}\n")
    with pytest.raises(ConfigError):
        load_config(f)


def test_guard_actually_catches_violations():
    """Meta-test: pastikan pola grep benar-benar menangkap pemanggilan tulis yang umum."""
    for bad in ("client.write_register(1, 2)", "c.write_registers(0, [1])", "c.write_coil(1, True)",
                "c.write_coils(0, [1])", "WriteSingleRegisterRequest", "c.readwrite_registers()",
                "c.mask_write_register()"):
        assert FORBIDDEN.search(bad), bad
    for fine in ("ser.write(tx)", "csv.writer(f)", "self._log.write(msg)"):
        assert not FORBIDDEN.search(fine), fine
