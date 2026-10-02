"""Mode interaktif (ketik `mbprobe`): logika REPL + satu uji end-to-end lewat pseudo-terminal."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from mbprobe import repl as R

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with create_pipe_input() as inp:
        r = R.Repl(input=inp, output=DummyOutput())
        r.ctx.out = str(tmp_path / "sessions")
        yield r


@pytest.fixture(scope="module")
def tcp_sim():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    p = subprocess.Popen([sys.executable, str(ROOT / "sim" / "sim_server.py"), "tcp", "--port", str(port)],
                         stdout=subprocess.PIPE, text=True)
    p.stdout.readline()
    time.sleep(0.5)
    yield port
    p.terminate()
    p.wait(5)


def complete(text):
    return [c.text for c in R.MbCompleter().get_completions(Document(text), None)]


def test_completer_commands_and_slash():
    assert "read" in complete("re") and "scan-rtu" in complete("sc")
    assert "read" in complete("/re")
    assert "connect" in complete("con")


def test_completer_options_and_values():
    assert "--addr" in complete("read --a")
    assert set(complete("read --parity ")) >= {"N", "E", "O"}
    assert set(complete("read --fc ")) == {"1", "2", "3", "4"}  # hanya FC baca
    assert complete("connect ") == ["rtu", "tcp"]


def test_connect_parsing(rp):
    rp.handle("connect rtu COM5 19200 e 7")
    assert (rp.ctx.kind, rp.ctx.port, rp.ctx.baud, rp.ctx.parity, rp.ctx.slave) == ("rtu", "COM5", 19200, "E", 7)
    rp.handle("/connect tcp 10.0.0.5 5020 3")
    assert rp.ctx.describe() == "TCP 10.0.0.5:5020 · unit 3"


def test_build_args_injects_connection_and_label(rp):
    assert rp.build_args("read", ["--addr", "1"]) is None  # belum ada koneksi
    rp.handle("connect rtu COM5 9600 N 2")
    rp.handle("label ZR250")
    a = rp.build_args("read", ["--addr", "1"])
    assert a[:2] == ["--addr", "1"] and "--rtu" in a and a[a.index("--id") + 1] == "2"
    assert a[a.index("--label") + 1] == "ZR250"
    explicit = rp.build_args("read", ["--tcp", "1.2.3.4"])
    assert "--rtu" not in explicit  # opsi eksplisit menang
    s = rp.build_args("sniff", [])
    assert s[s.index("--port") + 1] == "COM5" and "--baud" in s
    assert "--baud" not in rp.build_args("sniff", ["--auto"])


def test_read_and_find_through_repl(rp, tcp_sim):
    rp.handle(f"connect tcp 127.0.0.1 {tcp_sim} 1")
    rp.handle("read --addr 300 --count 2")
    s = json.loads((rp.ctx.last_session / "summary.json").read_text())
    assert s["values"] == [0x438A, 0x0001]
    rp.handle("find --value 82826 --from 290 --to 310")
    s = json.loads((rp.ctx.last_session / "summary.json").read_text())
    assert any(m["addr"] == 300 and m["order"] == "CDAB" for m in s["targets"]["82826"])


def test_scan_tcp_offers_connection(rp, tcp_sim, monkeypatch):
    monkeypatch.setattr(R, "_ask_choice", lambda msg, opts, default=None: opts[0][0])
    rp.handle(f"scan-tcp --host 127.0.0.1 --ports {tcp_sim} --modbus-port {tcp_sim} --unit-ids 1")
    assert rp.ctx.kind == "tcp" and rp.ctx.tcp_port == tcp_sim and rp.ctx.slave == 1


def test_scan_rtu_hit_sets_connection(rp, tmp_path, monkeypatch):
    d = tmp_path / "s1"
    d.mkdir()
    (d / "summary.json").write_text(json.dumps({"hits": [
        {"baud": 19200, "parity": "E", "slave": 7, "fc": 3, "status": "ok", "detail": "OK"}]}))
    monkeypatch.setattr(R, "_ask_yes", lambda *a, **k: True)
    rp.after("scan-rtu", ["--port", "COM7"], d)
    assert rp.ctx.describe() == "RTU COM7 19200 E1 · ID 7"


def test_unknown_and_bad_usage_do_not_crash(rp):
    rp.handle("ngawur")
    rp.handle("read --fc")  # usage error dari CLI → pesan, REPL tetap hidup
    rp.handle("exit")
    assert rp.running is False


@pytest.mark.skipif(os.name == "nt", reason="pexpect butuh pty")
def test_interactive_end_to_end(tcp_sim, tmp_path):
    pexpect = pytest.importorskip("pexpect")
    child = pexpect.spawn(sys.executable, ["-m", "mbprobe"], cwd=str(tmp_path), dimensions=(40, 120),
                          env={**os.environ, "HOME": str(tmp_path), "PYTHONPATH": str(ROOT),
                               "PROMPT_TOOLKIT_NO_CPR": "1"}, encoding="utf-8", timeout=20)
    child.expect("READ-ONLY")
    child.expect("›")
    child.sendline(f"connect tcp 127.0.0.1 {tcp_sim} 1")
    child.expect("Koneksi aktif")
    child.sendline("read --addr 120 --count 1")
    child.expect("Hasil disimpan")
    child.sendline("exit")
    child.expect("Sampai jumpa")
    child.expect(pexpect.EOF)
    sessions = list((tmp_path / "sessions").iterdir())
    assert len(sessions) == 1
    assert json.loads((sessions[0] / "summary.json").read_text())["values"] == [370]
