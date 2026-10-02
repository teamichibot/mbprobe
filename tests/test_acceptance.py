"""Acceptance test end-to-end: CLI mbprobe vs simulator (pymodbus) di bus RS485 virtual & TCP.

Butuh Linux/macOS (pty). Di Windows, jalankan prosedur manual dengan com0com (lihat README).
Device tersembunyi: RTU 19200 E, slave ID 7.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

if os.name == "nt":
    pytest.skip("acceptance test otomatis butuh pty (Linux/macOS)", allow_module_level=True)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sim"))
from virtual_bus import VirtualBus  # noqa: E402

PY = sys.executable
HIDDEN = dict(baud=19200, parity="E", id=7)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_sim(args: list[str]) -> subprocess.Popen:
    p = subprocess.Popen([PY, str(ROOT / "sim" / "sim_server.py"), *args],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = p.stdout.readline()
    assert "[sim]" in line, line
    time.sleep(0.5)
    return p


def stop(p: subprocess.Popen) -> None:
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


def mbprobe(out: Path, *args, timeout=180, check=True) -> tuple[subprocess.CompletedProcess, Path]:
    cp = subprocess.run([PY, "-m", "mbprobe", *map(str, args), "--out", str(out)], cwd=ROOT,
                        capture_output=True, text=True, timeout=timeout,
                        env={**os.environ, "COLUMNS": "200"})
    if check:
        assert cp.returncode == 0, cp.stdout + cp.stderr
    dirs = sorted(out.iterdir()) if out.exists() else []
    return cp, (dirs[-1] if dirs else None)


def summary(d: Path) -> dict:
    return json.loads((d / "summary.json").read_text())


@pytest.fixture(scope="module")
def bus():
    b = VirtualBus(3).start()
    sim = start_sim(["rtu", "--port", b.paths[0], "--baud", str(HIDDEN["baud"]),
                     "--parity", HIDDEN["parity"], "--id", str(HIDDEN["id"])])
    yield b
    stop(sim)
    b.stop()


@pytest.fixture(scope="module")
def tcp_sim():
    port = free_port()
    sim = start_sim(["tcp", "--host", "127.0.0.1", "--port", str(port), "--unit", "1"])
    yield port
    stop(sim)


RTU = lambda b: ["--rtu", b.paths[1], "--baud", HIDDEN["baud"], "--parity", HIDDEN["parity"], "--id", HIDDEN["id"]]  # noqa


# ------------------------------------------------------------------ RTU

def test_scan_rtu_finds_hidden_device(bus, tmp_path):
    cp, d = mbprobe(tmp_path, "scan-rtu", "--port", bus.paths[1], "--bauds", "9600,19200,38400",
                    "--parity", "N,E", "--ids", "1-10", "--timeout", "0.15", "--delay", "0.05")
    hits = summary(d)["hits"]
    assert [(h["baud"], h["parity"], h["slave"]) for h in hits] == [(19200, "E", 7)]
    assert hits[0]["status"] == "ok" and hits[0]["values"] == [1000]
    assert (d / "scan_rtu.csv").read_text().count("\n") == 2
    assert "DITEMUKAN" in cp.stdout


def test_scan_rtu_stop_on_first(bus, tmp_path):
    _, d = mbprobe(tmp_path, "scan-rtu", "--port", bus.paths[1], "--bauds", "19200", "--parity", "E",
                   "--ids", "5-20", "--timeout", "0.15", "--stop-on-first")
    s = summary(d)
    assert [h["slave"] for h in s["hits"]] == [7]
    assert s["attempts"] < 16 * 2


def test_read_rtu_interpretations(bus, tmp_path):
    cp, d = mbprobe(tmp_path, "read", *RTU(bus), "--fc", 3, "--addr", 120, "--count", 3)
    assert summary(d)["values"] == [370, 42, 0xFFFE]
    csv16 = (d / "read_16.csv").read_text()
    assert "122,65534,-2,0xFFFE" in csv16
    assert "3.7" in cp.stdout


def test_read_rtu_exception_is_reported(bus, tmp_path):
    cp, d = mbprobe(tmp_path, "read", *RTU(bus), "--addr", 100, "--count", 1)
    assert summary(d)["status"] == "exception" and summary(d)["exc_code"] == 2
    assert "ILLEGAL DATA ADDRESS" in cp.stdout


def test_read_rtu_wrong_baud_gives_hint(bus, tmp_path):
    cp, d = mbprobe(tmp_path, "read", "--rtu", bus.paths[1], "--baud", 9600, "--parity", "E", "--id", 7,
                    "--timeout", "0.3")
    assert summary(d)["status"] in ("timeout", "crc_error")
    assert "A/B" in cp.stdout or "CRC" in cp.stdout


def test_find_value_rtu(bus, tmp_path):
    _, d = mbprobe(tmp_path, "find-value", *RTU(bus), "--value", 82826, "--value", 3.7,
                   "--from", 280, "--to", 320, "--delay", 0.05)
    t = summary(d)["targets"]
    assert any(m["addr"] == 300 and m["typ"] == "uint32" and m["order"] == "CDAB" for m in t["82826"])
    assert t["3.7"] == []  # 120 di luar rentang 280..320


def test_dump_maps_valid_and_exception(bus, tmp_path):
    _, d = mbprobe(tmp_path, "dump", *RTU(bus), "--from", 90, "--to", 130, "--block", 50, "--delay", 0.05)
    ranges = [(r["from"], r["to"], r["status"]) for r in summary(d)["ranges"]]
    assert ranges == [(90, 99, "ok"), (100, 119, "exception 2"), (120, 130, "ok")]
    lines = (d / "dump.csv").read_text().splitlines()
    assert lines[0] == "addr,raw,hex,status,exc_code"
    assert "120,370,0x0172,ok," in lines
    assert "105,,,exception 2,2" in lines


def test_sniff_auto_detects_other_master(bus, tmp_path):
    """Client lain mem-poll simulator di endpoint 2; sniff --auto di endpoint 1 harus menemukan 19200 E."""
    from mbprobe.transport_rtu import RtuTransport
    stop_evt = threading.Event()

    def other_master():
        with RtuTransport(bus.paths[2], HIDDEN["baud"], HIDDEN["parity"], timeout=0.3) as t:
            while not stop_evt.is_set():
                t.request(HIDDEN["id"], 3, 120, 2)
                time.sleep(0.15)

    th = threading.Thread(target=other_master, daemon=True)
    th.start()
    try:
        cp, d = mbprobe(tmp_path, "sniff", "--port", bus.paths[1], "--auto", "--dwell", 1)
    finally:
        stop_evt.set()
        th.join()
    s = summary(d)
    assert s["best"] == {"baud": 19200, "parity": "E"}
    valid = {(r["baud"], r["parity"]) for r in s["results"] if r["valid_frames"]}
    assert valid == {(19200, "E")}
    row = next(r for r in s["results"] if (r["baud"], r["parity"]) == (19200, "E"))
    assert row["slaves"] == [7]
    assert "Bus sudah dipakai master lain" in cp.stdout


def test_sniff_reports_request_details(bus, tmp_path):
    from mbprobe.transport_rtu import RtuTransport

    def other_master():
        time.sleep(0.3)
        with RtuTransport(bus.paths[2], HIDDEN["baud"], HIDDEN["parity"], timeout=0.3) as t:
            for _ in range(3):
                t.request(HIDDEN["id"], 4, 0, 5)
                time.sleep(0.2)

    th = threading.Thread(target=other_master, daemon=True)
    th.start()
    _, d = mbprobe(tmp_path, "sniff", "--port", bus.paths[1], "--baud", 19200, "--parity", "E",
                   "--duration", 2)
    th.join()
    s = summary(d)
    assert {"slave": 7, "fc": 4, "addr": 0, "count": 5, "n": 3} in s["requests"]
    frames = (d / "sniff_frames.csv").read_text()
    assert "response" in frames and "2000 2001 2002 2003 2004" in frames


def test_sniff_wrong_parity_reports_non_modbus(bus, tmp_path):
    from mbprobe.transport_rtu import RtuTransport

    def other_master():
        time.sleep(0.3)
        with RtuTransport(bus.paths[2], HIDDEN["baud"], HIDDEN["parity"], timeout=0.3) as t:
            for _ in range(4):
                t.request(HIDDEN["id"], 3, 0, 10)
                time.sleep(0.15)

    th = threading.Thread(target=other_master, daemon=True)
    th.start()
    _, d = mbprobe(tmp_path, "sniff", "--port", bus.paths[1], "--baud", 9600, "--parity", "N",
                   "--duration", 1.5)
    th.join()
    s = summary(d)
    assert s["valid_frames"] == 0 and s["bytes"] > 0
    assert s["verdict"] == "ada lalu lintas non-Modbus atau baud/parity tidak cocok"
    assert s["sample_raw_hex"]


def test_poll_rtu(bus, tmp_path):
    cfg = tmp_path / "unit.yaml"
    cfg.write_text((ROOT / "examples" / "unit_sim.yaml").read_text())
    _, d = mbprobe(tmp_path / "out", "poll", "--config", cfg, "--port", bus.paths[1],
                   "--interval", 0.5, "--duration", 2)
    rows = (d / "poll.csv").read_text().splitlines()
    assert rows[0] == "timestamp,outlet_pressure,running_hours,load_hours,element_temp,input_reg_0"
    assert len(rows) >= 3
    assert rows[1].split(",")[1:] == ["3.7", "82826", "70335", "82.5", "2000"]


def test_poll_interval_floor(bus, tmp_path):
    cfg = tmp_path / "unit.yaml"
    cfg.write_text((ROOT / "examples" / "unit_sim.yaml").read_text())
    cp, d = mbprobe(tmp_path / "out", "poll", "--config", cfg, "--port", bus.paths[1],
                    "--interval", 0.1, "--duration", 1.2)
    assert "dinaikkan ke 0.5" in cp.stdout
    assert len((d / "poll.csv").read_text().splitlines()) <= 1 + 3


def test_echo_adapter_is_ignored(tmp_path):
    with VirtualBus(2, echo={1}) as b:
        sim = start_sim(["rtu", "--port", b.paths[0], "--baud", "9600", "--parity", "N", "--id", "3"])
        try:
            cp, d = mbprobe(tmp_path, "scan-rtu", "--port", b.paths[1], "--bauds", "9600", "--parity", "N",
                            "--ids", "1-4", "--timeout", "0.2")
            s = summary(d)
            assert [h["slave"] for h in s["hits"]] == [3]
            assert s["echo"] is True
            assert "echo" in cp.stdout.lower()
            log = (d / "log.txt").read_text()
            assert "echo adaptor dibuang" in log
        finally:
            stop(sim)


def test_log_has_timestamped_tx_rx(bus, tmp_path):
    _, d = mbprobe(tmp_path, "read", *RTU(bus), "--addr", 0, "--count", 2)
    log = (d / "log.txt").read_text().splitlines()
    tx = [l for l in log if " TX " in l]
    rx = [l for l in log if " RX " in l]
    assert tx and rx
    assert tx[0][:4].isdigit() and "07 03 00 00 00 02" in tx[0]
    assert "status=ok" in rx[0]


# ------------------------------------------------------------------ error lapangan

def test_bad_port_clear_error(tmp_path):
    cp, d = mbprobe(tmp_path, "read", "--rtu", "/dev/does-not-exist", check=False)
    assert cp.returncode == 1
    assert "Tidak bisa membuka" in cp.stdout and "mbprobe ports" in cp.stdout
    assert "Traceback" not in cp.stdout + cp.stderr


def test_ctrl_c_keeps_partial_results(bus, tmp_path):
    args = ["dump", *RTU(bus), "--from", 0, "--to", 3000, "--block", 10, "--delay", 0.05, "--out", tmp_path]
    p = subprocess.Popen([PY, "-m", "mbprobe", *map(str, args)], cwd=ROOT,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(3)
    p.send_signal(signal.SIGINT)
    out, _ = p.communicate(timeout=20)
    assert p.returncode == 130, out
    assert "Ctrl+C" in out and "Traceback" not in out
    d = next(tmp_path.iterdir())
    rows = (d / "dump.csv").read_text().splitlines()
    assert len(rows) > 10
    assert summary(d)["valid"] == len(rows) - 1 - summary(d)["exception"]


def test_port_disconnect_mid_dump(tmp_path):
    b = VirtualBus(2).start()
    sim = start_sim(["rtu", "--port", b.paths[0], "--baud", "9600", "--parity", "N", "--id", "1"])
    args = ["dump", "--rtu", b.paths[1], "--id", 1, "--from", 0, "--to", 3000, "--block", 10,
            "--delay", 0.05, "--out", tmp_path]
    p = subprocess.Popen([PY, "-m", "mbprobe", *map(str, args)], cwd=ROOT,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(2.5)
        stop(sim)
        b.stop()  # "cabut kabel": pty ditutup
        out, _ = p.communicate(timeout=60)
    finally:
        if p.poll() is None:
            p.kill()
    assert p.returncode in (0, 1), out
    assert "Traceback" not in out
    d = next(tmp_path.iterdir())
    assert len((d / "dump.csv").read_text().splitlines()) > 5
    assert (d / "summary.json").exists()


# ------------------------------------------------------------------ TCP

def test_scan_tcp_single_host(tcp_sim, tmp_path):
    _, d = mbprobe(tmp_path, "scan-tcp", "--host", "127.0.0.1", "--ports", tcp_sim,
                   "--modbus-port", tcp_sim, "--unit-ids", "1")
    hosts = summary(d)["hosts"]
    assert hosts[0]["host"] == "127.0.0.1" and tcp_sim in hosts[0]["open_ports"]
    assert hosts[0]["modbus"][0]["status"] == "ok"


def test_scan_tcp_subnet(tcp_sim, tmp_path):
    _, d = mbprobe(tmp_path, "scan-tcp", "--subnet", "127.0.0.0/29", "--ports", tcp_sim,
                   "--modbus-port", tcp_sim, "--unit-ids", "0,1,255", "--timeout", 0.5)
    hosts = {h["host"]: h for h in summary(d)["hosts"]}
    assert "127.0.0.1" in hosts
    assert any(m["unit"] == 1 and m["status"] == "ok" for m in hosts["127.0.0.1"]["modbus"])


def test_read_and_find_value_tcp(tcp_sim, tmp_path):
    _, d = mbprobe(tmp_path / "a", "read", "--tcp", "127.0.0.1", "--tcp-port", tcp_sim, "--unit", 1,
                   "--fc", 4, "--addr", 10, "--count", 3)
    assert summary(d)["values"] == [2010, 2011, 2012]
    _, d = mbprobe(tmp_path / "b", "find-value", "--tcp", "127.0.0.1", "--tcp-port", tcp_sim, "--unit", 1,
                   "--value", 70335, "--value", 82.5, "--from", 0, "--to", 400, "--block", 100,
                   "--delay", 0.05)
    t = summary(d)["targets"]
    assert any(m["addr"] == 302 and m["order"] == "CDAB" for m in t["70335"])
    assert any(m["addr"] == 310 and m["typ"] == "float32" and m["order"] == "ABCD" for m in t["82.5"])


def test_dump_tcp_coils(tcp_sim, tmp_path):
    _, d = mbprobe(tmp_path, "dump", "--tcp", "127.0.0.1", "--tcp-port", tcp_sim, "--unit", 1,
                   "--fc", 1, "--from", 0, "--to", 20)
    ranges = [(r["from"], r["to"], r["status"]) for r in summary(d)["ranges"]]
    assert ranges[0][:2] == (0, 15) and ranges[0][2] == "ok"
    assert ranges[-1][2].startswith("exception")


def test_tcp_connection_refused(tmp_path):
    cp, d = mbprobe(tmp_path, "read", "--tcp", "127.0.0.1", "--tcp-port", free_port(), check=False)
    assert summary(d)["status"] == "port_error"
    assert "Gagal konek" in cp.stdout
