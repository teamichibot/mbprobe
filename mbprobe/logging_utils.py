"""Folder sesi, log.txt request/response, dan writer CSV/JSON yang langsung flush."""
from __future__ import annotations

import csv
import json
import re
import threading
from datetime import datetime
from pathlib import Path

from .protocol import Result, hexs


def _ts() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


class CsvSink:
    """CSV yang di-flush tiap baris, supaya hasil sementara aman saat Ctrl+C / port putus."""

    def __init__(self, path: Path, header: list[str]):
        self.path = path
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._w = csv.writer(self._f)
        self._w.writerow(header)
        self._f.flush()
        self.rows = 0

    def add(self, row: list) -> None:
        self._w.writerow(row)
        self._f.flush()
        self.rows += 1

    def close(self) -> None:
        if not self._f.closed:
            self._f.close()


class Session:
    def __init__(self, command: str, label: str = "", root: str | Path = "sessions"):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")
        name = f"{stamp}_{safe}" if safe else f"{stamp}_{command}"
        base = Path(root) / name
        n = 1
        while base.exists():
            n += 1
            base = Path(root) / f"{name}_{n}"
        base.mkdir(parents=True)
        self.dir = base
        self.command = command
        self._log = open(base / "log.txt", "a", encoding="utf-8")
        self._lock = threading.Lock()
        self._sinks: list[CsvSink] = []
        self.files: list[Path] = [base / "log.txt"]
        self.echo_reported = False
        self.log(f"=== mbprobe {command} — sesi dimulai ===")

    def log(self, msg: str) -> None:
        with self._lock:
            self._log.write(f"{_ts()} {msg}\n")
            self._log.flush()

    def log_tx(self, link: str, tx: bytes, note: str = "") -> None:
        self.log(f"TX {link} {note} | {hexs(tx)}".replace("  ", " "))

    def log_result(self, link: str, r: Result) -> None:
        """TX + RX sekaligus (untuk transport yang tidak mencatat TX saat kirim)."""
        self.log_tx(link, r.tx, f"id={r.slave} fc={r.fc} addr={r.addr} count={r.count}")
        self.log_rx(link, r)

    def log_rx(self, link: str, r: Result) -> None:
        extra = ""
        if r.status == "exception":
            extra = f" exc={r.exc_code}"
        elif r.status == "ok":
            extra = f" values={r.values[:16]}{'…' if len(r.values) > 16 else ''}"
        if r.echo:
            extra += " (echo adaptor dibuang)"
        if r.message:
            extra += f" msg={r.message!r}"
        self.log(
            f"RX {link} status={r.status}{extra} t={r.elapsed_ms:.0f}ms | {hexs(r.rx) if r.rx else '-'}"
        )

    def csv(self, filename: str, header: list[str]) -> CsvSink:
        s = CsvSink(self.dir / filename, header)
        self._sinks.append(s)
        self.files.append(s.path)
        return s

    def json(self, filename: str, data) -> Path:
        p = self.dir / filename
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        if p not in self.files:
            self.files.append(p)
        return p

    def close(self) -> None:
        for s in self._sinks:
            s.close()
        self.log("=== sesi selesai ===")
        self._log.close()
