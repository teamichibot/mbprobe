#!/usr/bin/env bash
# Build single executable untuk OS saat ini (Linux/macOS). PyInstaller TIDAK bisa cross-compile:
# mbprobe.exe harus dibuild di Windows (scripts/build_exe.bat atau GitHub Actions).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --onefile --console --name mbprobe --collect-submodules serial.tools mbprobe/__main__.py
dist/mbprobe version
