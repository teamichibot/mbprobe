#!/bin/sh
# Installer mbprobe untuk Linux x64 / macOS Apple Silicon (tanpa Python).
#   curl -fsSL https://raw.githubusercontent.com/teamichibot/mbprobe/main/install.sh | sh
set -eu
REPO=teamichibot/mbprobe
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) asset=mbprobe-linux-x64 ;;
  Darwin-arm64) asset=mbprobe-macos-arm64 ;;
  *)
    echo "Belum ada binary untuk $(uname -s)-$(uname -m)."
    echo "Pakai: uv tool install git+https://github.com/$REPO"
    exit 1 ;;
esac
dest="${MBPROBE_DIR:-$HOME/.local/bin}"
mkdir -p "$dest"
echo "Mengunduh $asset ke $dest/mbprobe ..."
curl -fsSL "https://github.com/$REPO/releases/latest/download/$asset" -o "$dest/mbprobe.tmp"
chmod +x "$dest/mbprobe.tmp"
mv "$dest/mbprobe.tmp" "$dest/mbprobe"
"$dest/mbprobe" version
case ":$PATH:" in
  *":$dest:"*) echo "Selesai. Ketik: mbprobe" ;;
  *) echo "Selesai. Tambahkan ke PATH dulu:  export PATH=\"$dest:\$PATH\"  (taruh di ~/.zshrc atau ~/.bashrc)" ;;
esac
