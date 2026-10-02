# Installer mbprobe untuk Windows (tanpa Python).
#   irm https://raw.githubusercontent.com/teamichibot/mbprobe/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'
$repo = 'teamichibot/mbprobe'
$dir = Join-Path $env:LOCALAPPDATA 'mbprobe'
$exe = Join-Path $dir 'mbprobe.exe'
$url = "https://github.com/$repo/releases/latest/download/mbprobe-windows-x64.exe"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Mengunduh mbprobe dari $url ..."
try {
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
} catch {
    Write-Host "Gagal mengunduh/menimpa $exe. Kalau mbprobe sedang terbuka, tutup dulu lalu ulangi." -ForegroundColor Red
    throw
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $dir)) {
    $newPath = (@($userPath, $dir) | Where-Object { $_ }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Ditambahkan ke PATH: $dir"
}
if (-not (($env:Path -split ';') -contains $dir)) { $env:Path += ";$dir" }

& $exe version
Write-Host ""
Write-Host "Selesai. Ketik: mbprobe   (kalau tidak dikenali, buka terminal baru)" -ForegroundColor Green
