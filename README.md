# mbprobe: Modbus probe tool (read-only)

Tool CLI untuk memverifikasi apakah data bisa dibaca dari controller (compressor Atlas Copco
Elektronikon, Kobelco, dll.) lewat **Modbus RTU (RS485)** atau **Modbus TCP**, tanpa Modbus map
dan **tanpa risiko mengubah apa pun di controller**.

## Jaminan read-only

- Hanya **FC 01, 02, 03, 04** yang diimplementasikan. Function code tulis (05, 06, 15, 16, 22, 23)
  **tidak ada di codebase**: tidak ada builder-nya, dan tidak memakai client pymodbus (yang punya
  method tulis). Frame dibangun sendiri di `mbprobe/protocol.py`.
- Berlapis: builder menolak FC selain 1–4, transport mengecek byte FC sebelum mengirim, config
  YAML menolak `fc` selain 1–4.
- `tests/test_readonly.py` membuktikannya: grep identifier tulis, cek AST semua FC literal,
  hanya modul transport yang boleh mengirim byte, dan `sniff.py` tidak memanggil fungsi kirim apa pun.
- Jeda aman dengan batas minimum yang tidak bisa diturunkan:
  - poll: interval antar siklus default 5 s, minimum 0,5 s
  - scan/dump/find-value: jeda antar request default 100 ms, minimum 50 ms

  Nilai di bawah batas otomatis dinaikkan (ada peringatan).
- Semua request/response/timeout/exception tercatat di `log.txt` (hex + timestamp ms).

## Instalasi

**Windows tanpa Python** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/teamichibot/mbprobe/main/install.ps1 | iex
```
Script ini mengunduh `mbprobe.exe` dari GitHub Release terbaru ke `%LOCALAPPDATA%\mbprobe` dan
menambahkannya ke PATH. Jalankan perintah yang sama untuk update. Pakai Windows Terminal/PowerShell
(bukan cmd.exe lama) supaya tampilan mode interaktif rapi. Exe belum ditandatangani, jadi kalau Windows
Defender/SmartScreen memperingatkan, pilih *More info → Run anyway* (atau unduh manual dari halaman Releases).

**macOS (Apple Silicon) / Linux x64 tanpa Python:**
```bash
curl -fsSL https://raw.githubusercontent.com/teamichibot/mbprobe/main/install.sh | sh
```

**Dengan Python** (semua OS, butuh [uv](https://docs.astral.sh/uv/)):
```bash
uv tool install git+https://github.com/teamichibot/mbprobe
uv tool upgrade mbprobe         # update
```
atau `pipx install git+https://github.com/teamichibot/mbprobe`.

Setelah terpasang, cukup ketik **`mbprobe`** di terminal mana pun. Folder hasil `sessions/` dibuat
di folder tempat mbprobe dijalankan.

**Untuk development:**
```bash
git clone https://github.com/teamichibot/mbprobe && cd mbprobe
pip install -r requirements-dev.txt && pip install -e .
python -m pytest
```

**Membuat rilis baru:** naikkan `__version__` di `mbprobe/__init__.py` dan `version` di `pyproject.toml`,
lalu `git tag v0.1.1 && git push origin v0.1.1`. Workflow `release.yml` mem-build binary Windows/Linux/macOS
dan membuat GitHub Release, yang dipakai oleh installer di atas.

Driver adaptor USB-RS485: CH340 perlu driver WCH di Windows lama, sedangkan FTDI/CP210x biasanya otomatis.
Di Linux, tambahkan user ke grup `dialout` (`sudo usermod -aG dialout $USER`, lalu login ulang).

## Mode interaktif (cukup ketik `mbprobe`)

```bash
mbprobe            # di Windows: mbprobe.exe
```

Tampilannya mirip Claude Code: banner, satu baris input, dan toolbar status koneksi di bawah.

- **Autocomplete**: ketik `/` atau beberapa huruf untuk memunculkan menu perintah. Tab melengkapi opsi
  (`--addr`, `--fc` …) dan nilainya (daftar COM port, baud, parity N/E/O, FC 1–4). Panah ↑ membuka riwayat.
- **Koneksi diingat**: setelah `connect` (wizard dengan menu panah) atau setelah `scan` menemukan device
  dan kamu jawab **Y**, perintah `read`, `find`, dan `dump` tidak perlu mengulang `--rtu/--baud/--parity/--id`.
  Port hanya dibuka selama perintah berjalan, jadi bisa dipakai tool lain di antara perintah.
- `scan-tcp` menawarkan host yang ditemukan. `sniff --auto` menawarkan baud/parity terbaik.
- Perintah tambahan: `connect`, `status`, `label ZR250`, `open` (buka folder sesi terakhir), `help`, `exit`/Ctrl+D.
  Alias: `scan` = `scan-rtu`, `find` = `find-value`.
- Ctrl+C menghentikan perintah yang sedang jalan (hasil tetap tersimpan), tanpa keluar dari mbprobe.

Contoh sesi:
```
› label ZR250
› sniff --auto              ← bus sepi?
› scan                      ← pilih port dari menu → DITEMUKAN 9600 N ID 1 → "Pakai sebagai koneksi? Y"
› read --addr 0 --count 20
› find --value 82826 --value 70335 --value 3.7 --to 2000
› dump --fc 4 --to 2000
› open
```
Semua perintah di bawah juga tetap bisa dijalankan langsung (non-interaktif) seperti biasa,
misalnya untuk script.

## Prosedur lapangan (genba)

> Sebelum mulai: foto layar controller (jam run, jam load, tekanan, suhu) **dengan jam yang terlihat**,
> supaya nilai bisa dicocokkan. Pakai `--label <unit>` di setiap command.

1. **`ports`**: colok adaptor, kenali COM-nya (FTDI 0403, CH340 1A86, CP210x 10C4).
   ```
   mbprobe ports
   ```
2. **`sniff`**: sambungkan A/B ke bus **tanpa mengirim apa pun**. Cek apakah bus sudah dipakai master lain
   (mis. modul OEM). Kalau ada master lain, **jangan polling** sebelum koordinasi.
   ```
   mbprobe sniff --port COM5 --auto --label ZR250          (≈75 s: 5 baud × 3 parity)
   mbprobe sniff --port COM5 --baud 9600 --parity N --duration 60 --label ZR250
   ```
   Hasilnya: kombinasi baud/parity yang valid, slave ID, dan register apa yang dibaca master lain.
   Register yang dibaca master OEM adalah petunjuk bagus untuk register map.
3. **`scan-rtu`** (bus sepi) **atau `scan-tcp`** (port Ethernet, mis. Mk5):
   ```
   mbprobe scan-rtu --port COM5 --label ZR250                          (9600/19200/38400 × N/E × ID 1-32)
   mbprobe scan-rtu --port COM5 --bauds 9600,19200,38400,57600,115200 --parity N,E,O --ids 1-247
   mbprobe scan-tcp --subnet 192.168.1.0/24 --label GA110
   mbprobe scan-tcp --host 192.168.1.50
   ```
   Exception response (mis. *illegal data address*) **juga dihitung ditemukan**, karena itu tetap
   bukti device hidup dan bicara Modbus. Untuk scan-tcp, set IP laptop satu subnet dengan controller dulu.
   Host yang membuka port 80/443 kemungkinan punya web server (coba buka di browser).
4. **`read` / `find-value`**: cocokkan dengan layar.
   ```
   mbprobe read --rtu COM5 --baud 9600 --parity N --id 1 --fc 3 --addr 0 --count 10
   mbprobe read --tcp 192.168.1.50 --unit 1 --fc 4 --addr 100 --count 20
   mbprobe find-value --rtu COM5 --baud 9600 --parity N --id 1 --value 82826 --value 70335 --value 3.7 --from 0 --to 2000
   ```
   `read` menampilkan tiap register sebagai uint16/int16/hex/÷10/÷100, dan tiap pasangan register
   sebagai uint32/int32/float32 dalam urutan **ABCD, CDAB, BADC, DCBA**.
   `find-value` mencoba 16-bit dan 32-bit (4 urutan) dengan skala ×1, ×0,1, ×0,01, ×0,001, ×10,
   jadi `--value 3.7` menemukan raw 37 maupun 370, dan juga float32 3,7.
   Untuk nilai yang terus berubah (tekanan, suhu), pakai `--tolerance 0.1`, lalu ulangi beberapa kali.
   Kandidat yang konsisten dengan layar adalah yang benar.
5. **`dump`**: petakan seluruh rentang. Blok yang exception dipecah sampai per register.
   ```
   mbprobe dump --rtu COM5 --baud 9600 --parity N --id 1 --fc 3 --from 0 --to 2000 --block 50
   mbprobe dump --tcp 192.168.1.50 --unit 1 --fc 4 --from 0 --to 2000
   ```
   Lakukan untuk FC03 **dan** FC04. Simpan dump saat unit *load* dan *unload* untuk dibandingkan.
6. **`poll`**: tulis register yang sudah teridentifikasi ke YAML, lalu log berkala.
   ```
   mbprobe poll --config examples/unit_ga110.yaml --interval 5 --duration 3600
   ```

### Kalau tidak ada response

| Gejala | Kemungkinan |
|---|---|
| `TIMEOUT` di semua kombinasi | A/B terbalik (coba tukar), port controller belum diaktifkan sebagai Modbus slave, salah port (2X2 vs lainnya), kabel/terminasi |
| `CRC_ERROR` / "byte diterima tapi CRC tidak valid" | Ada device, tapi baud/parity salah. Bisa juga noise: cek GND, shield, terminasi 120 Ω |
| Sniff: "ada lalu lintas non-Modbus" di semua kombinasi | Protokol proprietary (bukan Modbus RTU), atau format 7-bit/2 stop bit (coba `--stopbits 2`) |
| `EXCEPTION 02` | Device **hidup**, alamat saja yang tidak valid. Lanjut `dump` |
| `NONSTANDARD` (mis. frame `01 09 02`) | Device **hidup**, tapi menolak alamat/FC itu dengan frame non-baku (umum di sensor murah). Lanjut `dump --fc 3` dan `dump --fc 4` untuk mencari alamat yang valid |
| "balasan datang setelah timeout" / `LATE` | Device hidup tapi **lambat**. Naikkan `--timeout` (mis. 2–3 s). Contoh: sensor SHT20/MD02 butuh ±600 ms, dan ±1,1 s kalau request beruntun |
| "Tidak ada SATU byte pun … di semua kombinasi" | Hampir pasti fisik: A/B, daya, terminal longgar, atau port dipegang program lain (Node-RED dll.). Kalau wiring yakin benar: `--timeout 2`, `--addr 1` |
| `EXCEPTION 01` | FC tidak didukung. Coba FC03 ↔ FC04 |
| TCP: port 502 tertutup | Modbus TCP belum aktif di controller. Cek menu/web server controller |
| "Adaptor memantulkan byte (echo)" | Normal untuk beberapa adaptor. Sudah otomatis diabaikan |

## Output

Setiap command (kecuali `ports`) membuat folder `sessions/YYYYMMDD_HHMMSS_<label>/`:

| File | Isi |
|---|---|
| `log.txt` | Semua TX/RX hex + timestamp ms + status (ok / exception / timeout / crc_error / invalid) |
| `*.csv` | `scan_rtu.csv`, `scan_tcp.csv`, `read_16.csv`, `read_32.csv`, `dump.csv`, `matches.csv`, `poll.csv`, `sniff_frames.csv`, `sniff_auto.csv` |
| `summary.json` | Ringkasan hasil (mudah dibaca script lain) |

CSV ditulis dan di-flush **per baris**, jadi kalau Ctrl+C atau kabel USB tercabut, hasil sementara
tetap tersimpan dan `summary.json` tetap dibuat. Opsi `--out <folder>` mengganti folder induk `sessions`.

## Config YAML (`poll`)

Lihat `examples/unit_ga110.yaml`. Field register: `name`, `fc` (1–4), `addr`, `type`
(`uint16`/`int16`/`uint32`/`int32`/`float32`), `word_order` (ABCD/CDAB/BADC/DCBA), `scale`, `offset`, `unit`.
Register berdekatan dengan FC sama otomatis digabung jadi satu request. Kalau blok gabungan kena
exception, mbprobe otomatis kembali ke pembacaan per register. Format ini sengaja netral supaya
bisa dipakai ulang untuk gateway ThingsBoard/MQTT di fase berikutnya.

## Semua command

```
mbprobe ports
mbprobe sniff      --port COM5 [--baud 9600 --parity N | --auto [--dwell 5]] [--duration 60] [--gap-ms N] [-q]
mbprobe scan-rtu   --port COM5 [--bauds 9600,19200,38400] [--parity N,E] [--ids 1-32] [--timeout 1.0] [--addr 0] [--delay 0.1] [--stop-on-first]
mbprobe scan-tcp   (--subnet 192.168.1.0/24 | --host IP) [--ports 502,80,443] [--unit-ids 0,1,255] [--modbus-port 502]
mbprobe read       (--rtu COM5 --baud --parity --id | --tcp IP [--tcp-port 502] --unit) --fc 3 --addr 0 --count 10
mbprobe dump       (--rtu … | --tcp …) --fc 3 --from 0 --to 2000 [--block 50] [--delay 0.1]
mbprobe find-value (--rtu … | --tcp …) --value 82826 [--value 3.7 …] [--tolerance 0] --from 0 --to 2000
mbprobe poll       --config unit.yaml [--interval 5] [--duration 3600] [--port COM6]
```
Opsi bersama: `--label`, `--out`, `--timeout` (default RTU 2 s untuk read/dump/find/poll, 1 s per percobaan
untuk scan), `--stopbits`. `--id` dan `--unit` adalah alias.
`mbprobe <command> --help` untuk detail.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

- `tests/test_protocol.py`, `tests/test_decode.py`: CRC, frame RTU (termasuk beberapa frame dalam satu
  chunk dan sampah), interpretasi tipe dan 4 urutan word, find-value
- `tests/test_readonly.py`: **bukti tidak ada FC tulis di codebase**
- `tests/test_acceptance.py`: end-to-end CLI vs simulator (Linux/macOS, otomatis di-skip di Windows):
  `scan-rtu` menemukan device tersembunyi 19200 E ID 7, `find-value 82826` menemukan alamat 300 CDAB,
  `dump` memetakan 90–99 ok / 100–119 exception / 120–130 ok, `sniff --auto` mendeteksi frame dari
  client lain yang sedang mem-poll, echo adaptor, Ctrl+C, port tercabut, dan TCP (scan/read/find-value/dump)

### Simulator

`sim/sim_server.py` (pymodbus) berisi peta register uji:

| FC | Alamat | Isi |
|---|---|---|
| 03 | 0–99 | 1000..1099 |
| 03 | 100–119 | **exception 02** |
| 03 | 120 | 370 (tekanan 3,70 bar, int16 ×0,01); 121 = 42; 122 = −2 |
| 03 | 200–299 | **exception 02** |
| 03 | 300–301 | 82826 uint32 **CDAB** (jam run) |
| 03 | 302–303 | 70335 uint32 CDAB (jam load) |
| 03 | 310–311 | 82,5 float32 ABCD (suhu) |
| 04 | 0–49 | 2000..2049 |
| 01/02 | 0–15 | bit pola |

**Linux/macOS:** `sim/virtual_bus.py` membuat bus RS485 virtual (pty) dengan N endpoint. Bus ini juga
meniru **baud/parity yang tidak cocok** (byte dirusak) dan **echo adaptor** (`--echo i`):
```bash
python sim/virtual_bus.py --endpoints 3            # mencetak /dev/ttysX untuk endpoint 0,1,2
python sim/sim_server.py rtu --port <endpoint0> --baud 19200 --parity E --id 7
python -m mbprobe scan-rtu --port <endpoint1> --ids 1-10
python -m mbprobe poll -c examples/unit_sim.yaml --port <endpoint2> --interval 1 &   # "master lain"
python -m mbprobe sniff --port <endpoint1> --auto --dwell 2
```
(socat juga bisa untuk pasangan sederhana: `socat -d -d pty,raw,echo=0 pty,raw,echo=0`, tapi tidak meniru salah baud.)

**Windows (com0com):** buat pasangan port, mis. `COM10 <-> COM11` (Setup com0com → *Add pair*), lalu:
```
python sim\sim_server.py rtu --port COM10 --baud 19200 --parity E --id 7
mbprobe.exe scan-rtu --port COM11 --bauds 9600,19200 --parity N,E --ids 1-10
mbprobe.exe find-value --rtu COM11 --baud 19200 --parity E --id 7 --value 82826 --from 0 --to 400
```
com0com tidak meniru salah baud/parity (device akan "terlihat" di semua baud), jadi validasi
baud/parity yang sebenarnya dilakukan di acceptance test Linux/macOS dan di uji hardware.

**TCP:** `python sim/sim_server.py tcp --port 5020`, lalu `mbprobe read --tcp 127.0.0.1 --tcp-port 5020 --unit 1 --addr 300 --count 4`.

### Uji hardware (wajib sebelum genba)

**Hasil 2026-10-03**: adaptor CH340 (1A86:7523) + sensor suhu/kelembapan RS485 SHT20/MD02 di macOS:
`scan` menemukan ID 1 @ 9600 N (respon non-standar), `dump --fc 4` memetakan alamat 0–2 valid,
`poll -c examples/sensor_sht20.yaml` membaca 32,7 °C / 58,5 %RH tanpa error. Temuan dari uji ini:
device lambat (±0,6–1,1 s) dan frame error non-standar — keduanya sekarang ditangani dan ada test-nya.
Sisa: uji di laptop Windows.


Dengan adaptor USB-RS485 nyata ke device Modbus di kantor (power meter / PLC / VFD):
1. `ports` → adaptor terdeteksi
2. `sniff --auto` dengan device diam → "bus sepi"
3. `scan-rtu` → baud/parity/ID cocok dengan setting device
4. `read` + `find-value` nilai yang tampil di layar device
5. `dump` → CSV peta alamat
6. `poll` 10 menit → CSV berisi nilai
7. Cabut USB saat `dump` berjalan → pesan jelas, file tetap tersimpan
8. Dengan 2 adaptor: PC lain/Modbus Poll mem-poll device, mbprobe `sniff` → frame terdeteksi

## Catatan & batasan

- Scan dengan baud/parity yang salah mengirim byte yang di sisi device terbaca sebagai sampah. Device
  Modbus membuang frame dengan CRC salah. Peluang sampah kebetulan lolos CRC sekitar 1:65536 per frame,
  dan tetap harus kebetulan membentuk perintah valid. Kalau ingin sangat konservatif, persempit
  `--bauds`/`--parity` sesuai info manual atau hasil `sniff`.
- `sniff` memakai jeda antar byte + struktur frame + CRC. Latency adaptor USB (FTDI ±16 ms) bisa
  menggabungkan beberapa frame dalam satu chunk. Itu ditangani oleh parser, tapi frame FC selain 01–04
  hanya dikenali kalau ada jeda di antaranya.
- Jangan jalankan mbprobe bersamaan dengan program lain yang memakai port yang sama (Node-RED, Modbus Poll).
  Di macOS, `/dev/cu.*` akan ditolak ("Resource busy", mbprobe menyebut nama prosesnya), tapi `/dev/tty.*`
  bisa terbuka bersamaan dan balasan device jadi rebutan.
- Protokol proprietary Atlas Copco / CAN **tidak** didekode. `sniff` hanya melaporkan bahwa ada
  lalu lintas non-Modbus dan menyimpan hex mentah di `summary.json` / `log.txt`.
- Di luar scope: GUI, fungsi tulis/kontrol, integrasi dashboard.
