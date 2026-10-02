"""Pesan petunjuk lapangan yang dipakai bersama oleh CLI dan GUI."""

HINT_TIMEOUT_RTU = ("Tidak ada response. Cek polaritas A/B (coba tukar), terminasi 120 Ω, GND, "
                    "atau coba baud/parity/ID lain (jalankan scan-rtu).")
HINT_CRC = ("Response rusak (CRC/format salah). Biasanya baud/parity tidak cocok, atau noise/wiring: "
            "cek GND, shield, dan terminasi.")
HINT_TIMEOUT_TCP = ("Tidak ada response Modbus. Coba unit ID lain (0, 1, 255) atau FC lain; "
                    "pastikan Modbus TCP aktif di controller.")
HINT_PORT_TCP = ("Gagal konek. Cek IP & kabel LAN, IP laptop satu subnet, dan port 502 terbuka "
                 "(jalankan scan-tcp --host).")
