# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/), versi mengikuti [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-12

### Ditambahkan
- Pemeriksaan SSL (penerbit, kedaluwarsa), umur domain (WHOIS), tanda mencurigakan pada URL, dan VirusTotal.
- Penilaian AMAN, CURIGA, BAHAYA dari skor gabungan.
- Keluaran `--json` dan `--version`.
- Kode keluar: 0 AMAN, 1 CURIGA, 2 BAHAYA, 64 salah pakai atau URL tidak valid.
- File konfigurasi TOML (`--config`): bobot, ambang, batas, daftar merek, dengan validasi ketat.
- Cache hasil VirusTotal di `~/.cache/url-checker/` (kunci hash SHA-256, izin 600, umur 6 jam), dan penanganan 429.
- Test tanpa internet dan CI GitHub Actions (Python 3.11 dan 3.13).

### Diperbaiki
- Kunci VirusTotal dibaca dari `.env` di folder kerja, sehingga alat yang dipasang dengan `uv tool install` menemukannya.
- Catatan "domain sangat baru" mengikuti `domain_new_days` dari konfigurasi.
