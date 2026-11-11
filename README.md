# url-checker

Alat baris perintah yang mengumpulkan beberapa sinyal keamanan tentang sebuah URL dan memberi penilaian sederhana: AMAN, CURIGA, atau BAHAYA.

Alat ini **bukan** pengganti perlindungan peramban atau antivirus. AMAN berarti "tidak ada sinyal buruk yang terdeteksi", bukan "situs ini aman". Lihat bagian Keterbatasan.

## Yang diperiksa

| Pemeriksaan | Sumber | Isi |
|---|---|---|
| SSL | koneksi langsung ke port 443 | penerbit, tanggal kedaluwarsa, sisa hari |
| Umur domain | WHOIS | tanggal pembuatan, umur dalam hari |
| Tanda mencurigakan | analisis URL lokal | `@` di URL, subdomain terlalu banyak, tanda `-` berlebihan, memuat atau mirip nama merek tapi bukan domain resminya |
| VirusTotal | API VirusTotal v3 | jumlah mesin yang menandai URL sebagai berbahaya atau mencurigakan |

Semua sinyal digabung menjadi satu skor. Bobot, ambang, dan daftar merek bisa diubah lewat file konfigurasi.

## Pemasangan

Butuh Python 3.11 atau lebih baru dan [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/diablock13-sec/url-checker.git
cd url-checker
uv tool install --from . url-checker
```

Cek: `url-checker --version`

## Kunci VirusTotal

Daftar akun gratis di VirusTotal dan ambil API key. Simpan di file `.env` pada **folder tempat kamu menjalankan perintah**:

```
VT_API_KEY=isi_kuncimu_di_sini
```

Jangan commit `.env`. Tanpa kunci, bagian VirusTotal melaporkan error dan pemeriksaan lain tetap jalan.

Tier gratis VirusTotal dibatasi 4 request per menit dan 500 per hari, dan ditujukan untuk pemakaian non-komersial. Periksa syarat layanan terbaru sebelum memakainya di luar itu.

## Pemakaian

```bash
url-checker example.com
url-checker https://contoh.com/halaman
url-checker --json example.com
url-checker --config konfigurasiku.toml example.com
```

Contoh keluaran teks (dipotong):

```
[SSL]
ok         : True
issuer     : SSL Corporation
expires    : 2026-12-25
days_left  : 44

[UMUR DOMAIN]
ok         : True
domain     : example.com
created    : 1995-08-14
age_days   : 11412

[TANDA MENCURIGAKAN]
tidak ada tanda mencurigakan

[VIRUSTOTAL]
ok         : True
malicious  : 0
suspicious : 0
harmless   : 63
undetected : 30

[PENILAIAN]
hasil      : AMAN (skor 0)
catatan    : AMAN bukan jaminan, ini hanya sinyal sederhana
```

Dengan `--json`, keluaran memuat kunci `url`, `ssl`, `domain_age`, `flags`, `virustotal`, `verdict`, `score`, `reasons`, dan `note`.

### Kode keluar

Berguna untuk skrip:

| Kode | Arti |
|---|---|
| 0 | AMAN |
| 1 | CURIGA |
| 2 | BAHAYA |
| 64 | salah pakai atau URL tidak valid |

## Konfigurasi

File bawaan ada di `src/url_checker/config.toml` dan ikut terpasang bersama paket. Untuk mengubahnya, salin file itu, edit salinannya, lalu jalankan dengan `--config`. File harus lengkap: kunci yang hilang atau tidak dikenal ditolak.

Nilai bawaan yang penting:

- Skor 2 atau lebih = CURIGA, skor 5 atau lebih = BAHAYA.
- Tiap sinyal punya bobot di bagian `[weights]`, misalnya `domain_new = 3` dan `flag = 2`.
- Batas sinyal ada di `[limits]`, misalnya domain dianggap baru di bawah `domain_new_days = 30` hari.
- Daftar merek ada di `[brands]`: nama merek dan domain resminya. Bawaannya hanya delapan merek. Tambahkan merek yang kamu butuhkan.

## Cache dan batas VirusTotal

- Hasil VirusTotal yang berhasil disimpan di `~/.cache/url-checker/` selama 6 jam, maksimal 500 entri, dengan izin file 600.
- Kunci cache adalah hash SHA-256 dari URL. URL mentah tidak disimpan.
- Hasil gagal tidak disimpan.
- Kalau VirusTotal membalas 429, alat menunggu sesuai `Retry-After` (dibatasi 1 sampai 30 detik) dan mencoba sekali lagi. Kalau masih 429, bagian VirusTotal dilaporkan `rate_limited` dan analisis lain tetap selesai.
- Untuk URL yang belum pernah discan, alat mengirimnya ke VirusTotal lalu menunggu hasil sampai sekitar 20 detik. Kalau belum selesai, hasilnya "coba lagi nanti".

## Privasi

- **URL yang kamu periksa dikirim ke VirusTotal.** Kalau URL belum pernah discan, URL itu dikirim untuk discan dan bisa tercatat di sana. Jangan periksa URL yang memuat token, sesi, tautan reset password, data pribadi di query string, atau `user:password@` di depan host.
- Pemeriksaan SSL membuka koneksi langsung dari komputermu ke host yang diperiksa.
- Pemeriksaan WHOIS mengirim nama domain ke server WHOIS.

## Keterbatasan

- **AMAN bukan jaminan.** Situs phishing sering punya SSL valid, dan domain lama bisa saja diretas. Sinyal di sini sederhana dan mudah dilewati.
- **Situs baru atau belum dikenal tampak bersih.** Kalau belum ada mesin VirusTotal yang menandainya, hasilnya tetap AMAN, selama sinyal lain tidak memicu.
- **SSL memakai port dari URL, bawaannya 443.** Alat tidak mengecek pencabutan sertifikat. Kegagalan koneksi (timeout, host mati) dilaporkan sebagai SSL gagal, dan itu bisa berarti situsnya sekadar tidak bisa dijangkau.
- **WHOIS tidak selalu lengkap.** Sebagian domain menyembunyikan tanggal pembuatan atau server WHOIS membatasi permintaan. Pada kasus itu umur domain tidak dinilai, dan hasilnya tidak berarti domain tersebut aman.
- **Deteksi merek terbatas.** Hanya merek di daftar `[brands]` yang dicek, dan kemiripan nama memakai ambang sederhana (`brand_similarity`). Serangan yang memakai huruf mirip dari alfabet lain (homograf) tidak ditangani secara khusus.
- **Bobot skor adalah tebakan yang masuk akal, bukan hasil pengukuran.** Belum ada pengukuran false positive dan false negative pada data berlabel.
- Satu URL diperiksa per perintah. Belum ada mode massal.

## Perbandingan dengan Google Safe Browsing

Google Safe Browsing adalah daftar URL berbahaya yang dikelola Google dan dipakai peramban seperti Chrome. Alat ini tidak memakainya.

- **Cakupan data:** Safe Browsing dan VirusTotal memiliki data ancaman yang jauh lebih luas daripada yang bisa dikumpulkan alat sederhana ini. url-checker sendiri hanya menambahkan beberapa sinyal lokal di atas hasil VirusTotal.
- **Perlindungan nyata:** untuk melindungi diri saat berselancar, andalkan perlindungan bawaan peramban dan antivirus, yang aktif otomatis dan diperbarui terus-menerus. url-checker tidak menggantikan itu.
- **Kapan alat ini berguna:** untuk melihat sinyal mentah (umur domain, SSL, tanda dalam URL) dalam satu perintah, untuk skrip lewat kode keluar dan `--json`, atau untuk belajar bagaimana sinyal digabung menjadi penilaian.
- **Kapan sebaiknya tidak dipakai:** sebagai satu-satunya dasar keputusan keamanan, untuk memeriksa URL yang sensitif, atau untuk volume besar (batas VirusTotal gratis cepat habis).

Detail kebijakan dan batas Safe Browsing berubah dari waktu ke waktu. Baca dokumentasi resminya sebelum membandingkan atau memakainya.

## Pengembangan

```bash
uv run pytest -q
uv run ruff check .
```

Semua test berjalan tanpa internet (koneksi sungguhan sengaja digagalkan di `tests/conftest.py`). CI menjalankan `ruff` dan `pytest` di Python 3.11 dan 3.13.
