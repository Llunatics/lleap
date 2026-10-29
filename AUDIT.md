# Audit — lleap

Audit Kamis 2026-10-29 (repo build Rabu 2026-10-28, v1.0.0 → v1.0.1).
Satu ronde: suite + review kode + probe adversarial (target tiruan untuk
semua kode redirect 301/302/303/307/308, target IPv6, argumen CLI ekstrem,
dan JSON tiruan). Tidak ada temuan keamanan pada lab: lab tetap mengikat
127.0.0.1 saja, dan payload katalog tidak menunjuk host pihak ketiga
nyata.

## Temuan yang diperbaiki (8)

1. **Target loopback IPv6 ditolak.** `check_target_safety` memakai
   `gethostbyname`, yang tidak bisa me-resolve `::1` — target
   `http://[::1]:...` selalu gagal dengan "cannot resolve" padahal itu
   loopback. Sekarang: IP literal (v4/v6) di-parse langsung, hostname
   di-resolve dengan `getaddrinfo` (kedua family), dan *semua* alamat
   hasil resolve harus lokal — sebelumnya hanya jawaban IPv4 pertama
   yang dinilai, jadi hostname dengan jawaban campuran publik/privat
   lolos dari satu alamat saja. Sekarang jawaban campuran ditolak
   tanpa `--allow-public-target`.
2. **Open redirect lolos karena kapitalisasi host.** Perbandingan host
   redirect case-sensitive: `Location: https://EVIL.EXAMPLE.COM/` dan
   `evil.example.com.` (trailing dot) diklasifikasikan UNCLEAR, padahal
   DNS tidak peduli kapitalisasi maupun titik akhir. `_loose_host`
   sekarang me-lowercase dan memangkas trailing dot; pencocokan echo
   host di body juga case-insensitive.
3. **JSON lab bisa dipalsukan target sembarang.** Cabang lab di
   `classify` mempercayai *setiap* body JSON yang punya field
   `fetched_status` — API JSON apa pun yang mengembalikan field itu
   akan mendapat verdict FETCHED dengan bukti "lab reports…".
   Sekarang lab menyertakan marker `"lleap_lab": true` di semua
   respons fetch, dan classifier hanya memakai cabang lab bila marker
   itu ada; tanpa marker, JSON tersebut jatuh ke klasifikasi biasa
   (terverifikasi: spoof `{"fetched_status": 200}` → UNCLEAR).
4. **`lleap lab --port` di luar rentang men-traceback.**
   `--port 70000` / `-1` menghasilkan traceback `OverflowError`.
   Sekarang validasi rentang 0–65535 di muka plus `OSError` saat bind
   gagal (mis. port sudah dipakai) → pesan bersih, exit code 2.
5. **`--json` ke path tak bisa ditulis men-traceback.**
   Scan penuh jalan dulu, baru `FileNotFoundError` traceback setelah
   tabel tercetak. Sekarang `OSError` saat menulis ditangkap →
   pesan bersih, exit code 2.
6. **`--sets ""` diam-diam memindai semua grup.** String kosong
   jatuh ke "default: all" tanpa peringatan — kemungkinan typo yang
   mengubah cakupan scan. Sekarang error bersih exit 2, berlaku sama
   untuk `scan` dan `list-payloads`.
7. **`--timeout` negatif menghasilkan scan "bersih" palsu.**
   Timeout −5 membuat semua payload ERROR ("Timeout value out of
   range") tapi exit code tetap 0 — tak bisa dibedakan dari target
   bersih. Sekarang `--timeout <= 0` dan `--delay < 0` divalidasi di
   muka → error bersih exit 2 (pesan `--delay` negatif sebelumnya
   hanya "sleep length must be non-negative" setelah request pertama).
8. **Bukti redirect tidak di-sanitasi.** String bukti
   "client redirected to …" memakai host dari header `Location`
   server mentah; dengan katalog payload tetap tidak terjangkau,
   tapi sekarang di-`term_safe` sebagai pertahanan berlapis, konsisten
   dengan bukti lab dan ERROR yang sudah di-sanitasi.

## Terverifikasi aman / bukan bug

- Semua kode redirect 301/302/303/307/308 ditangkap tanpa di-follow
  (probe server tiruan: 5/5 OPEN-REDIRECT).
- `/%2fevil.example.com/` tetap UNCLEAR — benar, karena itu path
  relatif same-origin, bukan host eksternal.
- Redirect ke host yang sama, payload `javascript:`/`data:` yang
  direfleksikan, dan marker metadata tetap terklasifikasi benar.
- Terminal injection via `Location` ber-ESC tidak terjangkau: host
  hasil unquote yang mengandung ESC tidak akan sama dengan host
  payload katalog, jadi verdict jatuh ke UNCLEAR (temuan 8 tetap
  diperbaiki sebagai pertahanan berlapis).
- `--delay` negatif sudah exit 2 sebelum audit; hanya pesannya yang
  diperjelas lewat validasi di muka (temuan 7).

## Uji

- Suite: 21 → 28 tes, semua hijau (termasuk 7 tes regresi baru:
  marker lab, kapitalisasi/trailing-dot redirect, echo host
  case-insensitive, safety IPv6 loopback & publik, `--sets` kosong,
  `--port` di luar rentang).
- `lleap demo` end-to-end: FETCHED=2, OPEN-REDIRECT=6, UNCLEAR=32,
  canary hit 1/1 — sama seperti sebelum perbaikan (tanpa regresi).
- CLI: `--port 70000`, `--json` ke direktori tak ada, `--timeout -5`,
  `--sets ""` → semua pesan bersih, exit 2, tanpa traceback.
- Target `[::1]` kini lolos safety check dan berjalan normal.

## Verdict

v1.0.1 solid sebagai tester SSRF/open-redirect untuk aplikasi sendiri
dan lab: klasifikasi redirect kini benar untuk variasi host DNS yang
wajar, safety check target mencakup IPv6 dan jawaban DNS campuran,
dan semua jalur error CLI menghasilkan pesan bersih. Batasan jujur
yang tetap berlaku: verdict FETCHED/UNCLEAR adalah grade bukti, bukan
bukti eksploitasi (README sudah menyatakannya); deteksi echo host di
body masih heuristik substring dan bisa false positive pada halaman
yang menyebut "localhost" secara generik.

