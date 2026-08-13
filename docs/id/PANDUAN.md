# Panduan Lengkap (Bahasa Indonesia)

> Dokumen ini adalah versi lengkap berbahasa Indonesia.
> Ringkasan berbahasa Inggris ada di [README](../../README.md);
> instalasi di [docs/INSTALL.md](../INSTALL.md); penggunaan di [docs/USAGE.md](../USAGE.md).

---

Jembatan **FortiSOAR → database → FortiGate External Resource**. Berjalan native di
Linux sebagai unit `systemd`. Tidak ada Docker, tidak ada container runtime.

```
FortiSOAR ──POST /api/v1/ingest (Bearer)──▶ ┌────────────────────────┐
                                            │ uvicorn + FastAPI      │
Operator SOC ──HTTPS──▶ Dashboard ─────────▶│ SQLite (WAL)           │
                                            │ pruner TTL (asyncio)   │
FortiGate ──GET /api/v1/feed/fortigate─────▶└────────────────────────┘
```

---

## 1. Tech stack & alasannya

| Lapisan | Pilihan | Alasan |
|---|---|---|
| Runtime | Python 3.10+ / uvicorn (uvloop + httptools) | Satu proses, ~60 MB RSS, cold start < 1 detik |
| Framework | FastAPI | Validasi Pydantic + OpenAPI otomatis di `/api/docs` |
| Database | SQLite mode WAL | Feed IP adalah beban baca-berat/tulis-ringan; nol daemon tambahan, backup = salin satu file |
| Frontend | HTML/CSS/JS satu berkas | Tanpa CDN — tetap berfungsi di SOC yang terisolasi dari internet |
| Proses | systemd + `Type=exec` | Restart otomatis, journald, sandbox kernel |
| TLS | nginx di depan uvicorn | Terminasi TLS, rate limit, allow-list per lokasi |

**Kapan pindah ke PostgreSQL:** SQLite nyaman sampai sekitar 1 juta indikator dengan satu
penulis. Pindah jika Anda butuh >1 worker uvicorn, replikasi, atau beberapa node di
belakang load balancer. Ganti `app/database.py` ke `psycopg` dan ubah `ON CONFLICT … RETURNING`
(sintaksnya identik di PostgreSQL) — sisa kode tidak berubah.

---

## 2. Instalasi

Salin folder project ke VM target, lalu jalankan satu perintah:

```bash
scp -r threatfeed/ user@10.10.10.30:/tmp/          # dari laptop
ssh user@10.10.10.30
cd /tmp/threatfeed && sudo bash deploy/setup.sh
```

Wizard menanyakan lima hal (domain, IP FortiSOAR, IP FortiGate, TTL, mode TLS), lalu
mengerjakan sisanya sendiri: paket sistem → service account `threatfeed` (nologin) →
virtualenv → database → kredensial acak → unit systemd → nginx + TLS → aturan ufw →
uji fungsional → perintah `threatfeedctl`. Di akhir tercetak password dashboard, kedua
token, dan blok `config system external-resource` yang tinggal ditempel ke FortiGate.
Semua itu juga tersimpan di `/etc/threatfeed/INSTALL-SUMMARY.txt`.

**Tanpa interaksi** (untuk Ansible atau instalasi berulang):

```bash
sudo bash deploy/setup.sh --yes \
  --domain feed.networklabs.id \
  --soar-ip 10.10.10.20 \
  --fgt-ip 10.10.10.0/24 \
  --ttl 30 \
  --tls existing \
  --cert /etc/ssl/certs/feed-fullchain.pem \
  --key  /etc/ssl/private/feed.key
```

| Flag | Fungsi |
|---|---|
| `--tls self-signed` | nginx + sertifikat buatan sendiri (lab; FortiGate perlu `server-identity-check none`) |
| `--tls existing --cert … --key …` | nginx + sertifikat Anda, mis. terbitan Networklabs-Root-CA |
| `--tls none` / `--no-nginx` | uvicorn saja di `127.0.0.1`, tanpa nginx |
| `--comments` / `--no-comments` | Sertakan komentar di feed FortiGate (default: tidak) |
| `--comment-format plain\|short\|full` | Isi komentar (default: `plain`) |
| `--port 8080` | Port internal uvicorn |
| `--upgrade` | Perbarui kode saja; kredensial dan database dipertahankan, versi lama dicadangkan |
| `--uninstall` | Copot bersih (database dipertahankan kecuali Anda menyetujui penghapusan) |

Jika instalasi baru gagal di tengah jalan, skrip mengembalikan perubahan sendiri:
service dihentikan, unit dan `/opt/threatfeed` dihapus, sedangkan `/etc/threatfeed`
dan `/var/lib/threatfeed` tidak disentuh.

**Manual, jika Anda ingin mengendalikan setiap langkah** (`deploy/install.sh` adalah
versi minimal dari alur yang sama):

```bash
sudo useradd --system --home-dir /var/lib/threatfeed --shell /usr/sbin/nologin threatfeed
sudo install -d -o threatfeed -g threatfeed -m 750 /opt/threatfeed /var/lib/threatfeed
sudo install -d -o root -g threatfeed -m 750 /etc/threatfeed

sudo cp -r app static requirements.txt /opt/threatfeed/
sudo python3 -m venv /opt/threatfeed/.venv
sudo /opt/threatfeed/.venv/bin/pip install -r /opt/threatfeed/requirements.txt
sudo chown -R threatfeed:threatfeed /opt/threatfeed

sudo cp deploy/threatfeed.env.example /etc/threatfeed/threatfeed.env
sudo chmod 640 /etc/threatfeed/threatfeed.env
sudo chown root:threatfeed /etc/threatfeed/threatfeed.env
sudo nano /etc/threatfeed/threatfeed.env      # isi semua nilai GANTI_*

sudo cp deploy/threatfeed.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threatfeed
```

### Perintah operasional — `threatfeedctl`

Dipasang otomatis oleh `setup.sh` ke `/usr/local/bin/`.

```bash
threatfeedctl status              # service + database + jumlah entri feed + aktivitas terakhir
threatfeedctl creds               # URL, password dashboard, kedua token
threatfeedctl logs 100            # atau: threatfeedctl logs -f
threatfeedctl test 103.74.20.57   # push satu IoC uji lewat jalur yang sama dengan FortiSOAR
threatfeedctl feed 25             # intip persis apa yang dilihat FortiGate
threatfeedctl stats               # rekap per severity / TLP / sumber
threatfeedctl search C2           # cari indikator di database
threatfeedctl audit 20            # jejak audit terakhir
threatfeedctl expire 1.2.3.4      # cabut satu IP dari feed
threatfeedctl prune               # jalankan pruning TTL sekarang
threatfeedctl backup              # backup aman saat service hidup (14 salinan terakhir disimpan)
threatfeedctl restore <file>      # pulihkan dari backup
threatfeedctl config              # edit .env lalu restart
threatfeedctl rotate ingest       # ganti token tanpa downtime (lihat di bawah)
threatfeedctl doctor              # periksa 10 titik kegagalan tersering
```

Rotasi token berlangsung dua tahap agar tidak ada jeda layanan:

```bash
sudo threatfeedctl rotate ingest             # token baru + lama berlaku bersamaan
# … pindahkan konfigurasi FortiSOAR ke token baru …
sudo threatfeedctl rotate ingest --finish    # cabut token lama
```

Perintah systemd mentah tetap berlaku:

```bash
systemctl status threatfeed
journalctl -u threatfeed --since "1 hour ago" | grep feed_pull
systemctl restart threatfeed                   # wajib setelah mengubah .env
systemd-analyze security threatfeed            # verifikasi hardening
```

### Backup

`threatfeedctl backup` memakai perintah `.backup` bawaan SQLite, yang aman dijalankan
saat service hidup. `cp` biasa **tidak** aman: berkas `-wal` bisa tertinggal dan salinan
yang dihasilkan kehilangan transaksi terakhir. Untuk backup terjadwal:

```bash
sudo tee /etc/cron.d/threatfeed-backup <<'EOF'
0 2 * * * root /usr/local/bin/threatfeedctl backup >/dev/null 2>&1
EOF
```

---

## 3. Konfigurasi FortiSOAR (ingestion)

Endpoint: `POST https://threatfeed.networklabs.id/api/v1/ingest`
Header: `Authorization: Bearer <TF_INGEST_TOKENS>`, `Content-Type: application/json`

Parser menerima **enam** bentuk payload — Anda tidak perlu menyeragamkan playbook:

```jsonc
// 1. Rich payload FortiSOAR (bentuk utama)
{"commands":[{"name":"FortiSOAR_Threat_Feeds-IP-01","command":"add","entries":[
  {"ip":"103.74.20.57","type":"Malware","severity":"Malicious","confidence":100,
   "tlp":"TLP:RED","source":"FortiSOAR Playbook","comment":"C2 Server detected"}]}]}

// 2. Single command tanpa pembungkus "commands"
{"name":"feed-01","command":"add","entries":[{"ip":"1.2.3.4"}]}

// 3. Array of strings
{"entries":["103.74.20.57","45.155.205.233"]}

// 4. Array telanjang
["103.74.20.57","45.155.205.233"]

// 5. Campuran object + string dalam satu array
{"entries":["1.2.3.4",{"ip":"5.6.7.8","severity":"High"}]}

// 6. Object tunggal
{"ip":"103.74.20.57","severity":"Malicious"}
```

Field IP dikenali dari salah satu kunci: `ip`, `ip_address`, `value`, `indicator`,
`address`, `src_ip`, `dst_ip` — sehingga output modul TAXII FortiSOAR (yang menaruh IP
di `value`) langsung diterima.

**Command yang didukung**

| `command` | Efek |
|---|---|
| `add` / `update` | Upsert. IP baru → INSERT; IP lama → UPDATE `severity`, `confidence`, `tlp`, `comment`, `updated_at`, `hit_count++` |
| `delete` / `remove` | Set `status='revoked'` — langsung hilang dari feed, riwayat tetap tersimpan |
| `replace` / `sync` | Rekonsiliasi penuh: entri yang dikirim di-upsert, sisa isi feed itu dicabut |

**Normalisasi otomatis:** `"40%"` → `40` · `tlp:green` → `TLP:GREEN` · `TLP:CLEAR` → `TLP:WHITE` ·
`critical` → `Critical` · `1.2.3.4/32` → `1.2.3.4` · `10.0.0.1-10.0.0.9` dipertahankan sebagai
range · loopback/multicast/unspecified ditolak · CR/LF pada komentar dipangkas (mencegah
injeksi baris ke berkas feed).

**Respons** (HTTP 200, `status` = `ok` atau `partial`):

```json
{"status":"partial","received":5,"inserted":2,"updated":1,"deduplicated":1,
 "revoked":0,"rejected":1,"errors":[{"entry":"999.1.1.1","error":"…"}],
 "processed_at":"2026-08-10T13:12:49Z"}
```

Entri buruk tidak menggagalkan seluruh batch — playbook FortiSOAR tetap sukses, dan
`errors` memberi tahu baris mana yang perlu diperbaiki.

**Uji cepat:**

```bash
curl -sS -X POST https://threatfeed.networklabs.id/api/v1/ingest \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"commands":[{"name":"test","command":"add","entries":[
       {"ip":"103.74.20.57","type":"Malware","severity":"Malicious",
        "confidence":100,"tlp":"TLP:RED","comment":"C2"}]}]}' | jq
```

---

## 4. Konfigurasi FortiGate (konsumsi feed)

```
config system external-resource
    edit "IoC-WATCH-Blocklist"
        set type address
        set resource "https://threatfeed.networklabs.id/api/v1/feed/fortigate"
        set refresh-rate 5
        set server-identity-check none
        set username "fortigate"
        set password ENC <TF_FEED_TOKENS>
        set status enable
    next
end
```

`username`/`password` dikirim sebagai HTTP Basic; server memeriksa bagian **password**
terhadap `TF_FEED_TOKENS`, jadi isi `username` bebas. Jika Anda lebih suka token di URL,
tambahkan `&token=<TF_FEED_TOKENS>` dan biarkan kredensial kosong.

Pakai di kebijakan:

```
config firewall policy
    edit 0
        set name "Block-IoC-WATCH"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "IoC-WATCH-Blocklist"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

Verifikasi di FortiGate:

```
diagnose test application externalresource 1     # daftar resource + status terakhir
diagnose test application externalresource 2     # paksa refresh sekarang
diagnose sys external-resource list
diagnose sys external-resource entry-list IoC-WATCH-Blocklist
execute log filter category event
```

### Parameter endpoint feed

**URL tanpa query string adalah yang disarankan.** CLI FortiGate kadang memakan
karakter `?` saat `set resource` diketik langsung, sehingga URL berubah jadi path yang
tidak ada dan dijawab `404` — yang dilaporkan GUI sebagai "Server not reachable".
Karena itu output bersih dijadikan perilaku bawaan, dan tersedia tiga path setara:

```
/api/v1/feed/fortigate            ← ikut TF_FEED_INLINE_COMMENTS (default: IP murni)
/api/v1/feed/fortigate/clean      ← selalu IP murni
/api/v1/feed/fortigate.txt        ← selalu IP murni, untuk alat yang menuntut ekstensi
/api/v1/feed/fortigate/annotated  ← selalu dengan komentar inline
/api/v1/feed/fortigate/annotated?type={filter}  ← filter by type
```

### Menampilkan komentar di FortiGate

Aktifkan lewat path (tanpa query string, aman dari CLI yang memakan `?`):

```
set resource "https://192.168.110.9/api/v1/feed/fortigate/annotated"
```

Atau jadikan default untuk semua path dasar:

```bash
sudo threatfeedctl config       # TF_FEED_INLINE_COMMENTS=true
```

Isi komentarnya dapat dipilih lewat `TF_FEED_COMMENT_FORMAT`:

| Nilai | Hasil |
|---|---|
| `plain` (default) | `103.74.20.57 # C2 Server detected` — isi kolom `comment` saja |
| `short` | `103.74.20.57 # Malware \| C2 Server detected` |
| `full` | `103.74.20.57 # Malware \| Malicious/100 \| TLP:RED \| FortiSOAR Playbook \| C2 Server detected` |

Entri yang tidak punya komentar ditulis sebagai IP polos tanpa `#` menggantung.

> **Validasi dulu sebelum produksi.** Dokumentasi FortiOS 7.4 menjamin komentar
> **baris-penuh** yang diawali `#`, tetapi komentar **inline** setelah alamat IP tidak
> didokumentasikan untuk feed tipe `address`. Kalau parser FortiGate Anda menolaknya,
> gejalanya adalah jumlah entri anjlok atau nol — bukan pesan error. Bandingkan:
>
> ```
> diagnose sys external-resource entry-list IoC-WATCH-Blocklist
> ```
> ```bash
> sudo threatfeedctl feed | grep -c .
> ```
>
> Kedua angka harus sama. Kalau berbeda, kembalikan ke `/clean` — konteks per-IP tetap
> bisa dilihat di dashboard dan lewat `threatfeedctl search`.

| Parameter | Default | Fungsi |
|---|---|---|
| `comments=true` | `false` | Header + komentar inline: `103.74.20.57 # Malware \| Malicious/100 \| TLP:RED \| C2 Server` |
| `clean=false` | — | Kembali ke perilaku lama (header `#` + ikut `TF_FEED_INLINE_COMMENTS`) |
| `severity=` | semua | `severity=Malicious,Critical` |
| `tlp=` | semua | `tlp=TLP:RED,TLP:AMBER` |
| `feed_name=` | semua | Batasi ke satu feed FortiSOAR — memungkinkan beberapa objek external-resource dari satu server |
| `min_confidence=` | `TF_FEED_MIN_CONFIDENCE` | Contoh: `min_confidence=80` |
| `ttl_days=` | `TF_TTL_DAYS` | Override TTL per-resource |
| `limit=` | `131072` | Batas keras FortiOS |

> **Catatan format.** Dokumentasi FortiOS 7.4 secara eksplisit menjamin komentar
> **baris-penuh** yang diawali `#`; komentar **inline** setelah alamat IP tidak
> didokumentasikan untuk feed tipe `address`. Karena itu `TF_FEED_INLINE_COMMENTS`
> default-nya `false`. Jika Anda ingin memakainya, aktifkan di lab dulu dan pastikan
> jumlah entri yang terbaca cocok:
> `diagnose sys external-resource entry-list IoC-WATCH-Blocklist | grep -c .`
> Untuk melihat konteks per-IP tanpa risiko, gunakan dashboard atau kolom `comment`
> di database — bukan berkas feed.

**Contoh multi-resource dari satu server:**

```
edit "IoC-CRITICAL"  set resource "https://…/feed/fortigate?severity=Malicious,Critical"
edit "IoC-TOR"       set resource "https://…/feed/fortigate?feed_name=Tor-Exit-Nodes"
```

Batas FortiOS: 10 MB atau 131.072 entri per berkas, mana yang lebih dulu tercapai; ada
pula batas jumlah objek `system.external-resource` per model — cek dengan
`diagnose sys external-resource list` dan `print tablesize`.

---

## 5. Dashboard

`https://threatfeed.networklabs.id/` — login dengan `TF_ADMIN_PASSWORD`. Sesi disimpan
dalam cookie HttpOnly bertanda tangan HMAC (tanpa `localStorage`).

Isi layar:

- **Strip peluruhan TTL** — setiap batang mewakili satu hari umur sejak pembaruan terakhir,
  diwarnai per severity, dengan garis "tebing kedaluwarsa" di hari ke-`TTL_DAYS`.
  Menumpuknya batang di sisi kanan berarti FortiSOAR berhenti me-refresh indikator lama.
- **Empat kartu statistik** — total IP, jumlah yang benar-benar disajikan ke FortiGate,
  waktu sinkronisasi terakhir, dan jumlah tarikan FortiGate dalam 24 jam.
- **Tabel indikator** — severity ditampilkan sebagai heat bar selebar nilai confidence,
  TLP sebagai badge berwarna resmi. Semua kolom bisa diurutkan.
- **Pencarian global** — satu kotak mencari IP, tipe, TLP, severity, sumber, komentar,
  dan nama feed sekaligus; ditambah lima filter dropdown.
- **Jejak audit** — 60 peristiwa terakhir, lengkap dengan IP klien dan durasi.

Halaman menyegarkan diri setiap 30 detik.

---

## 6. Fitur operasional

**Deduplikasi & upsert.** `ip_address` bersifat `UNIQUE COLLATE NOCASE`. Penulisan memakai
`INSERT … ON CONFLICT(ip_address) DO UPDATE … RETURNING hit_count` — satu perjalanan ke
database per entri, dan `hit_count == 1` menjadi penanda deterministik bahwa baris itu
baru (jangan pakai perbandingan timestamp: resolusinya detik dan bisa bertabrakan dalam
batch yang sama). Komentar kosong dari SOAR tidak akan menimpa konteks yang sudah ada.

**TTL / auto-pruning.** Dua lapis:
1. *Saat baca* — query feed selalu menyaring `updated_at >= now - TTL_DAYS`, sehingga
   indikator basi berhenti disajikan seketika, bahkan sebelum pruner berjalan.
2. *Saat rawat* — task asyncio setiap `TF_PRUNE_INTERVAL_SECONDS` menandai baris basi
   sebagai `expired`, menghapus permanen setelah `TF_HARD_DELETE_DAYS` (0 = tidak pernah),
   dan memangkas audit di luar `TF_AUDIT_RETENTION_DAYS`.

Pruning dapat dipicu manual dari dashboard atau lewat `POST /api/v1/maintenance/prune`.
Pruner **tidak** menyentuh `updated_at` — kolom itulah dasar perhitungan TTL.

**Audit trail.** Tabel `audit_log` mencatat `ingest`, `feed_pull`, `login`, `login_failed`,
`delete`, dan `prune`, masing-masing dengan waktu, aktor (sidik jari SHA-256 8 karakter
dari token — token asli tidak pernah ditulis), IP klien, User-Agent, jumlah entri
sukses/gagal, status HTTP, dan durasi.

**Caching.** Respons feed membawa `ETag`; FortiGate yang mengirim `If-None-Match` akan
menerima `304 Not Modified`. Dengan `refresh-rate 5` dan ribuan entri, ini menghemat
bandwidth secara signifikan.

**Keamanan.** Perbandingan token memakai `hmac.compare_digest` terhadap seluruh kandidat
(waktu eksekusi tidak membocorkan panjang token) · allow-list CIDR terpisah untuk ingest
dan feed · cookie HttpOnly + SameSite=Strict · header `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy` · rate limit per zona di nginx · sandbox systemd
dengan `ProtectSystem=strict` dan `CapabilityBoundingSet=` kosong.

**Rotasi token tanpa downtime:** isi `TF_INGEST_TOKENS=token_baru,token_lama`, restart,
pindahkan FortiSOAR ke token baru, lalu hapus yang lama dan restart sekali lagi.

---

## 7. Referensi endpoint

| Method | Path | Auth | Keterangan |
|---|---|---|---|
| `POST` | `/api/v1/ingest` | Bearer (ingest) | Push indikator dari FortiSOAR |
| `GET` | `/api/v1/feed/fortigate` | Bearer / Basic / `?token=` | Plain text untuk External Resource |
| `GET` | `/api/v1/feed/stats` | sama seperti feed | Jumlah entri yang sedang disajikan |
| `POST` | `/api/v1/auth/login` | password | Menerbitkan cookie sesi |
| `GET` | `/api/v1/stats` | cookie | Statistik dashboard + distribusi umur |
| `GET` | `/api/v1/indicators` | cookie | Cari/filter/urut/paginasi |
| `GET` | `/api/v1/filters` | cookie | Nilai unik untuk dropdown |
| `DELETE` | `/api/v1/indicators/{id}` | cookie | Hapus permanen satu indikator |
| `GET` | `/api/v1/audit` | cookie | Jejak audit |
| `POST` | `/api/v1/maintenance/prune` | cookie | Pruning manual |
| `GET` | `/healthz` | — | Health check |
| `GET` | `/api/docs` | — | OpenAPI (matikan di produksi bila perlu) |

---

## 8. Troubleshooting

Jalankan `sudo threatfeedctl doctor` lebih dulu — ia memeriksa service, port, nginx,
kecocokan SAN sertifikat, allowlist, dan menampilkan IP klien asli yang terlihat server.

| Gejala | Penyebab yang paling sering | Tindakan |
|---|---|---|
| FortiGate: `Server not reachable`, log nginx berkode `404` | Karakter `?` hilang saat `set resource` diketik di CLI | Pakai URL tanpa query string, atau masukkan lewat GUI |
| FortiGate: `Server not reachable`, tidak ada apa pun di log nginx | Belum ada yang mendengarkan di 443, atau firewall di jalur | `sudo ss -ltnp \| grep 443`; dari FortiGate: `execute telnet <ip> 443` |
| FortiGate: `Server not reachable`, sertifikat ber-CN hostname | SAN tidak mencakup IP yang dipakai FortiGate | Terbitkan ulang dengan SAN `IP:<ip>`; turunkan sementara ke `server-identity-check none` |
| nginx: `unknown directive "http2"` | nginx < 1.25.1 memakai `listen 443 ssl http2;` | Jalankan ulang `setup.sh` — versi terbaru mendeteksi versi nginx |
| FortiGate: `entry-list` kosong padahal HTTP 200 | Seluruh entri melewati TTL | `sudo threatfeedctl feed`; cek `TF_TTL_DAYS` |
| FortiGate gagal ambil, log `SSL error` | `server-identity-check full` tetapi Root CA belum diimpor | Impor Networklabs-Root-CA ke FortiGate, atau turunkan ke `basic` sementara |
| Ingest balas 401 | Token salah, atau `Authorization` dipotong proxy | `journalctl -u threatfeed \| grep login_failed`; pastikan nginx meneruskan header |
| Ingest balas 503 | `TF_INGEST_TOKENS` kosong | Isi di `/etc/threatfeed/threatfeed.env`, lalu restart |
| Ingest balas 403 | IP sumber di luar `TF_INGEST_ALLOWED_CIDRS` | Tambahkan IP FortiSOAR; jika di belakang proxy, pastikan `TF_TRUST_PROXY=true` |
| `database is locked` | Ada proses lain menulis ke berkas DB yang sama | Pastikan hanya `--workers 1`; jangan buka DB dengan `sqlite3` dalam mode tulis saat service hidup |
| Service gagal start setelah edit unit | `Type=notify` — uvicorn tidak mengirim `sd_notify` | Gunakan `Type=exec` (sudah demikian di unit terlampir) |
| Dashboard minta login berulang | `TF_SECRET_KEY` kosong sehingga diacak ulang tiap restart | Set nilai tetap hasil `openssl rand -hex 32` |
| Cookie tidak tersimpan | `TF_COOKIE_SECURE=true` tetapi diakses via HTTP | Pasang TLS, atau set `false` khusus lab |

---

## 9. Uji fungsional

```bash
bash tests/smoke.sh
```

Menjalankan instance sementara di port 8899 dan memverifikasi 15 skenario: kedua bentuk
payload, penanganan input bengkok, upsert vs insert, `delete`, autentikasi negatif,
ketiga mode output feed, filter severity, Basic auth, ETag/304, alur login dashboard,
pencarian, jejak audit, kedaluwarsa TTL + pruning, dan penetralan injeksi CRLF.
