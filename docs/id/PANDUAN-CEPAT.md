# Panduan Cepat — IoC-WATCH Threat Feed Server

Panduan ini memuat contoh **siap tempel**: instalasi, konfigurasi FortiGate
`external-resource`, dan potongan body untuk FortiSOAR maupun webhook pihak ketiga.
Ganti setiap `<...>` dengan nilai Anda.

Untuk penjelasan mendalam, lihat [PANDUAN.md](PANDUAN.md).
Dokumentasi berbahasa Inggris: [../INSTALL.md](../INSTALL.md), [../USAGE.md](../USAGE.md),
[../INTEGRATIONS.md](../INTEGRATIONS.md).

---

## 1. Instalasi

Server: Ubuntu 22.04/24.04 atau Debian 12, 1 vCPU, 1 GB RAM.

```bash
# Pastikan jam benar — TTL bergantung sepenuhnya pada ini
sudo timedatectl set-timezone Asia/Jakarta
timedatectl        # "System clock synchronized: yes"

# Letakkan di lokasi tetap, bukan /tmp (dibersihkan saat reboot)
sudo mkdir -p /opt/threatfeed-src
sudo unzip threatfeed-github.zip -d /tmp/tf && sudo cp -r /tmp/tf/threatfeed/. /opt/threatfeed-src/
cd /opt/threatfeed-src

# Pasang. Halaman Konfigurasi Sistem, tombol Pulihkan, dan generator snippet
# aktif secara DEFAULT — tidak perlu flag tambahan. Untuk mematikannya,
# tambahkan --disable-env-editor.
sudo bash deploy/setup.sh \
  --domain 192.168.110.9 \
  --soar-ip 192.168.0.99 \
  --fgt-ip 192.168.110.0/24 \
  --ttl 30 \
  --comments \
  --yes
```

Instalasi mencetak password dashboard dan kedua token, dan menyimpannya di
`/etc/threatfeed/INSTALL-SUMMARY.txt`. Verifikasi:

```bash
sudo threatfeedctl doctor          # harus 0 gagal
sudo threatfeedctl creds           # tampilkan URL dashboard, password, token
```

Nilai yang benar untuk `--soar-ip` dan `--fgt-ip` adalah **alamat setelah NAT** — yang
terlihat server. Konfirmasi belakangan lewat kolom Klien di `threatfeedctl audit`.

---

## 2. Konfigurasi FortiGate

Ambil token feed dulu:

```bash
sudo threatfeedctl creds | grep -i feed
```

### Cara termudah: salin dari dashboard

Buka **Konfigurasi Sistem → Kredensial & Keamanan → Snippet CLI FortiGate**. Panel itu
merakit blok di bawah dengan URL, path, username, dan filter yang sudah benar, lengkap
dengan jumlah entri yang cocok. Tekan **Salin**, tempel di FortiGate.

### Manual

```
config system external-resource
    edit "IoC-WATCH-Blocklist"
        set type address
        set resource "https://192.168.110.9/api/v1/feed/fortigate/annotated"
        set refresh-rate 5
        set server-identity-check full
        set username "fortigate"
        set password <TOKEN_FEED>
        set status enable
    next
end
```

Catatan penting:

- **Path `/annotated`** hanya bila Anda memasang dengan `--comments`. Kalau tidak, pakai
  `/api/v1/feed/fortigate`.
- **`server-identity-check full`** butuh sertifikat dari CA yang root-nya sudah diimpor
  ke FortiGate. Untuk sertifikat self-signed, pakai `set server-identity-check none`.
- **`username`** boleh apa saja secara default; hanya token yang diperiksa. Kalau Anda
  mengisi `TF_FEED_USERNAME`, nilai di sini harus sama persis.

### Terapkan ke policy

```
config firewall address
    edit "IoC-WATCH-Blocklist"
        set type external
    next
end

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

### Verifikasi di FortiGate

```
diagnose sys external-resource list
diagnose sys external-resource entry-list IoC-WATCH-Blocklist
```

Bandingkan jumlahnya dengan yang dilihat server:

```bash
sudo threatfeedctl feed | grep -c .
```

Kedua angka **harus sama**. Kalau berbeda saat memakai `/annotated`, parser FortiGate
menolak komentar inline — kembalikan ke `/api/v1/feed/fortigate/clean`. Gejalanya bukan
pesan error, melainkan entri anjlok diam-diam.

### Beberapa feed dari satu server

Filter lewat query string. Semua nilai tidak peka huruf besar-kecil.

```
edit "IoC-CRITICAL"
    set resource "https://192.168.110.9/api/v1/feed/fortigate?severity=malicious,critical"
next
edit "IoC-DECEPTION"
    set resource "https://192.168.110.9/api/v1/feed/fortigate?type=deception"
next
edit "IoC-TOR"
    set resource "https://192.168.110.9/api/v1/feed/fortigate?feed_name=Tor-Exit-Nodes"
next
```

Parameter yang tersedia: `severity`, `type`, `tlp`, `feed_name`, `min_confidence`,
`ttl_days`, `limit`.

---

## 3. Push dari FortiSOAR

**Endpoint:** `POST https://192.168.110.9/api/v1/ingest`
**Header:** `Authorization: Bearer <TOKEN_INGEST>`, `Content-Type: application/json`

Metode selalu `POST`. Menambah, menghapus, dan mengganti dibedakan oleh field `command`
di body, bukan oleh HTTP method.

### Menambah indikator

```json
{
  "commands": [
    {
      "name": "Threat_Feeds-IP-01",
      "command": "add",
      "entries": [
        {
          "ip": "{{ vars.input.params.sourceIp }}",
          "type": "{{ vars.input.params.type }}",
          "severity": "{{ vars.input.params.severity }}",
          "confidence": 90,
          "tlp": "TLP:AMBER",
          "source": "FortiSOAR Playbook",
          "comment": "{{ vars.input.params.name }} at {{ vars.input.params.createDate }}"
        }
      ]
    }
  ]
}
```

### Menghapus indikator

Hanya `ip` yang dibaca; field lain boleh dihilangkan.

```json
{
  "commands": [
    {
      "name": "Threat_Feeds-IP-01",
      "command": "delete",
      "entries": [
        { "ip": "{{ vars.input.params.sourceIp }}" }
      ]
    }
  ]
}
```

### Sinkronisasi penuh

Bila playbook menghasilkan daftar lengkap setiap kali berjalan, `replace` mencabut
sendiri IP yang tak lagi ada — terbatas pada feed bernama sama.

```json
{
  "commands": [
    {
      "name": "Threat_Feeds-IP-01",
      "command": "replace",
      "entries": [ "203.0.113.10", "203.0.113.11", "45.155.205.233" ]
    }
  ]
}
```

### Respons

```json
{"status":"ok","received":1,"inserted":1,"updated":0,"revoked":0,"rejected":0,
 "processed_at":"2026-08-13T04:00:00Z"}
```

`status` bernilai `ok` atau `partial`. Entri buruk tidak menggagalkan batch — playbook
tetap sukses, dan array `errors` menunjukkan baris yang perlu diperbaiki.

### Uji cepat dari server

```bash
sudo threatfeedctl test 203.0.113.55     # tambah lewat jalur yang sama
sudo threatfeedctl feed                  # pastikan muncul
sudo threatfeedctl expire 203.0.113.55   # hapus
```

---

## 4. Webhook pihak ketiga (FortiDeceptor)

Untuk produk yang payloadnya tidak bisa Anda bentuk dan membedakan block/unblock lewat
URL. Tiga fitur menanganinya: aksi dari path (`/block`, `/unblock`), `?deep=true` untuk
memindai IP dari struktur JSON apa pun, dan metadata lewat query string.

### Bedah payload dulu — sekali

Arahkan Block URL sementara ke endpoint diagnostik yang **tidak menyimpan apa pun**:

```
https://192.168.110.9/api/v1/ingest/echo
```

Picu satu kejadian, lalu lihat apa yang tertangkap:

```bash
sudo threatfeedctl audit 5
```

Responsnya menampilkan IP yang terdeteksi:

```json
{"detected_ips":["198.51.100.77"],
 "content_type":"application/json",
 "payload":{"incident":{"attacker":{"ipv4":"198.51.100.77"}}},
 "hint":"Pakai ?deep=true jika detected_ips sudah benar."}
```

Kalau `detected_ips` sudah berisi IP penyerang saja, ganti URL ke `/block`.

### Konfigurasi final di FortiDeceptor

Menu **Integrate With New Device**, Integrate Method `FortiGate-WEBHOOK`:

| Field | Isi |
|---|---|
| Block URL | `https://192.168.110.9/api/v1/ingest/block?deep=true&source=FortiDeceptor&type=Deception&severity=Malicious&confidence=90&tlp=TLP:AMBER&feed_name=FortiDeceptor` |
| Block Authorization | `Bearer <TOKEN_INGEST>` |
| Unblock URL | `https://192.168.110.9/api/v1/ingest/unblock?deep=true` |
| Unblock Authorization | `Bearer <TOKEN_INGEST>` |

Field Authorization menerima nilai header lengkap — kata `Bearer` dan spasinya wajib.

### Contoh body webhook mentah

Ini yang dikirim FortiDeceptor; Anda tidak menulisnya sendiri, tetapi berguna untuk
memahami apa yang `?deep=true` pindai:

```json
{
  "incident": {
    "id": "FD-2026-001",
    "attacker": { "ipv4": "198.51.100.77" },
    "sensor": { "ip": "192.168.110.9" },
    "severity": "high",
    "event": "SMB lure triggered"
  }
}
```

Kunci yang mengandung `attacker`, `source`, `src`, `remote`, `client` diprioritaskan, jadi
hanya `198.51.100.77` yang tersimpan — IP sensor diabaikan.

### Izinkan IP-nya

Tambahkan alamat yang terlihat server (dari `threatfeedctl audit`) ke allowlist lewat
**Konfigurasi Sistem → Kontrol Akses Jaringan**, atau CLI:

```bash
sudo threatfeedctl config     # ubah TF_INGEST_ALLOWED_CIDRS
```

### Pola webhook generik

Produk apa pun yang bisa POST terautentikasi:

```
POST https://192.168.110.9/api/v1/ingest/block?deep=true&source=<nama>&feed_name=<nama>
Authorization: Bearer <TOKEN_INGEST>
Content-Type: application/json

{ ...apa pun yang dikirim produk... }
```

Beri tiap integrasi `feed_name` sendiri agar terpisah di dashboard dan bisa disajikan ke
objek FortiGate berbeda.

---

## 5. Operasional harian

| Kebutuhan | Perintah |
|---|---|
| Kesehatan menyeluruh | `sudo threatfeedctl doctor` |
| Apa yang dilihat FortiGate | `sudo threatfeedctl feed` |
| Cari indikator | `sudo threatfeedctl search <teks>` |
| Siapa yang mengakses | `sudo threatfeedctl audit 20` |
| Backup manual | `sudo threatfeedctl backup` |
| Rotasi token tanpa downtime | `sudo threatfeedctl rotate feed` lalu `--finish` |

Lewat dashboard: **Ekspor** (CSV/JSON/backup .db), **Backup** (snapshot + restore),
**Konfigurasi Sistem** (semua variabel `.env`).

---

## 6. Bila bermasalah

| Gejala | Kemungkinan penyebab |
|---|---|
| FortiGate: "Server not reachable" | Sertifikat tidak mencakup IP; jalankan `threatfeedctl doctor` |
| Feed kosong di FortiGate | Semua indikator lewat TTL, atau parser menolak komentar inline → pakai `/clean` |
| Webhook `403 Forbidden` | IP sumber di luar `TF_INGEST_ALLOWED_CIDRS` — cek log nginx untuk IP asli |
| Webhook `401` | Token salah, atau header `Authorization` tidak lengkap |
| Ingest `405` | HTTP method bukan POST |
| Filter `?severity=...` hasilkan feed kosong | Salah ketik nilai — panel snippet menampilkan jumlah cocok |

Detail lengkap: [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md).
