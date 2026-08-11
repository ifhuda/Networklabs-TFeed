# Checklist Penerapan Produksi

Urutan ini disusun supaya setiap langkah bisa diverifikasi sebelum melangkah ke
berikutnya. Kalau satu langkah gagal, Anda tahu persis di mana, bukan mencari-cari
setelah semuanya terpasang.

---

## Sebelum mulai

- [ ] **VM disiapkan** — Ubuntu 22.04/24.04 atau Debian 12, 1 vCPU, 1 GB RAM, 10 GB disk
- [ ] **Jam benar** — TTL bergantung sepenuhnya pada ini

  ```bash
  sudo timedatectl set-timezone Asia/Jakarta
  timedatectl    # "System clock synchronized: yes"
  ```

- [ ] **Tiga alamat dicatat**

  | Nilai | Cara memastikan |
  |---|---|
  | IP/FQDN server | `hostname -I` |
  | IP FortiSOAR | Alamat sumber yang akan push |
  | IP/subnet FortiGate | Alamat yang akan menarik feed |

  Kalau ada NAT di jalur, yang dipakai adalah alamat **setelah** NAT — yaitu yang
  terlihat oleh server. Bisa dikonfirmasi belakangan lewat `threatfeedctl audit`.

- [ ] **Sertifikat disiapkan** (disarankan untuk produksi)

  Terbitkan dari Networklabs-Root-CA dengan SAN yang mencakup **IP** yang akan
  dipakai FortiGate, bukan hanya hostname. Root CA harus diimpor ke FortiGate:
  **System > Certificates > Import > CA Certificate**.

  Tanpa ini, pakai `--tls self-signed` dan FortiGate perlu
  `set server-identity-check none`.

---

## Instalasi

- [ ] **Letakkan project di luar `/tmp`** — `/tmp` dibersihkan saat reboot, dan
      tanpa foldernya `--upgrade` serta `--uninstall` tidak tersedia

  ```bash
  sudo mkdir -p /opt/threatfeed-src
  sudo git clone <repo-url> /opt/threatfeed-src   # atau ekstrak arsip rilis
  cd /opt/threatfeed-src
  ```

- [ ] **Jalankan installer**

  ```bash
  sudo bash deploy/setup.sh \
    --domain <ip-atau-fqdn> \
    --soar-ip <ip-fortisoar> \
    --fgt-ip <subnet-fortigate> \
    --ttl 30 \
    --tls existing --cert /etc/ssl/certs/feed-fullchain.pem --key /etc/ssl/private/feed.key \
    --comments \
    --yes
  ```

  Hilangkan `--comments` kalau feed ingin berisi IP polos saja.
  Ganti `--tls existing …` dengan `--tls self-signed` kalau sertifikat belum terbit.

- [ ] **Catat kredensial** yang tercetak di akhir. Tersimpan juga di
      `/etc/threatfeed/INSTALL-SUMMARY.txt` (mode 640).

---

## Verifikasi server

- [ ] **Pemeriksaan menyeluruh**

  ```bash
  sudo threatfeedctl doctor
  ```

  Harus `0 gagal`. Perhatikan khusus baris "sertifikat mencakup …" — inilah
  penyebab tersering FortiGate melaporkan "Server not reachable".

- [ ] **Port terbuka**

  ```bash
  sudo ss -ltnp | grep -E ':(443|8080)'
  ```

  Yang benar: `127.0.0.1:8080` (uvicorn) dan `0.0.0.0:443` (nginx). uvicorn memang
  hanya di loopback — nginx yang menghadap jaringan.

- [ ] **Feed terbaca**

  ```bash
  sudo threatfeedctl feed 10
  ```

---

## Verifikasi dari sisi klien

- [ ] **Dari FortiGate** — ini yang menguji routing, firewall, dan TLS sekaligus

  ```
  execute ping <ip-server>
  execute telnet <ip-server> 443
  ```

- [ ] **Tarik feed dari host di subnet FortiGate**

  ```bash
  curl -v -u fortigate:<TOKEN_FEED> https://<ip-server>/api/v1/feed/fortigate
  ```

  | Hasil | Artinya |
  |---|---|
  | `200` + daftar IP | Siap |
  | `401` | Token salah |
  | `403` | IP sumber di luar `TF_FEED_ALLOWED_CIDRS` |
  | `404` | Path salah — periksa karakter `?` |
  | Gagal konek | Firewall atau routing |

---

## Sambungkan FortiGate

- [ ] **Konfigurasi resource** (salin dari `INSTALL-SUMMARY.txt` — sudah berisi
      path dan token yang benar)

  ```
  config system external-resource
      edit "IoC-WATCH-Blocklist"
          set type address
          set resource "https://<ip-server>/api/v1/feed/fortigate/annotated"
          set refresh-rate 5
          set server-identity-check full
          set username "fortigate"
          set password <TOKEN_FEED>
          set status enable
      next
  end
  ```

  `server-identity-check none` kalau sertifikat masih self-signed.
  Path `/annotated` hanya bila Anda memasang dengan `--comments`; kalau tidak,
  pakai `/api/v1/feed/fortigate`.

- [ ] **Verifikasi jumlah entri cocok** — wajib bila memakai `/annotated`

  ```
  diagnose sys external-resource entry-list IoC-WATCH-Blocklist
  ```
  ```bash
  sudo threatfeedctl feed | grep -c .
  ```

  Kedua angka harus sama. Kalau berbeda, parser FortiGate menolak komentar inline —
  kembalikan ke `/api/v1/feed/fortigate/clean`. Gejalanya bukan pesan error,
  melainkan entri anjlok diam-diam.

- [ ] **Pantau dari server saat FortiGate menarik**

  ```bash
  sudo tail -f /var/log/nginx/threatfeed.access.log
  ```

---

## Sambungkan FortiSOAR

- [ ] **Konfigurasi connector**

  - URL: `https://<ip-server>/api/v1/ingest`
  - Method: `POST`
  - Header: `Authorization: Bearer <TOKEN_INGEST>`, `Content-Type: application/json`

- [ ] **Uji satu kiriman**, lalu konfirmasi IP sumber yang benar-benar terlihat server

  ```bash
  sudo threatfeedctl audit 10
  ```

  Kolom Klien menunjukkan IP asli setelah NAT. Sesuaikan
  `TF_INGEST_ALLOWED_CIDRS` bila berbeda dari yang Anda isi saat instalasi.

---

## Pengerasan setelah semuanya jalan

- [ ] **Allowlist terisi** — bukan dibiarkan kosong

  ```bash
  grep ALLOWED_CIDRS /etc/threatfeed/threatfeed.env
  ```

  Jangan hilangkan entri loopback: `threatfeedctl` memanggil API dari `127.0.0.1`.

- [ ] **Cookie aman** — `TF_COOKIE_SECURE=true` bila diakses via HTTPS

- [ ] **Entri uji dihapus**

  ```bash
  sudo threatfeedctl expire 192.0.2.99
  ```

- [ ] **Backup terjadwal**

  ```bash
  sudo tee /etc/cron.d/threatfeed-backup <<'EOF'
  0 2 * * * root /usr/local/bin/threatfeedctl backup >/dev/null 2>&1
  EOF
  ```

- [ ] **Hardening systemd terverifikasi**

  ```bash
  systemd-analyze security threatfeed
  ```

- [ ] **Dokumentasi API ditutup** bila tidak diperlukan — `/api/docs` terbuka tanpa
      autentikasi (hanya menampilkan skema, bukan data). Blokir di nginx bila perlu:

  ```nginx
  location /api/docs { deny all; }
  ```

- [ ] **Rotasi kredensial** bila token sempat tampil di layar, chat, atau tiket

  ```bash
  sudo threatfeedctl rotate ingest              # token baru + lama berlaku
  # … pindahkan FortiSOAR ke token baru …
  sudo threatfeedctl rotate ingest --finish     # cabut token lama
  ```

---

## Operasional harian

| Kebutuhan | Perintah |
|---|---|
| Kesehatan menyeluruh | `sudo threatfeedctl doctor` |
| Ringkasan cepat | `sudo threatfeedctl status` |
| Apa yang dilihat FortiGate | `sudo threatfeedctl feed` |
| Cari indikator | `sudo threatfeedctl search <teks>` |
| Siapa yang mengakses | `sudo threatfeedctl audit 20` |
| Backup manual | `sudo threatfeedctl backup` |
| Ubah konfigurasi | `sudo threatfeedctl config` |

**Yang perlu diperhatikan di dashboard:** strip peluruhan TTL. Batang yang menumpuk
di sisi kanan berarti FortiSOAR berhenti me-refresh indikator lama — peringatan
beberapa hari sebelum proteksi Anda diam-diam berhenti, bukan setelahnya.

---

## Upgrade di kemudian hari

```bash
cd /opt/threatfeed-src
sudo unzip -o ~/threatfeed-baru.zip -d /tmp/tf && sudo cp -r /tmp/tf/threatfeed/. .
sudo bash deploy/setup.sh --upgrade
sudo threatfeedctl doctor
```

`--upgrade` hanya memperbarui kode. Kredensial, database, dan konfigurasi nginx
dipertahankan; versi lama dicadangkan ke `/var/lib/threatfeed/rollback-*`.
