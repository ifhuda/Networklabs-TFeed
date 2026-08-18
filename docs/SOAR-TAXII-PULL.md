# Tarik dari FortiSOAR (TAXII 2.1)

Arah sebaliknya dari ingest yang biasa dipakai. Alih-alih menunggu playbook FortiSOAR
mem-POST indikator ke `/api/v1/ingest`, server ini bisa aktif menarik indikator dari
**Outgoing TAXII Feed** FortiSOAR (Intelligence → Threat Feeds → TAXII Server) secara
berkala. Kedua jalur berjalan berdampingan — ini pelengkap, bukan pengganti.

## Kapan dipakai

Push (ingest yang sudah ada) lebih baik untuk kebanyakan kasus: indikator sampai persis
saat playbook mengonfirmasinya, real-time, tanpa server ini menyimpan kredensial
FortiSOAR. Pull (fitur ini) berguna kalau Anda tidak ingin membuat playbook untuk setiap
kejadian, atau ingin server menyapu seluruh koleksi TAXII secara berkala tanpa bergantung
pada trigger playbook.

## Menyiapkan di FortiSOAR

1. **Intelligence → Threat Feeds → TAXII Server**, aktifkan Outgoing TAXII Feed.
2. Catat **Server Address** (mis. `https://192.168.120.9:443/api/taxii/1/`) — inilah
   api-root yang dipakai server ini.
3. Buat **API Key** (direkomendasikan FortiSOAR sendiri di atas Basic Auth biasa):
   nama key jadi username, key itu sendiri jadi password.
4. Di **Available Datasets**, catat dataset mana yang ingin ditarik — Available Datasets
   yang sudah ada) di FortiSOAR bisa langsung dijadikan koleksi TAXII.

## Menyiapkan di IoC-WATCH

Buka tombol **Tarik FortiSOAR** di header dashboard.

1. Isi **Server Address**, **Nama API Key**, **API Key**.
2. Tekan **Uji Koneksi** — ini memanggil discovery dan `collections` FortiSOAR memakai
   nilai yang baru diketik, sebelum apa pun disimpan. Berhasil akan mengisi dropdown
   **Koleksi TAXII** dengan seluruh dataset yang tersedia.
3. Pilih koleksi, isi **Nama feed lokal** (label sumber di dashboard dan filter
   `?feed_name=` untuk FortiGate).
4. Tekan **Tarik Sekarang** untuk menguji satu siklus penuh — hasilnya langsung masuk
   database dan tersaji di feed FortiGate.

Panel ini untuk **menguji dan menarik on-demand**. Untuk polling otomatis berkelanjutan
dan menyimpan kredensial secara permanen, salin nilai yang sama ke **Konfigurasi
Sistem → Tarik dari FortiSOAR**, isi `TF_SOAR_TAXII_ENABLED=true`, lalu simpan — ini
menulis ke `.env` lewat helper root dan me-restart service seperti pengaturan lainnya.

| Variabel | Arti |
|---|---|
| `TF_SOAR_TAXII_ENABLED` | Master switch polling otomatis |
| `TF_SOAR_TAXII_URL` | Server Address (api-root) FortiSOAR |
| `TF_SOAR_TAXII_KEY_NAME` | Username Basic Auth (nama API key) |
| `TF_SOAR_TAXII_API_KEY` | Password Basic Auth (API key itu sendiri) |
| `TF_SOAR_TAXII_COLLECTION_ID` | UUID koleksi TAXII yang ditarik |
| `TF_SOAR_TAXII_FEED_NAME` | Label sumber di dashboard & filter feed FortiGate |
| `TF_SOAR_TAXII_POLL_MINUTES` | Jeda antar tarikan otomatis (default 15) |
| `TF_SOAR_TAXII_VERIFY_TLS` | Verifikasi sertifikat TLS FortiSOAR (default true) |

## Menarik lewat API langsung (tanpa GUI)

```bash
curl -s -b sesi.jar -X POST https://<server>/api/v1/admin/soar/pull-now \
  -H "Content-Type: application/json" -d '{
    "collection_ids": ["25d1110d-1189-49a3-86a7-b2d48ef0ba36",
                       "34a3f04d-f6de-4548-973f-a4cf9ba805f6"],
    "feed_name": "FortiGuard-Gabungan"
  }'
```

Respons meringkas seluruh koleksi yang diminta:

```json
{"inserted": 42, "updated": 8, "deduplicated": 0, "raw_objects": 55,
 "collections": [
   {"collection_id": "25d1110d-...", "raw_objects": 30, "pages": 1, "inserted": 25, "updated": 5},
   {"collection_id": "34a3f04d-...", "raw_objects": 25, "pages": 1, "inserted": 17, "updated": 3}
 ],
 "errors": []}
```

Bila satu koleksi gagal (kredensial salah untuk sebagian, koleksi dihapus di FortiSOAR,
dsb), koleksi itu masuk `errors` dan koleksi lain tetap diproses — respons hanya berupa
error HTTP 502 bila **semua** koleksi yang diminta gagal, bukan sebagian.

## Bagaimana cara kerjanya

Server memanggil endpoint TAXII 2.1 standar:

```
GET {Server Address}/collections
GET {Server Address}/collections/{id}/objects?limit=1000&added_after=<cursor>
```

Setiap objek STIX Indicator diparsing dua cara — pattern STIX baku dulu
(`[ipv4-addr:value = '1.2.3.4']`), lalu jatuh ke field `value` mentah bila FortiSOAR
mengekspor bentuk non-standar. Objek yang bukan IP (domain, hash, URL) dilewati diam-diam,
bukan dianggap error.

**Koleksi campuran benar-benar dilewati diam-diam, bukan cuma dijanjikan begitu.**
Koleksi seperti FortiGuard Outbreak sering berisi IP dan hash file (`typeOfFeed:
"FileHash-SHA256"`) dalam satu koleksi yang sama. Objek hash diproses lewat jalur yang
sama dengan IP, gagal saat `normalize_ip` mencoba mem-parsingnya sebagai alamat, dan
kegagalan itu ditangkap per-objek — satu hash yang gagal di-parse tidak menghentikan
objek IP lain di koleksi yang sama, dan tidak menjatuhkan siklus tarikan secara
keseluruhan.

### Pemetaan field — FortiSOAR bukan STIX baku

Objek yang dikirim endpoint TAXII FortiSOAR untuk fitur ini **bukan STIX 2.1 murni**,
melainkan bentuk `ThreatIntel` FortiSOAR sendiri: `reputation`, `source`, dan `tLP`
(perhatikan huruf L kapital di tengah — bukan `tlp`) ada langsung sebagai field objek,
sementara `pattern` dan `labels` (yang biasanya dipakai STIX baku) selalu kosong.
Contoh satu objek nyata:

```json
{"name": "103.74.20.57", "value": "103.74.20.57", "reputation": "Malicious",
 "source": "IPsum Threat Intelligence Feed", "tLP": "Red", "confidence": 100,
 "pattern": null, "label": null}
```

Memperlakukan ini sebagai STIX baku akan membuat `type` jatuh ke "Indicator" generik,
`comment` jatuh ke field `name` (yang kebetulan berisi IP itu sendiri, bukan konteks
apa pun), dan `source` selalu memakai nama feed lokal alih-alih sumber intel
sesungguhnya. Pemetaan yang dipakai:

| Kolom dashboard | Diisi dari | Contoh |
|---|---|---|
| **Type** | `reputation`, apa adanya | `Malicious` |
| **Severity** | `reputation`, dipetakan ke skala standar (lihat tabel di bawah) | `Critical` |
| **Source** | `source` | `IPsum Threat Intelligence Feed` |
| **Comment** | `source` + `reputation` digabung | `IPsum Threat Intelligence Feed — Malicious` |
| **TLP** | `tLP` (huruf L kapital) | `Red` → `TLP:RED` |
| **Confidence** | `confidence` | `100` |

Untuk server yang benar-benar mengirim STIX 2.1 baku (bukan bentuk FortiSOAR di atas),
parser jatuh kembali ke `labels`/`x_severity`/`x_tlp` seperti sebelumnya — `reputation`
yang kosong tidak menimpa apa pun.

### Severity mengikuti skala standar, bukan teks reputation mentah

`reputation` FortiSOAR ("Malicious", "Suspicious", dst) bukan bagian dari taksonomi
severity standar (Critical/High/Medium/Low/Info) yang dipakai untuk triase — memakainya
mentah sebagai severity akan membuat kolom itu berisi nilai yang tidak sebanding dan
tidak bisa diurutkan berdasarkan tingkat keparahan. Dipetakan lewat
`taxii_client.REPUTATION_SEVERITY`:

| `reputation` FortiSOAR | Severity dashboard | Alasan |
|---|---|---|
| `Malicious` | **Critical** | Butuh perhatian segera — indikator terkonfirmasi jahat |
| `Suspicious` | **High** | Mengindikasikan masalah, belum terkonfirmasi |
| `Unknown` | **Medium** | Peringatan dini, bukan kesalahan aktual |
| `Known Good`, `Good`, `Benign`, `Clean`, `Trusted`, `Safe`, `Whitelisted` | **Info** | Sekadar informasi |
| Nilai lain yang tidak dikenal | **Medium** | Default aman — tidak diam-diam diabaikan atau dianggap kritis |

Perbandingan dicocokkan tanpa peduli huruf besar-kecil. Kolom **Type** tetap memakai
teks `reputation` apa adanya (mis. "Malicious") — hanya **Severity** yang dipetakan ke
skala standar, supaya info reputasi asli FortiSOAR tetap terlihat di Type sekaligus
severity-nya bisa dibandingkan lintas sumber data lain di dashboard.

**Cursor `added_after` per-koleksi**, bukan global: setiap koleksi punya jejak
"kapan terakhir ditarik" sendiri, diambil dari jejak audit `soar_pull` yang cocok
`collection_id`-nya. Tanpa ini, menarik koleksi lain di antara dua siklus akan secara
tidak sengaja memakai timestamp koleksi yang salah dan melewatkan indikator baru.

Paginasi diikuti lewat `next` cursor sampai `more: false`, maksimum 20 halaman per
siklus (mencegah satu koleksi raksasa menahan siklus polling selamanya).

Hasil tarikan melewati jalur `crud.upsert_many` yang sama dengan ingest push — dedup,
severity/TLP/confidence normalize, dan hit_count semuanya berlaku otomatis.

## Verifikasi

```bash
sudo threatfeedctl audit 10 | grep soar_
sudo threatfeedctl feed | grep -c .
```

Jejak audit `soar_pull` mencatat `raw_objects`, jumlah `inserted`/`updated`, dan
`collection_id` di tiap siklus — baik dari polling otomatis maupun tombol Tarik Sekarang.

## Kesalahan umum

| Pesan | Penyebab |
|---|---|
| `401 — API key atau nama key salah` | Nama key atau API key tertukar/salah ketik |
| `403 — key valid tapi tidak berizin` | Key belum diberi akses ke koleksi ini di FortiSOAR |
| `404 — path TAXII tidak ditemukan` | Server Address salah; pastikan diakhiri `/api/taxii/1/` |
| Tarik Sekarang gagal 401 padahal Uji Koneksi berhasil | API Key belum diisi ulang di form (kosong setelah re-render); ketik ulang sebelum menarik |
| Panel selalu "belum pernah ditarik" walau polling aktif | `TF_SOAR_TAXII_COLLECTION_ID` kosong di `.env` — polling otomatis melewati siklus tanpanya |
| Seluruh pull gagal 500 (bukan sebagian) saat koleksi berisi hash file | Bug pada versi sebelum 1.3.3 — `ValueError` dari input non-IP tidak tertangkap dan menjatuhkan seluruh siklus. Perbarui ke versi terbaru; hash sekarang dilewati per-objek, tidak menjatuhkan seluruh tarikan |

## Pengujian

```bash
bash tests/soar-taxii.sh
```

22 skenario terhadap server TAXII 2.1 tiruan: auth benar/salah, parsing pattern STIX
standar dengan domain-name dilewati, **pemetaan field bentuk asli FortiSOAR
(`reputation`/`source`/`tLP`) ke type/severity/source/comment/tlp**, **koleksi campuran
IP dan hash SHA-256 yang tidak boleh men-crash siklus tarikan** (reproduksi persis dari
log produksi), paginasi dua halaman, isolasi cursor antar-koleksi, integrasi ke feed
FortiGate, proteksi sesi pada ketiga endpoint admin, cakupan jejak audit, plus: menarik
banyak koleksi
dalam satu panggilan (`collection_ids`), kegagalan sebagian yang tidak menyembunyikan
hasil yang berhasil, kegagalan total yang melapor 502 alih-alih sukses parsial palsu,
dan status koleksi ad-hoc yang belum tersimpan ke `.env` (`?ids=`).
