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

### Empat jenis indikator: IP, domain, hash, URL

Server mendukung empat jenis indikator sekaligus dalam satu koleksi campuran — persis
bentuk FortiGuard Outbreak yang mencampur alamat IP, hash file, dan URL (mis.
`https://t.me/...` sebagai link phishing/C2) dalam koleksi yang sama, atau Phishing
Threat Feeds yang berisi domain. Setiap objek diparsing dua cara: pattern STIX baku dulu
(`[ipv4-addr:value = '1.2.3.4']`, `[domain-name:value = 'evil.com']`,
`[file:hashes.'SHA-256' = '...']`, `[url:value = 'https://...']`), lalu jatuh ke field
`value` mentah dengan jenisnya disimpulkan dari `indicatorTypes`/`typeOfFeed` — bentuk
yang dipakai mayoritas objek FortiSOAR.

| Jenis di FortiSOAR | Dikenali dari | Tersimpan sebagai |
|---|---|---|
| `indicatorTypes: ["ipv4-addr"]`, `typeOfFeed: "IP Address"` | IP | `ioc_type = ip` |
| `indicatorTypes: ["file"]`, `typeOfFeed: "FileHash-SHA256"` (juga MD5/SHA-1) | Hash | `ioc_type = hash` |
| `indicatorTypes: ["domain-name"]`, `typeOfFeed: "Domain"` | Domain | `ioc_type = domain` |
| `indicatorTypes: ["url"]`, `typeOfFeed: "URL"` | URL | `ioc_type = url` |

Setiap indikator diproses menurut jenisnya sendiri, divalidasi lewat fungsi normalisasi
yang sesuai (`normalize_ip`/`normalize_hash`/`normalize_domain`/`normalize_url`) — satu
objek yang gagal divalidasi (mis. bentuknya tidak dikenali sama sekali) dilewati sendiri,
tidak menjatuhkan siklus tarikan secara keseluruhan atau menghentikan objek lain di
koleksi yang sama.

Bila jenisnya sama sekali tidak bisa disimpulkan dari `indicatorTypes`/`typeOfFeed`,
parser mencoba menebak dari bentuk nilainya sendiri sebagai upaya terakhir: string
heksadesimal 32/40/64 karakter → hash, mengandung `://` → URL, bisa di-parse sebagai
alamat IP → ip, selain itu → domain.

### Kolom Tipe terpisah dari Reputasi

Dashboard punya dua kolom yang mudah tertukar maknanya:

- **Tipe** — jenis indikator (IP Address / Domain / Hash / URL), badge berwarna di
  tabel dan filter dropdown tersendiri. Diambil dari `ioc_type`.
- **Reputasi** — label reputasi asli FortiSOAR (mis. "Malicious"), sebelumnya berlabel
  "Type" di versi lebih lama. Diambil dari field `reputation`.

### Feed FortiGate terpisah per jenis

Satu feed `config system external-resource / set type address` tidak bisa mencampur
alamat IP dengan domain, hash, atau URL — empat endpoint terpisah disediakan, masing-masing
hanya menyajikan satu jenis:

| Endpoint | Isi | Dipakai untuk |
|---|---|---|
| `/api/v1/feed/fortigate` (dan `/clean`, `/annotated`, `.txt`) | Hanya IP | `set type address`, dipasang langsung ke firewall policy |
| `/api/v1/feed/fortigate/domain` (dan `/clean`, `/annotated`) | Hanya domain | `set type domain`, dipasang langsung ke firewall policy |
| `/api/v1/feed/fortigate/hash` (dan `/clean`) | Hanya hash | `set type malware`, dipasang lewat AntiVirus profile ("Use external malware block list") — bukan langsung ke firewall policy |
| `/api/v1/feed/fortigate/url` (dan `/clean`) | Hanya URL lengkap (skema+host+path) | `set type category` dengan nomor kategori 192–221, dipasang lewat Web Filter profile sebagai Remote Category — butuh SSL deep inspection agar path URL terlihat di trafik HTTPS |

`ioc_type` pada endpoint feed **dikunci oleh server**, tidak bisa diubah lewat query
string — mencegah domain atau hash tercampur secara tidak sengaja ke feed alamat IP yang
sedang dipakai firewall policy aktif.

Semua filter yang sudah ada (`severity`, `type`, `tlp`, `feed_name`, `min_confidence`,
`ttl_days`, `limit`) tetap berlaku di ketiga endpoint ini, sebagaimana biasa.

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
| **Tipe** | `ioc_type` disimpulkan dari `indicatorTypes`/`typeOfFeed` atau bentuk pattern STIX | `IP Address` / `Domain` / `Hash` |
| **Reputasi** | `reputation`, apa adanya | `Malicious` |
| **Severity** | `reputation`, dipetakan ke skala standar (lihat tabel di bawah) | `Critical` |
| **Source** | `source` | `IPsum Threat Intelligence Feed` |
| **Comment** | `source` + `reputation` digabung | `IPsum Threat Intelligence Feed - Malicious` |
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

Perbandingan dicocokkan tanpa peduli huruf besar-kecil. Kolom **Reputasi** tetap memakai
teks `reputation` apa adanya (mis. "Malicious") — hanya **Severity** yang dipetakan ke
skala standar, supaya info reputasi asli FortiSOAR tetap terlihat di kolom Reputasi
sekaligus severity-nya bisa dibandingkan lintas sumber data lain di dashboard.

**Cursor `added_after` per-koleksi**, bukan global: setiap koleksi punya jejak
"kapan terakhir ditarik" sendiri, diambil dari jejak audit `soar_pull` yang cocok
`collection_id`-nya. Tanpa ini, menarik koleksi lain di antara dua siklus akan secara
tidak sengaja memakai timestamp koleksi yang salah dan melewatkan indikator baru.

### Kenapa indikator yang sudah ada tidak selalu ter-update

`added_after` bekerja berdasarkan **tanggal objek ditambahkan** ke koleksi TAXII, bukan
tanggal terakhir diubah. Bila FortiSOAR mengubah `reputation`, `tLP`, atau `confidence`
pada indikator yang **sudah pernah ditarik sebelumnya**, tapi tanggal "ditambahkan"-nya
di FortiSOAR tidak berubah, tarikan berikutnya (yang memakai cursor) tidak akan melihat
objek itu lagi — server TAXII hanya mengembalikan objek yang genuinely baru sejak
timestamp itu.

Untuk kasus ini, centang **"Tarik ulang semua (abaikan histori)"** di panel Tarik
FortiSOAR (atau kirim `"full_history": true` lewat API) — ini melewati cursor sama
sekali dan menarik ulang seluruh koleksi dari awal, sehingga perubahan field pada
indikator lama ikut terbawa. Checkbox ini otomatis tidak tercentang lagi setelah satu
kali tarikan berhasil, supaya tidak tidak sengaja menarik ulang seluruh koleksi di
setiap klik berikutnya.

Paginasi diikuti lewat `next` cursor sampai `more: false`, maksimum 20 halaman per
siklus (mencegah satu koleksi raksasa menahan siklus polling selamanya). Bila server
mengembalikan cursor `next` yang **sama persis** dengan siklus sebelumnya sambil tetap
melaporkan `more: true` — indikasi cursor macet di sisi server — client berhenti setelah
mendeteksinya (2 request, bukan menghabiskan seluruh 20 halaman) alih-alih terus
mengulang permintaan yang sama.

Hasil tarikan melewati jalur `crud.upsert_many` yang sama dengan ingest push — dedup,
severity/TLP/confidence normalize, dan hit_count semuanya berlaku otomatis. Menarik
ulang objek yang sudah ada (baik lewat cursor alami maupun `full_history`) selalu
tercatat sebagai **update**, bukan insert ganda — `ip_address` adalah kunci unik di
database.

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
| Data di FortiSOAR berubah (reputasi/TLP/confidence) tapi tidak terlihat di dashboard setelah tarik ulang | Cursor `added_after` hanya mengambil objek baru, bukan yang diubah. Centang "Tarik ulang semua (abaikan histori)" di panel, atau kirim `full_history: true` lewat API |
| Seluruh pull gagal 500 (bukan sebagian) saat koleksi berisi hash file | Bug pada versi sebelum 1.3.3 — `ValueError` dari input non-IP tidak tertangkap dan menjatuhkan seluruh siklus. Perbarui ke versi terbaru; hash sekarang ditarik sebagai indikator hash (bukan lagi dilewati), dan satu objek yang benar-benar tidak dikenali tetap tidak menjatuhkan seluruh tarikan |
| Domain/hash malah muncul di feed FortiGate `type address` | Terjadi hanya di versi sebelum 1.4.0, sebelum feed dipisah per `ioc_type`. Perbarui ke versi terbaru — `/api/v1/feed/fortigate` sekarang otomatis hanya menyajikan IP; pakai `/feed/fortigate/domain` atau `/feed/fortigate/hash` untuk jenis lain |
| Deskripsi hash terpotong di `diagnose sys scanunit file-hash list malware` (hilang bagian setelah nama sumber) | Bug pada versi sebelum 1.4.3 — FortiOS memotong field description begitu bertemu byte non-ASCII pertama; pemisah em-dash `—` lama menyebabkan ini. Perbarui ke versi terbaru — komentar sekarang selalu murni ASCII (`Sumber - Reputasi`, pemisah tanda hubung biasa) |

### Menguji hash benar-benar aktif di FortiGate

1. **GUI**: buka konektor external-resource, tekan **View Entries** — semua baris harus berstatus **Valid** dan jumlah **Accepted** sesuai jumlah hash yang ditarik.
2. **CLI, verifikasi paling andal** — konfirmasi scanunit daemon (bukan cuma GUI konfigurasi) benar-benar memuat hash-nya:
   ```
   diagnose sys scanunit file-hash list malware
   ```
   Cari baris dengan `profile '<nama-konektor-Anda>'` — kalau hash Anda muncul di situ lengkap dengan `description`, feed sudah aktif dipakai untuk deteksi, bukan cuma tervalidasi di layar konfigurasi.
3. **Aktifkan di AV profile** (wajib, feed tidak otomatis dipakai hanya karena entrinya valid):
   ```
   config antivirus profile
       edit "nama_profile_anda"
           config outbreak-prevention
               set external-blocklist "nama-konektor-Anda"
           end
       next
   end
   ```
   lalu pastikan profil AV itu terpasang di firewall policy (dengan SSL deep-inspection aktif untuk trafik HTTPS).

Hash sungguhan dari feed threat-intel adalah sampel malware nyata — tidak ada cara aman untuk memicu deteksinya tanpa benar-benar mengirim file berbahaya lewat policy, dan file uji standar seperti EICAR tidak akan cocok (hash-nya berbeda). Verifikasi lewat `diagnose sys scanunit file-hash list malware` di atas adalah cara paling realistis untuk memastikan feed aktif; kejadian blokir sungguhan nanti bisa dipantau di **Log & Report → Security Events → AntiVirus**.

## Pengujian

```bash
bash tests/soar-taxii.sh
```

31 skenario terhadap server TAXII 2.1 tiruan: auth benar/salah, parsing pattern STIX
untuk keempat jenis (`ipv4-addr`/`domain-name`/`file:hashes`/`url`), **pemetaan field
bentuk asli FortiSOAR (`reputation`/`source`/`tLP`) ke tipe/severity/source/comment/tlp**,
**koleksi campuran IP+hash+domain+URL yang semuanya harus tertarik dengan `ioc_type`
benar** (reproduksi persis dari log dan payload produksi Anda, termasuk indikator URL
`https://t.me/...` dari FortiGuard Outbreak), **feed FortiGate IP/domain/hash/URL yang
harus terisolasi tanpa bocor silang**, **penjaga cursor macet yang berhenti begitu
`next` terdeteksi tidak maju, bukan menghabiskan seluruh `page_limit`**, **komentar
feed hash murni ASCII sehingga tidak terpotong `diagnose sys scanunit file-hash list
malware` di FortiOS**, filter `?ioc_type=`, paginasi dua halaman, isolasi cursor
antar-koleksi, proteksi sesi pada ketiga endpoint admin, cakupan jejak audit, **opsi
"Tarik ulang semua" (`full_history`) yang benar-benar melewati cursor**, plus: menarik
banyak koleksi dalam satu panggilan (`collection_ids`), kegagalan sebagian yang tidak
menyembunyikan hasil yang berhasil,
kegagalan total yang melapor 502 alih-alih sukses parsial palsu, dan status koleksi
ad-hoc yang belum tersimpan ke `.env` (`?ids=`).
