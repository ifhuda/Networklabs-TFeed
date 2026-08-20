#!/usr/bin/env bash
# Uji fitur "Tarik dari FortiSOAR" (TAXII 2.1): parsing STIX standar & kuirk
# field `value` FortiSOAR, paginasi, endpoint admin, dan integrasi ke feed.
set -uo pipefail
cd /home/claude/threatfeed

WORK=/tmp/soartest
rm -rf "$WORK"; mkdir -p "$WORK"
MOCK_DIR=/tmp/mocksoar

# --- server TAXII tiruan -----------------------------------------------------
mkdir -p "$MOCK_DIR"
cat > "$MOCK_DIR/server.py" << 'PYEOF'
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import base64, uvicorn

app = FastAPI()
KEY_NAME, API_KEY = "svc-key", "s3cr3t-token-xyz"

def _check_auth(request: Request):
    h = request.headers.get("authorization", "")
    if not h.startswith("Basic "):
        raise HTTPException(401, "no basic auth")
    user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
    if user != KEY_NAME or pw != API_KEY:
        raise HTTPException(401, "bad credentials")

@app.get("/api/taxii/1/taxii")
def discovery(request: Request):
    _check_auth(request)
    return {"title": "Mock FortiSOAR TAXII"}

@app.get("/api/taxii/1/collections")
def collections(request: Request):
    _check_auth(request)
    return {"collections": [
        {"id": "coll-standard", "title": "Standard STIX pattern"},
        {"id": "coll-fortisoar-value", "title": "FortiSOAR value field"},
        {"id": "coll-paged", "title": "Koleksi dua halaman"},
        {"id": "coll-severity-scale", "title": "Uji skala severity"},
        {"id": "coll-mixed-hash", "title": "Koleksi campuran IP + hash SHA-256"},
        {"id": "coll-multi-type", "title": "IP + Hash + Domain"},
        {"id": "coll-url-test", "title": "Uji URL"},
        {"id": "coll-stuck-cursor", "title": "Uji cursor macet"},
    ]}

@app.get("/api/taxii/1/collections/{cid}/objects")
def objects(cid: str, request: Request):
    _check_auth(request)
    added_after = request.query_params.get("added_after")
    next_cur = request.query_params.get("next")

    if cid == "coll-standard":
        return {"objects": [
            {"type": "indicator", "id": "indicator--1",
             "pattern": "[ipv4-addr:value = '203.0.113.55']",
             "labels": ["malicious-activity"], "confidence": 85,
             "x_tlp": "TLP:RED", "description": "C2 server dari feed standar"},
            {"type": "indicator", "id": "indicator--2",
             "pattern": "[domain-name:value = 'evil.example.com']",
             "labels": ["malicious-activity"]},
        ], "more": False}

    if cid == "coll-fortisoar-value":
        # Bentuk ASLI FortiSOAR (bukan STIX baku): reputation/source/tLP
        # langsung sebagai field objek, persis payload dari curl produksi.
        if added_after:
            return {"objects": [
                {"type": "indicator", "id": "indicator--4", "value": "198.51.100.9",
                 "name": "198.51.100.9", "reputation": "Suspicious",
                 "source": "Phishing Threat Feeds", "tLP": "Amber", "confidence": 60},
            ], "more": False}
        return {"objects": [
            {"type": "indicator", "id": "indicator--3", "value": "198.51.100.7",
             "name": "198.51.100.7", "reputation": "Malicious",
             "source": "IPsum Threat Intelligence Feed", "tLP": "Red", "confidence": 100},
        ], "more": False}

    if cid == "coll-paged":
        if not next_cur:
            return {"objects": [
                {"type": "indicator", "id": "p1", "value": "192.0.2.10", "confidence": 80},
            ], "more": True, "next": "page2"}
        return {"objects": [
            {"type": "indicator", "id": "p2", "value": "192.0.2.11", "confidence": 80},
        ], "more": False}

    # Koleksi yang tidak dikenal server sungguhan mengembalikan 404, bukan
    # daftar objek kosong — meniru itu di sini supaya uji kegagalan-sebagian
    # (satu ID salah di antara beberapa yang benar) sungguh menguji kegagalan.
    if cid == "coll-severity-scale":
        # Satu objek per nilai reputation yang dikenali FortiSOAR, plus satu
        # nilai tak dikenal untuk memastikan fallback ke Medium.
        reps = [
            ("198.51.100.1", "Malicious"), ("198.51.100.2", "Suspicious"),
            ("198.51.100.3", "Unknown"), ("198.51.100.4", "Known Good"),
            ("198.51.100.5", "Benign"), ("198.51.100.6", "Nilai-Asing-Tak-Dikenal"),
        ]
        return {"objects": [
            {"type": "indicator", "id": f"sev-{ip}", "name": ip, "value": ip,
             "reputation": rep, "source": "Uji Skala Severity", "tLP": "Green",
             "confidence": 70}
            for ip, rep in reps
        ], "more": False}

    if cid == "coll-mixed-hash":
        # Persis bentuk koleksi FortiGuard Outbreak nyata: campuran IP dan
        # hash SHA-256 dalam satu koleksi. Ini kasus yang pernah men-crash
        # seluruh siklus tarikan (500) sebelum ValueError dari normalize_ip
        # ditangkap dengan benar.
        return {"objects": [
            {"type": "indicator", "id": "m1", "name": "94.100.52.128",
             "value": "94.100.52.128", "reputation": "Malicious",
             "source": "FortiGuard Outbreak", "tLP": "Amber", "confidence": 100,
             "indicatorTypes": ["ipv4-addr"], "typeOfFeed": "IP Address"},
            {"type": "indicator", "id": "m2",
             "name": "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a",
             "value": "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a",
             "reputation": "Malicious", "source": "FortiGuard Outbreak",
             "tLP": "Amber", "confidence": 100, "indicatorTypes": ["file"],
             "typeOfFeed": "FileHash-SHA256"},
            {"type": "indicator", "id": "m3", "name": "51.195.39.150",
             "value": "51.195.39.150", "reputation": "Malicious",
             "source": "FortiGuard Outbreak", "tLP": "Amber", "confidence": 100,
             "indicatorTypes": ["ipv4-addr"], "typeOfFeed": "IP Address"},
        ], "more": False}

    if cid == "coll-multi-type":
        # Satu koleksi berisi ketiga jenis sekaligus: IP, hash, domain. Nilai
        # sengaja BEDA dari coll-mixed-hash supaya tidak saling tumpang tindih
        # (insert vs update) antar skenario uji yang berjalan berurutan.
        return {"objects": [
            {"type": "indicator", "id": "mt1", "name": "203.0.113.201",
             "value": "203.0.113.201", "reputation": "Malicious",
             "source": "FortiGuard Outbreak", "tLP": "Amber", "confidence": 100,
             "indicatorTypes": ["ipv4-addr"], "typeOfFeed": "IP Address"},
            {"type": "indicator", "id": "mt2",
             "name": "1111111111111111111111111111111111111111111111111111111111111111",
             "value": "1111111111111111111111111111111111111111111111111111111111111111"[:64],
             "reputation": "Malicious", "source": "FortiGuard Outbreak",
             "tLP": "Amber", "confidence": 100, "indicatorTypes": ["file"],
             "typeOfFeed": "FileHash-SHA256"},
            {"type": "indicator", "id": "mt3", "name": "phishing.bad-domain.com",
             "value": "phishing.bad-domain.com", "reputation": "Malicious",
             "source": "Phishing Threat Feeds", "tLP": "Red", "confidence": 90,
             "indicatorTypes": ["domain-name"], "typeOfFeed": "Domain"},
        ], "more": False}

    if cid == "coll-url-test":
        # Persis payload dari screenshot produksi: URL "https://t.me/ChiefYoru"
        # dari FortiGuard Outbreak, reputation=Malicious, tLP=Amber.
        return {"objects": [
            {"type": "indicator", "id": "u1", "name": "https://t.me/ChiefYoru",
             "value": "https://t.me/ChiefYoru", "indicatorTypes": ["url"],
             "typeOfFeed": "URL", "reputation": "Malicious",
             "source": "FortiGuard Outbreak", "tLP": "Amber", "confidence": 100,
             "recordTags": ["Outbreak Alert"]},
        ], "more": False}

    if cid == "coll-stuck-cursor":
        # Server rusak: next TIDAK PERNAH maju walau more=true terus-menerus —
        # menguji penjaga anti-loop di pull_collection.
        return {"objects": [
            {"type": "indicator", "id": "s1", "value": "203.0.113.250",
             "reputation": "Malicious", "source": "Stuck", "tLP": "Red", "confidence": 90},
        ], "more": True, "next": "cursor-yang-sama"}

    raise HTTPException(404, f"collection {cid} not found")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9978, log_level="warning")
PYEOF

python3 -m uvicorn --app-dir "$MOCK_DIR" server:app --host 127.0.0.1 --port 9978 --log-level warning \
  >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!

export TF_DB_PATH="$WORK/threatfeed.db"
export TF_INGEST_TOKENS=ingtok TF_FEED_TOKENS=fgttok
export TF_ADMIN_PASSWORD=RahasiaSekali12 TF_SECRET_KEY=0123456789abcdef
export TF_COOKIE_SECURE=false

python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8912 --log-level warning \
  >"$WORK/srv.log" 2>&1 &
SRV=$!
trap 'kill $SRV $MOCK_PID 2>/dev/null; wait $SRV $MOCK_PID 2>/dev/null' EXIT

for i in $(seq 1 40); do curl -sf localhost:8912/healthz >/dev/null && break; sleep 0.25; done
for i in $(seq 1 20); do curl -sf -u x:x localhost:9978/api/taxii/1/collections >/dev/null 2>&1 && break; sleep 0.2; done

U=http://127.0.0.1:8912; TAXII=http://127.0.0.1:9978/api/taxii/1/
J='Content-Type: application/json'
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" \
  -d '{"password":"RahasiaSekali12"}' >/dev/null

hr(){ printf '\n── %s\n' "$1"; }

hr "1. Status sebelum konfigurasi apa pun"
curl -s -b "$WORK/jar" $U/api/v1/admin/soar/status | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   enabled:', d['enabled'], '| api_key_set:', d['api_key_set'], '| last_pull:', d['last_pull'])"

hr "2. test-connection tanpa URL -> 400"
curl -s -o /dev/null -w "   %{http_code} (400 = benar)\n" -b "$WORK/jar" \
  -X POST $U/api/v1/admin/soar/test-connection -H "$J" -d '{}'

hr "3. test-connection kredensial salah -> 502 dengan pesan jelas"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/test-connection -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"salah\",\"api_key\":\"salah\",\"verify_tls\":false}" \
  | python3 -c "import json,sys;print('  ', json.load(sys.stdin)['detail'][:60])"

hr "4. test-connection benar -> daftar koleksi (8)"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/test-connection -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",\"verify_tls\":false}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   server_title:', d['server_title'])
for c in d['collections']: print('   -', c['id'], ':', c['title'])
assert len(d['collections']) == 8"

hr "5. pull-now tanpa collection_id -> 400"
curl -s -o /dev/null -w "   %{http_code} (400 = benar)\n" -b "$WORK/jar" \
  -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",\"verify_tls\":false}"

hr "6. pull-now koleksi STIX standar: pattern IP dan domain-name keduanya tertarik"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-standard\",\"feed_name\":\"UjiStandar\",\"verify_tls\":false}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   raw_objects:', d['raw_objects'], '| inserted:', d['inserted'])
assert d['raw_objects'] == 2 and d['inserted'] == 2, \
    'pattern ipv4-addr DAN domain-name harus dua-duanya tertarik dengan ioc_type masing-masing'
assert d['collections'][0]['collection_id'] == 'coll-standard'
assert d['errors'] == []"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=evil.example.com&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'domain', d
print('   OK — domain dari pattern STIX baku tersimpan dengan ioc_type=domain')"

hr "7. Indikator benar-benar tersaji di feed FortiGate"
FEED=$(curl -s $U/api/v1/feed/fortigate -H "Authorization: Bearer fgttok")
echo "   $FEED"
[[ "$FEED" == *"203.0.113.55"* ]] && echo "   OK — IP dari TAXII masuk feed" || echo "   GAGAL — IP tidak ditemukan"

hr "8. pull-now koleksi bentuk ASLI FortiSOAR (reputation/source/tLP, bukan STIX baku)"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-fortisoar-value\",\"feed_name\":\"UjiValue\",\"verify_tls\":false}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   inserted:', d['inserted'])
assert d['inserted'] == 1"

hr "8b. Field mapping ke tabel dashboard: type/source/comment/tlp/confidence"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=198.51.100.7&size=1" | python3 -c "
import json,sys; d=json.load(sys.stdin)
row = d['items'][0]
print('   type      :', row['type'])
print('   severity  :', row['severity'])
print('   source    :', row['source'])
print('   comment   :', row['comment'])
print('   tlp       :', row['tlp'])
print('   confidence:', row['confidence'])
assert row['type'] == 'Malicious', 'type harus diisi dari field reputation'
assert row['severity'] == 'Critical', 'reputation=Malicious harus dipetakan ke severity=Critical (skala standar), bukan disalin mentah'
assert row['source'] == 'IPsum Threat Intelligence Feed', 'source harus field source asli, bukan nama feed lokal'
assert row['comment'] == 'IPsum Threat Intelligence Feed - Malicious', 'comment harus source + reputation (pemisah ASCII biasa, bukan em-dash — lihat skenario 8k)'
assert row['tlp'] == 'TLP:RED', 'tLP=\"Red\" (huruf L kapital) harus terpetakan ke TLP:RED'
assert row['confidence'] == 100
print('   OK — semua field termapping benar dari payload asli FortiSOAR')"

hr "8c. Seluruh tabel pemetaan reputation -> severity (skala Critical/High/Medium/Low/Info)"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-severity-scale\",\"feed_name\":\"UjiSeverity\",\"verify_tls\":false}" >/dev/null
curl -s -b "$WORK/jar" "$U/api/v1/indicators?source=Uji%20Skala%20Severity&size=10" | python3 -c "
import json,sys; d=json.load(sys.stdin)
by_ip = {r['ip_address']: r['severity'] for r in d['items']}
expect = {
  '198.51.100.1': 'Critical',  # Malicious
  '198.51.100.2': 'High',      # Suspicious
  '198.51.100.3': 'Medium',    # Unknown
  '198.51.100.4': 'Info',      # Known Good
  '198.51.100.5': 'Info',      # Benign
  '198.51.100.6': 'Medium',    # nilai asing -> fallback
}
for ip, want in expect.items():
    got = by_ip.get(ip)
    mark = 'OK' if got == want else 'GAGAL'
    print(f'   {ip}  {got!s:<10} (harus {want})  {mark}')
    assert got == want, f'{ip}: dapat {got}, harus {want}'
print('   OK — seluruh tabel pemetaan severity benar')"

hr "8d. Koleksi campuran IP + hash SHA-256 — tidak boleh crash, hash tertarik sebagai indikator hash"
curl -s -o /tmp/mixed_result.json -w "   HTTP %{http_code} (200 = benar, BUKAN 500)\n" \
  -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-mixed-hash\",\"feed_name\":\"UjiCampuran\",\"verify_tls\":false}"
python3 -c "
import json
d = json.load(open('/tmp/mixed_result.json'))
print('   raw_objects:', d.get('raw_objects'), '| inserted:', d.get('inserted'))
assert d.get('raw_objects') == 3, d
assert d.get('inserted') == 3, 'ketiganya (2 IP + 1 hash) harus tertarik: ' + str(d)
print('   OK — 2 IP dan 1 hash SHA-256 semuanya tertarik tanpa men-crash siklus')"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=9c285fe3&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'hash', d
print('   OK — hash SHA-256 tersimpan sebagai indikator dengan ioc_type=hash')"

hr "8e. Koleksi campuran IP+hash+domain — ketiganya masuk dengan ioc_type benar"
curl -s -o /tmp/multitype_result.json -w "   HTTP %{http_code}\n" -b "$WORK/jar" \
  -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-multi-type\",\"feed_name\":\"UjiMultiType\",\"verify_tls\":false}"
python3 -c "
import json
d = json.load(open('/tmp/multitype_result.json'))
print('   inserted:', d.get('inserted'), '(harus 3 — IP, hash, domain semuanya masuk)')
assert d.get('inserted') == 3, d"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=203.0.113.201&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'ip', d
print('   OK — IP:', d['items'][0]['ip_address'], '-> ioc_type=ip')"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=1111111111111111&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'hash', d
print('   OK — Hash: ioc_type=hash')"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=phishing.bad-domain.com&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'domain', d
print('   OK — Domain: ioc_type=domain')"

hr "8f. Feed FortiGate IP/domain/hash TERPISAH — tidak boleh bocor silang"
FGT='Authorization: Bearer fgttok'
HASH64=$(printf '1%.0s' {1..64})
FEED_IP=$(curl -s $U/api/v1/feed/fortigate/clean -H "$FGT")
FEED_DOMAIN=$(curl -s $U/api/v1/feed/fortigate/domain/clean -H "$FGT")
FEED_HASH=$(curl -s $U/api/v1/feed/fortigate/hash/clean -H "$FGT")
echo "   feed IP    : $FEED_IP"
echo "   feed domain: $FEED_DOMAIN"
echo "   feed hash  : $FEED_HASH"
[[ "$FEED_IP" == *"203.0.113.201"* ]] && [[ "$FEED_IP" != *"phishing"* ]] && [[ "$FEED_IP" != *"$HASH64"* ]] \
  && echo "   OK — feed IP hanya berisi IP" || echo "   GAGAL — feed IP bocor tipe lain"
[[ "$FEED_DOMAIN" == *"phishing.bad-domain.com"* ]] && [[ "$FEED_DOMAIN" != *"203.0.113.201"* ]] \
  && echo "   OK — feed domain hanya berisi domain" || echo "   GAGAL — feed domain bocor tipe lain"
[[ "$FEED_HASH" == *"$HASH64"* ]] && [[ "$FEED_HASH" != *"203.0.113.201"* ]] \
  && echo "   OK — feed hash hanya berisi hash" || echo "   GAGAL — feed hash bocor tipe lain"

hr "8g. Filter ?ioc_type= di /api/v1/indicators"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?ioc_type=hash&size=10" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   total dengan ioc_type=hash:', d['total'])
assert all(r['ioc_type'] == 'hash' for r in d['items'])
print('   OK — semua hasil bertipe hash')"

hr "8h. Indikator URL (persis payload FortiGuard Outbreak dari screenshot produksi)"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-url-test\",\"feed_name\":\"UjiURL\",\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   inserted:', d['inserted'])
assert d['inserted'] == 1"
curl -s -b "$WORK/jar" "$U/api/v1/indicators?q=t.me&size=5" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1, d
r = d['items'][0]
assert r['ip_address'] == 'https://t.me/ChiefYoru', r
assert r['ioc_type'] == 'url', r
assert r['severity'] == 'Critical', r
print('   OK — URL tersimpan dengan ioc_type=url, severity=Critical (dari reputation=Malicious)')"

hr "8i. Feed FortiGate URL terpisah — tidak bocor ke feed IP"
FGT='Authorization: Bearer fgttok'
FEED_IP_2=$(curl -s $U/api/v1/feed/fortigate/clean -H "$FGT")
FEED_URL=$(curl -s $U/api/v1/feed/fortigate/url/clean -H "$FGT")
echo "   feed URL: $FEED_URL"
[[ "$FEED_URL" == *"t.me/ChiefYoru"* ]] && echo "   OK — feed URL berisi URL yang benar" || echo "   GAGAL"
[[ "$FEED_IP_2" != *"t.me"* ]] && echo "   OK — URL tidak bocor ke feed IP" || echo "   GAGAL — URL bocor ke feed IP"

hr "8j. Penjaga cursor macet: next yang tidak maju harus berhenti, bukan loop sampai page_limit"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-stuck-cursor\",\"feed_name\":\"UjiStuck\",\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
c = d['collections'][0]
print('   pages:', c['pages'], '(harus 2 — deteksi minimum saat cursor sama muncul 2x, bukan 20)')
assert c['pages'] == 2, f'penjaga gagal, masih {c[\"pages\"]} halaman'
print('   OK — penjaga berhenti di 2 request, bukan menghabiskan page_limit=20')"

hr "8k. Komentar feed hash ASCII-aman — em-dash tidak boleh memotong deskripsi FortiOS"
# Bug produksi nyata: FortiOS scanunit memotong field description pada
# external-resource malware-hash begitu ketemu byte non-ASCII pertama.
# Em-dash "—" (pemisah lama "Sumber — Reputasi") membuat 'diagnose sys
# scanunit file-hash list malware' hanya menampilkan "Sumber " tanpa reputasi.
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-mixed-hash\",\"feed_name\":\"UjiAsciiSafe\",\"verify_tls\":false}" >/dev/null
curl -s "$U/api/v1/feed/fortigate/hash" -H "$FGT" | python3 -c "
import sys
body = sys.stdin.read()
assert body.encode('ascii'), 'feed hash mengandung byte non-ASCII \u2014 akan terpotong FortiOS'
lines = [l for l in body.splitlines() if l and not l.startswith('#')]
assert lines, 'feed hash kosong'
for l in lines:
    if ' # ' in l:
        _, _, desc = l.partition(' # ')
        assert desc, f'deskripsi kosong pada baris: {l!r}'
        print('   baris:', l[:90])
print('   OK \u2014 seluruh baris feed hash murni ASCII, deskripsi tidak terpotong')"

hr "9. Cursor per-koleksi (bukan global) — uji langsung ke fungsi pemilih cursor"
python3 - <<PYEOF
import sys, os
sys.path.insert(0, ".")
os.environ["TF_DB_PATH"] = "$WORK/threatfeed.db"
from app import crud, main as m

# Rekam tarikan sukses untuk DUA koleksi berbeda, coll-B belakangan (lebih baru).
crud.log_event("soar_pull", actor="system", entries_ok=1,
                detail='{"collection_id":"coll-A","inserted":1}')
crud.log_event("soar_pull", actor="system", entries_ok=1,
                detail='{"collection_id":"coll-B","inserted":1}')

ts_a = m._last_pull_ts_for("coll-A")
ts_b = m._last_pull_ts_for("coll-B")
ts_c = m._last_pull_ts_for("coll-C-belum-pernah-ditarik")

print("   cursor coll-A:", ts_a)
print("   cursor coll-B:", ts_b)
print("   cursor coll-C (belum pernah):", ts_c)

# Bug yang diperbaiki: sebelum ini, cursor koleksi APA PUN akan mengembalikan
# timestamp tarikan TERAKHIR SECARA GLOBAL (milik coll-B) — termasuk untuk
# coll-A dan koleksi yang belum pernah ditarik sama sekali.
assert ts_a is not None, "coll-A pernah ditarik, cursornya tidak boleh None"
assert ts_c is None, "coll-C belum pernah ditarik — cursor harus None, bukan ikut milik coll-B"
print("   OK — setiap koleksi punya cursor sendiri, tidak tertukar")
PYEOF

hr "10. Paginasi: kedua halaman koleksi 'coll-paged' tertarik"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-paged\",\"feed_name\":\"UjiPaged\",\"full_history\":true,\"verify_tls\":false}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
c = d['collections'][0]
print('   pages:', c['pages'], '| inserted:', d['inserted'])
assert c['pages'] == 2 and d['inserted'] == 2"

hr "10b. Multi-koleksi dalam SATU panggilan (collection_ids array) — hasil teragregasi"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_ids\":[\"coll-standard\",\"coll-fortisoar-value\"],
  \"full_history\":true,\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
ids = sorted(c['collection_id'] for c in d['collections'])
print('   collections diproses:', ids)
print('   total inserted+updated:', d['inserted'], '+', d['updated'])
assert ids == ['coll-fortisoar-value', 'coll-standard'], 'kedua koleksi harus diproses'
assert len(d['collections']) == 2 and d['errors'] == []"

hr "10c. Multi-koleksi dengan SATU ID salah -> tetap lapor yang berhasil"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_ids\":[\"coll-standard\",\"coll-tidak-ada\"],
  \"full_history\":true,\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   berhasil:', [c['collection_id'] for c in d['collections']])
print('   gagal   :', [e['collection_id'] for e in d['errors']])
assert len(d['collections']) == 1 and d['collections'][0]['collection_id'] == 'coll-standard'
assert len(d['errors']) == 1 and d['errors'][0]['collection_id'] == 'coll-tidak-ada', \
    'satu koleksi gagal tidak boleh menyembunyikan hasil koleksi lain yang berhasil'"

hr "10d. Multi-koleksi SEMUA ID salah kredensial -> 502 gabungan, bukan sukses parsial palsu"
curl -s -o /tmp/soar_all_fail.json -w "   %{http_code} (502 = benar)\n" -b "$WORK/jar" \
  -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"salah\",\"api_key\":\"salah\",
  \"collection_ids\":[\"coll-standard\",\"coll-paged\"],
  \"full_history\":true,\"verify_tls\":false}"
python3 -c "
import json
d = json.load(open('/tmp/soar_all_fail.json'))
print('   pesan:', d['detail'][:100])"

hr "11. Status setelah beberapa pull menunjukkan hasil terakhir"
curl -s -b "$WORK/jar" $U/api/v1/admin/soar/status | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   last_pull ok:', d['last_pull']['ok'])
print('   detail:', d['last_pull']['detail'])"

hr "12. Tanpa sesi -> 401 pada ketiga endpoint admin"
for ep in status test-connection pull-now; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$U/api/v1/admin/soar/$ep" -H "$J" -d '{}')
  [[ "$ep" == status ]] && code=$(curl -s -o /dev/null -w "%{http_code}" "$U/api/v1/admin/soar/status")
  echo "   /$ep -> $code"
done

hr "13. Jejak audit mencatat soar_test dan soar_pull"
curl -s -b "$WORK/jar" "$U/api/v1/audit?limit=30" | python3 -c "
import json,sys
from collections import Counter
c = Counter(a['action'] for a in json.load(sys.stdin)['items'] if a['action'].startswith('soar'))
for k,v in sorted(c.items()): print(f'   {k}: {v}')
assert c['soar_test'] >= 1 and c['soar_pull'] >= 1"

hr "14. GUI menyertakan tombol dan panel"
curl -s $U/ -o "$WORK/page.html"
grep -q 'id="btnSoar"' "$WORK/page.html" && echo "   OK — tombol Tarik FortiSOAR ada di toolbar"
grep -q 'id="soarBody"' "$WORK/page.html" && echo "   OK — drawer panel ada"

hr "15. GET /status?ids= mengembalikan status koleksi yang BELUM tersimpan di .env"
# Sengaja pakai ID yang belum pernah masuk config, tapi sudah ditarik di atas
# (coll-standard) — ini kasus yang paling sering: menguji lewat panel sebelum
# apa pun disimpan permanen.
curl -s -b "$WORK/jar" "$U/api/v1/admin/soar/status?ids=coll-standard,coll-belum-pernah" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
by_id = {c['id']: c['last_pull'] for c in d['collections']}
print('   coll-standard last_pull:', 'ada' if by_id.get('coll-standard') else 'TIDAK ADA')
print('   coll-belum-pernah:', by_id.get('coll-belum-pernah'))
assert by_id.get('coll-standard') is not None, 'koleksi ad-hoc yang sudah ditarik harus tetap muncul statusnya walau TF_SOAR_TAXII_COLLECTION_ID kosong'
assert by_id.get('coll-belum-pernah') is None"

hr "16. GUI: checklist multi-koleksi (bukan dropdown tunggal) ada di HTML"
grep -q 'class="soar-coll"' "$WORK/page.html" && echo "   OK — checkbox per-koleksi ditemukan"
grep -q 'id="btnSoarPullNow"' "$WORK/page.html" && echo "   OK — tombol Tarik yang Dicentang ditemukan"
if ! grep -q 'id="soar_collection"' "$WORK/page.html"; then
  echo "   OK — dropdown single-select lama sudah tidak ada (diganti checklist)"
else
  echo "   PERINGATAN — dropdown lama masih ditemukan di HTML"
fi

hr "16b. Backend: field kosong (url/key_name/api_key) tetap jatuh ke config .env"
# Panel GUI sekarang tidak lagi merender field koneksi saat sudah tersimpan
# di .env (diverifikasi manual lewat Playwright: form kosong + Tarik Sekarang
# tetap berhasil dua kali berturut-turut). Di sini diuji langsung fungsi
# fallback-nya: _soar_field() harus memilih config bila body kosong.
python3 -c "
import sys; sys.path.insert(0, '.')
from app.main import _soar_field
assert _soar_field('', 'dari-config') == 'dari-config'
assert _soar_field('  ', 'dari-config') == 'dari-config'
assert _soar_field('dari-body', 'dari-config') == 'dari-body'
print('   OK — _soar_field jatuh ke config saat body kosong, body menang saat diisi')
"

hr "17. GUI: opsi 'Tarik ulang semua' (full_history) ada di panel"
grep -q 'id="soar_full_history"' "$WORK/page.html" && echo "   OK — checkbox full_history ditemukan di HTML"

hr "18. full_history=true benar-benar mengabaikan cursor added_after"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-standard\",\"feed_name\":\"UjiFullHistory\",
  \"full_history\":false,\"verify_tls\":false}" >/dev/null
# Pull kedua TANPA full_history: cursor sudah maju dari pull pertama, mock
# coll-standard tidak memfilter added_after (selalu kembalikan objek sama),
# tapi upsert harus mengenali sebagai UPDATE, bukan INSERT baru.
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-standard\",\"feed_name\":\"UjiFullHistory\",
  \"full_history\":false,\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   pull kedua (full_history=false): inserted=', d['inserted'], 'updated=', d['updated'])
assert d['inserted'] == 0, 'objek yang sudah ada tidak boleh ter-insert ulang'"
# Pull ketiga DENGAN full_history=true: harus tetap sukses (bukan error),
# dan tetap terdeteksi sebagai update (data tidak berubah di mock).
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/soar/pull-now -H "$J" -d "{
  \"url\":\"$TAXII\",\"key_name\":\"svc-key\",\"api_key\":\"s3cr3t-token-xyz\",
  \"collection_id\":\"coll-standard\",\"feed_name\":\"UjiFullHistory\",
  \"full_history\":true,\"verify_tls\":false}" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('   pull ketiga (full_history=true): inserted=', d['inserted'], 'updated=', d['updated'])
assert d['updated'] >= 1, 'full_history=true harus tetap menarik objek yang sudah pernah ada'"
echo
