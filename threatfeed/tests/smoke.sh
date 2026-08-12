#!/usr/bin/env bash
# Uji end-to-end: ingest (rich + simple), dedup, feed FortiGate, auth, dashboard.
set -u
cd "$(dirname "$0")/.."

export TF_DB_PATH=${TF_DB_PATH:-/tmp/tf_smoke.db}
export TF_INGEST_TOKENS=soar-test-token
export TF_FEED_TOKENS=fgt-test-token
export TF_ADMIN_PASSWORD=admin123
export TF_SECRET_KEY=0123456789abcdef0123456789abcdef
export TF_COOKIE_SECURE=false
export TF_TTL_DAYS=30

rm -f "$TF_DB_PATH"*
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8899 --log-level warning &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in $(seq 1 40); do curl -sf localhost:8899/healthz >/dev/null && break; sleep 0.25; done

B="Authorization: Bearer soar-test-token"    # token ingest
BF="Authorization: Bearer fgt-test-token"     # token feed
J="Content-Type: application/json"
pp() { python3 -m json.tool 2>/dev/null || cat; }

echo "== 1. Rich payload FortiSOAR (object entries) =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" -d '{
 "commands":[{"name":"FortiSOAR_Threat_Feeds-IP-01","command":"add","entries":[
  {"ip":"103.74.20.57","type":"Malware","severity":"Malicious","confidence":100,"tlp":"TLP:RED","source":"FortiSOAR Playbook","comment":"C2 Server detected during automated incident response"},
  {"ip":"45.155.205.233","type":"Bruteforce","severity":"High","confidence":85,"tlp":"TLP:AMBER","source":"FortiSOAR","comment":"SSH brute force"},
  {"ip":"185.220.101.0/24","type":"Tor Exit","severity":"Medium","confidence":60,"tlp":"tlp:green","source":"OSINT"},
  {"ip":"192.0.2.10-192.0.2.50","type":"Scanner","severity":"Low","confidence":"40%","tlp":"CLEAR"}]}]}' | pp

echo; echo "== 2. Array of strings (payload sederhana) =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" \
  -d '["8.8.4.4","1.1.1.1","103.74.20.57"]' | pp

echo; echo "== 3. Payload bengkok: IP invalid, loopback, duplikat, IPv6, key 'value' =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" \
  -d '{"entries":["999.1.1.1","127.0.0.1","8.8.4.4","8.8.4.4",{"value":"2001:db8::1","severity":"critical","comment":"IPv6 C2"}]}' | pp

echo; echo "== 4. Upsert: severity/confidence/comment berubah, TIDAK menambah baris =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" -d '{
 "commands":[{"name":"FortiSOAR_Threat_Feeds-IP-01","command":"add","entries":[
  {"ip":"103.74.20.57","type":"Malware","severity":"Critical","confidence":95,"tlp":"TLP:RED","source":"FortiSOAR Playbook","comment":"Re-confirmed via sandbox detonation"}]}]}' | pp

echo; echo "== 5. Command delete (revoke) =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" \
  -d '{"commands":[{"name":"FortiSOAR_Threat_Feeds-IP-01","command":"delete","entries":["1.1.1.1"]}]}' | pp

echo; echo "== 6. Auth negatif: token salah / tanpa token =="
echo -n "  token salah -> "; curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8899/api/v1/ingest -H "Authorization: Bearer salah" -H "$J" -d '[]'
echo -n "  tanpa token -> "; curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8899/api/v1/ingest -H "$J" -d '[]'
echo -n "  feed tanpa token -> "; curl -s -o /dev/null -w "%{http_code}\n" localhost:8899/api/v1/feed/fortigate

echo; echo "== 7. Feed FortiGate — DEFAULT tanpa query string (harus IP murni) =="
curl -s "localhost:8899/api/v1/feed/fortigate" -H "Authorization: Bearer fgt-test-token"

echo "== 8. Feed FortiGate — ?comments=true (komentar inline) =="
curl -s "localhost:8899/api/v1/feed/fortigate?comments=true" -H "Authorization: Bearer fgt-test-token"

echo "== 9. Path alias /clean dan .txt harus identik dengan default =="
# Nama F1..F4, bukan A..D: variabel B dipakai sebagai header Authorization di
# seluruh skrip, dan menimpanya di sini membuat semua request setelahnya rusak.
F1=$(curl -s "localhost:8899/api/v1/feed/fortigate"            -H "$BF")
F2=$(curl -s "localhost:8899/api/v1/feed/fortigate/clean"      -H "$BF")
F3=$(curl -s "localhost:8899/api/v1/feed/fortigate.txt"        -H "$BF")
F4=$(curl -s "localhost:8899/api/v1/feed/fortigate?clean=true" -H "$BF")
[[ "$F1" == "$F2" && "$F1" == "$F3" && "$F1" == "$F4" ]] && echo "  OK - keempatnya identik" || echo "  GAGAL - output berbeda"
echo -n "  tidak ada baris komentar? -> "; grep -c '^#' <<<"$F1" || true

echo "== 10. Feed terfilter: severity=Malicious,Critical =="
curl -s "localhost:8899/api/v1/feed/fortigate?severity=Malicious,Critical" -H "Authorization: Bearer fgt-test-token"

echo "== 11. Basic auth (mode 'set username/password' FortiGate) + ETag/304 =="
ET=$(curl -s -D- -o /dev/null -u fgt:fgt-test-token "localhost:8899/api/v1/feed/fortigate" | awk '/[Ee][Tt]ag/{print $2}' | tr -d '\r')
echo "  ETag=$ET"
echo -n "  If-None-Match -> "; curl -s -o /dev/null -w "%{http_code}\n" -u fgt:fgt-test-token -H "If-None-Match: $ET" "localhost:8899/api/v1/feed/fortigate"

echo; echo "== 12. Dashboard: login + stats + search =="
curl -s -c /tmp/tf.jar -X POST localhost:8899/api/v1/auth/login -H "$J" -d '{"password":"admin123"}' | pp
curl -s -b /tmp/tf.jar localhost:8899/api/v1/stats | python3 -c "import json,sys;d=json.load(sys.stdin);print({k:d[k] for k in ('total','active','in_feed','revoked','added_24h','ttl_days')});print('by_tlp',d['by_tlp'])"
echo -n "  search q=C2 -> "; curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?q=C2" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['total'],[i['ip_address']+'/'+i['severity']+'/'+str(i['confidence']) for i in d['items']])"
echo -n "  filter tlp=TLP:RED -> "; curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?tlp=TLP:RED" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['total'])"
echo -n "  stats tanpa cookie -> "; curl -s -o /dev/null -w "%{http_code}\n" localhost:8899/api/v1/stats

echo; echo "== 13. Audit trail =="
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/audit?limit=6" | python3 -c "
import json,sys
for a in json.load(sys.stdin)['items']:
    print(f\"  {a['ts']} {a['action']:<12} {a['actor'][:22]:<22} ok={a['entries_ok']:<3} fail={a['entries_fail']:<3} {a['status_code']} {a['duration_ms']}ms\")"

echo; echo "== 14. TTL: mundurkan updated_at 40 hari lalu jalankan pruning =="
python3 - <<'PY'
import sqlite3, os
c = sqlite3.connect(os.environ["TF_DB_PATH"])
c.execute("UPDATE indicators SET updated_at='2026-01-01T00:00:00Z' WHERE ip_address='8.8.4.4'")
c.commit()
PY
echo -n "  8.8.4.4 masih di feed? -> "; curl -s "localhost:8899/api/v1/feed/fortigate" -H "Authorization: Bearer fgt-test-token" | grep -c '^8.8.4.4$'
curl -s -b /tmp/tf.jar -X POST localhost:8899/api/v1/maintenance/prune | pp
echo -n "  status setelah pruning -> "; curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?q=8.8.4.4" | python3 -c "import json,sys;print([ (i['ip_address'],i['status']) for i in json.load(sys.stdin)['items']])"

echo; echo "== 15. Injeksi baris lewat komentar (CRLF) harus dinetralkan =="
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" \
  -d '{"entries":[{"ip":"198.51.100.7","comment":"jahat\n0.0.0.0/0\n# injected"}]}' >/dev/null
curl -s "localhost:8899/api/v1/feed/fortigate?comments=true" -H "Authorization: Bearer fgt-test-token" | grep -E '198.51.100.7|0.0.0.0'

echo; echo "== SELESAI =="

echo; echo "== 16. Path /annotated — format default 'plain' (kolom comment saja) =="
curl -s "localhost:8899/api/v1/feed/fortigate/annotated" -H "Authorization: Bearer fgt-test-token" | sed -n '3,8p'
echo "  --- entri tanpa comment harus tampil polos, tanpa '#' menggantung ---"
curl -s "localhost:8899/api/v1/feed/fortigate/annotated" -H "Authorization: Bearer fgt-test-token" | grep -E '^(8\.8\.4\.4|185\.220)' 
echo "  --- /clean harus tetap murni ---"
curl -s "localhost:8899/api/v1/feed/fortigate/clean" -H "Authorization: Bearer fgt-test-token" | sed -n '1,2p'

echo; echo "== 17. Integrasi webhook pihak ketiga (FortiDeceptor) =="
# Satu baris: baris baru mentah di dalam body membuat uvicorn menolaknya
# sebagai "Invalid HTTP request".
FD_PAYLOAD='{"incident":{"id":"FD-2026-001","attacker":{"ipv4":"198.51.100.77"},"sensor":{"ip":"192.168.110.9"},"severity":"high","event":"SMB lure triggered"}}'

echo -n "  a. tanpa ?deep -> "
curl -s -o /dev/null -w "%{http_code} (400 = benar, format tak dikenal)\n" \
  -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" -d "$FD_PAYLOAD"

echo "  b. /echo membedah payload:"
curl -s -X POST localhost:8899/api/v1/ingest/echo -H "$B" -H "$J" -d "$FD_PAYLOAD" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('     detected_ips =',d['detected_ips'])"

echo "  c. block via path + ?deep + metadata dari query string:"
curl -s -X POST "localhost:8899/api/v1/ingest/block?deep=true&source=FortiDeceptor&type=Deception&severity=Malicious&confidence=90&tlp=TLP:AMBER&feed_name=FortiDeceptor&comment=Lure%20triggered" \
  -H "$B" -H "$J" -d "$FD_PAYLOAD" | pp

echo "  d. entri yang tersimpan:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?q=198.51.100.77" \
  | python3 -c "
import json,sys
for i in json.load(sys.stdin)['items']:
    print(f\"     {i['ip_address']} {i['type']} {i['severity']}/{i['confidence']} {i['tlp']} src={i['source']} feed={i['feed_name']} status={i['status']}\")"

echo "  e. unblock via path (tanpa mengubah body):"
curl -s -X POST "localhost:8899/api/v1/ingest/unblock?deep=true" -H "$B" -H "$J" -d "$FD_PAYLOAD" \
  | python3 -c "import json,sys;print('     revoked =',json.load(sys.stdin)['revoked'])"

echo "  f. status setelah unblock:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?q=198.51.100.77" \
  | python3 -c "import json,sys;print('    ',[(i['ip_address'],i['status']) for i in json.load(sys.stdin)['items']])"

echo -n "  g. IP sensor TIDAK ikut tersimpan -> "
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/indicators?q=192.168.110.9" \
  | python3 -c "import json,sys;print('benar' if json.load(sys.stdin)['total']==0 else 'SALAH - ikut tersimpan')"

echo; echo "== 18. Pengaturan lewat dashboard =="
echo -n "  a. GET tanpa sesi -> "
curl -s -o /dev/null -w "%{http_code} (401 = benar)\n" localhost:8899/api/v1/settings

echo "  b. nilai awal (asal .env):"
curl -s -b /tmp/tf.jar localhost:8899/api/v1/settings | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d['settings']:
    if s['key'] in ('TF_TTL_DAYS','TF_FEED_COMMENT_FORMAT','TF_INGEST_ALLOWED_CIDRS'):
        print(f\"     {s['key']:<26} = {s['value']:<22} (asal: {s['source']})\")
print('     kunci rahasia yang ditolak:', len(d['readonly_keys']))"

echo "  c. validasi menolak nilai buruk (semua-atau-tidak):"
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_TTL_DAYS":"9999999","TF_FEED_COMMENT_FORMAT":"ngawur"}}' \
  | python3 -c "import json,sys;print('    ',json.load(sys.stdin)['detail'][:150])"

echo -n "  d. token TIDAK boleh diubah lewat dashboard -> "
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_INGEST_TOKENS":"token-jahat"}}' \
  | python3 -c "import json,sys;print('ditolak:', json.load(sys.stdin)['detail'][:80])"

echo -n "  e. TTL diubah jadi 1 hari lalu berlaku SEKETIKA -> "
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_TTL_DAYS":"1"}}' >/dev/null
python3 - <<'PY'
import sqlite3, os
c = sqlite3.connect(os.environ["TF_DB_PATH"])
c.execute("UPDATE indicators SET updated_at='2026-08-05T00:00:00Z' WHERE ip_address='1.1.1.1'")
c.execute("UPDATE indicators SET status='active' WHERE ip_address='1.1.1.1'")
c.commit()
PY
BEFORE=$(curl -s "localhost:8899/api/v1/feed/fortigate/clean" -H "$BF" | grep -c '^1\.1\.1\.1$' || true)
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" -d '{"changes":{"TF_TTL_DAYS":"3650"}}' >/dev/null
AFTER=$(curl -s "localhost:8899/api/v1/feed/fortigate/clean" -H "$BF" | grep -c '^1\.1\.1\.1$' || true)
[[ "$BEFORE" == "0" && "$AFTER" == "1" ]] && echo "benar (TTL 1 hari: tersembunyi, TTL 3650: muncul, tanpa restart)" \
  || echo "GAGAL (before=$BEFORE after=$AFTER)"

echo -n "  f. loopback dipertahankan otomatis di allowlist -> "
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_FEED_ALLOWED_CIDRS":"10.99.0.0/16"}}' \
  | python3 -c "import json,sys;v=json.load(sys.stdin)['values']['TF_FEED_ALLOWED_CIDRS'];print('benar:' if '127.0.0.1/32' in v else 'GAGAL:', v)"

echo -n "  g. feed masih bisa ditarik dari loopback setelah allowlist dipersempit -> "
curl -s -o /dev/null -w "%{http_code}\n" "localhost:8899/api/v1/feed/fortigate/clean" -H "$BF"

echo -n "  h. CIDR tidak valid ditolak -> "
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_FEED_ALLOWED_CIDRS":"bukan-cidr"}}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['detail'][:70])"

echo "  i. reset mengembalikan ke nilai .env:"
curl -s -b /tmp/tf.jar -X POST localhost:8899/api/v1/settings/reset -H "$J" -d '{"changes":{}}' \
  | python3 -c "import json,sys;print('     dibuang:',json.load(sys.stdin)['reset'])"
curl -s -b /tmp/tf.jar localhost:8899/api/v1/settings | python3 -c "
import json,sys
for s in json.load(sys.stdin)['settings']:
    if s['key'] in ('TF_TTL_DAYS','TF_FEED_ALLOWED_CIDRS'):
        print(f\"     {s['key']:<26} = {s['value']:<22} (asal: {s['source']})\")"

echo -n "  j. sesi dashboard tetap hidup setelah reset -> "
curl -s -o /dev/null -w "%{http_code} (200 = benar)\n" -b /tmp/tf.jar localhost:8899/api/v1/stats

echo -n "  k. perubahan tercatat di audit -> "
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/audit?limit=30" \
  | python3 -c "
import json,sys
a=[x for x in json.load(sys.stdin)['items'] if x['action'].startswith('settings')]
print(f\"{len(a)} entri: {sorted(set(x['action'] for x in a))}\")"

echo; echo "== 19. Pengaturan bertahan setelah service restart =="
curl -s -b /tmp/tf.jar -X PUT localhost:8899/api/v1/settings -H "$J" \
  -d '{"changes":{"TF_TTL_DAYS":"77","TF_FEED_COMMENT_FORMAT":"full"}}' >/dev/null
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8899 --log-level warning &
SRV=$!
for i in $(seq 1 40); do curl -sf localhost:8899/healthz >/dev/null && break; sleep 0.25; done
echo -n "  TTL setelah restart -> "
curl -s "localhost:8899/api/v1/feed/fortigate?comments=true" -H "$BF" | sed -n 2p
echo -n "  format komentar setelah restart -> "
curl -s "localhost:8899/api/v1/feed/fortigate/annotated" -H "$BF" | sed -n 3p
curl -s -c /tmp/tf.jar -X POST localhost:8899/api/v1/auth/login -H "$J" -d '{"password":"admin123"}' >/dev/null
curl -s -b /tmp/tf.jar -X POST localhost:8899/api/v1/settings/reset -H "$J" -d '{"changes":{}}' >/dev/null
echo "  (override dibersihkan kembali)"

echo; echo "== 20. Username feed FortiGate + generator snippet =="
echo -n "  a. TF_FEED_USERNAME kosong: username apa pun diterima -> "
curl -s -o /dev/null -w "%{http_code}\n" -u "siapasaja:fgt-test-token" "localhost:8899/api/v1/feed/fortigate/clean"
echo -n "  b. Bearer tetap jalan tanpa username -> "
curl -s -o /dev/null -w "%{http_code}\n" -H "$BF" "localhost:8899/api/v1/feed/fortigate/clean"
echo "  c. snippet CLI (token disamarkan):"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/admin/fortigate-snippet" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'detail' in d: print('    ',str(d['detail'])[:70])
else:
    print('\n'.join('     '+l for l in d['snippet'].splitlines()))
    print('     token_revealed =', d['token_revealed'])
    for n in d['notes']: print('     catatan:', n[:80])"

echo "  d. parameter type pada snippet:"
for T in address domain malware mac-address category; do
  curl -s -b /tmp/tf.jar "localhost:8899/api/v1/admin/fortigate-snippet?type=$T&category=200" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
lines=[l.strip() for l in d['snippet'].splitlines() if l.strip().startswith(('set type','set category'))]
warn=[n for n in d['notes'] if 'hanya menghasilkan daftar alamat IP' in n or 'Nomor kategori' in n]
print(f\"     {d['type']:<12} {' | '.join(lines):<38} peringatan={len(warn)}\")"
done
echo -n "  e. type ngawur jatuh ke address -> "
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/admin/fortigate-snippet?type=ngawur" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['type'])"
echo -n "  f. category di luar rentang ditolak -> "
curl -s -o /dev/null -w "%{http_code} (422 = benar)\n" -b /tmp/tf.jar \
  "localhost:8899/api/v1/admin/fortigate-snippet?type=category&category=999"

echo; echo "== 21. Filter type pada feed + case-insensitive =="
echo -n "  a. ?type=Malware (persis)            -> "
curl -s "localhost:8899/api/v1/feed/fortigate?type=Malware" -H "$BF" | grep -c . || true
echo -n "  b. ?type=malware (huruf kecil)       -> "
curl -s "localhost:8899/api/v1/feed/fortigate?type=malware" -H "$BF" | grep -c . || true
echo -n "  c. ?severity=high (huruf kecil)      -> "
curl -s "localhost:8899/api/v1/feed/fortigate?severity=high" -H "$BF" | grep -c . || true
echo -n "  d. ?tlp=tlp:red (huruf kecil)        -> "
curl -s "localhost:8899/api/v1/feed/fortigate?tlp=tlp:red" -H "$BF" | grep -c . || true
echo -n "  e. gabungan type+severity            -> "
curl -s "localhost:8899/api/v1/feed/fortigate?type=malware&severity=critical" -H "$BF" | grep -c . || true
echo -n "  f. filter salah ketik = feed kosong  -> "
curl -s "localhost:8899/api/v1/feed/fortigate?type=ngawur" -H "$BF" | grep -c . || true

echo "  g. snippet dengan filter type + peringatan feed kosong:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/admin/fortigate-snippet?indicator_type=malware&severity=critical" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('     resource :', [l.strip() for l in d['snippet'].splitlines() if 'set resource' in l][0][:100])
print('     matched  :', d['matched'])"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/admin/fortigate-snippet?indicator_type=tidakada" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('     matched  :', d['matched'])
for n in d['notes']:
    if 'KOSONG' in n: print('     peringatan:', n[:75])"

echo; echo "== 22. Ekspor CSV / JSON / backup database =="
echo -n "  a. tanpa sesi -> "
curl -s -o /dev/null -w "%{http_code} (401 = benar)\n" "localhost:8899/api/v1/export/indicators"

echo "  b. CSV — header, jumlah baris, dan nama berkas:"
curl -s -D /tmp/hdr.txt -b /tmp/tf.jar "localhost:8899/api/v1/export/indicators?format=csv" -o /tmp/exp.csv
echo "     $(sed -n 1p /tmp/exp.csv)"
echo "     baris data: $(( $(grep -c . /tmp/exp.csv) - 1 ))"
grep -i 'content-disposition\|x-export-rows' /tmp/hdr.txt | sed 's/^/     /' | tr -d '\r'

echo "  c. CSV mengikuti filter aktif (severity=Malicious):"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/export/indicators?format=csv&severity=Malicious" -o /tmp/exp2.csv
echo "     baris data: $(( $(grep -c . /tmp/exp2.csv) - 1 ))"

echo "  d. JSON valid dan bisa diparse:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/export/indicators?format=json" -o /tmp/exp.json
python3 -c "
import json
d=json.load(open('/tmp/exp.json'))
print(f'     {len(d)} objek, kunci: {sorted(d[0])[:6]}…' if d else '     kosong')"

echo "  e. Netralisasi formula injection pada CSV:"
curl -s -X POST localhost:8899/api/v1/ingest -H "$B" -H "$J" \
  -d '{"entries":[{"ip":"203.0.113.77","comment":"=HYPERLINK(\"http://jahat\",\"klik\")"}]}' >/dev/null
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/export/indicators?format=csv&q=203.0.113.77" -o /tmp/exp3.csv
grep '203.0.113.77' /tmp/exp3.csv | python3 -c "
import sys
line = sys.stdin.read()
raw = line.split(',')
cell = next((c for c in raw if 'HYPERLINK' in c), '')
print('     sel:', cell.strip()[:45])
print('     ✓ diawali kutip tunggal' if \"'=\" in cell else '     ✗ MASIH BISA DIEKSEKUSI SPREADSHEET')"

echo "  f. Ekspor jejak audit:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/export/audit?format=csv&limit=10" -o /tmp/aud.csv
echo "     $(sed -n 1p /tmp/aud.csv | cut -c1-70)"
echo "     baris: $(( $(grep -c . /tmp/aud.csv) - 1 ))"

echo "  g. Backup database — snapshot valid dan bisa dibuka:"
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/export/backup" -o /tmp/snap.db
python3 -c "
import sqlite3
c = sqlite3.connect('/tmp/snap.db')
n = c.execute('SELECT COUNT(*) FROM indicators').fetchone()[0]
a = c.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
import os; print(f'     {os.path.getsize(\"/tmp/snap.db\")} byte · {n} indikator · {a} entri audit')
print('     ✓ snapshot dapat dibuka sebagai database SQLite')"

echo -n "  h. ekspor tercatat di audit -> "
curl -s -b /tmp/tf.jar "localhost:8899/api/v1/audit?limit=20" | python3 -c "
import json,sys
acts=[a['action'] for a in json.load(sys.stdin)['items']]
print(f\"{acts.count('export')} export, {acts.count('backup_download')} backup_download\")"
