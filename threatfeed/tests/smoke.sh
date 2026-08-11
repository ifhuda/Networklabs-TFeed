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

B="Authorization: Bearer soar-test-token"
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
A=$(curl -s "localhost:8899/api/v1/feed/fortigate"       -H "Authorization: Bearer fgt-test-token")
B=$(curl -s "localhost:8899/api/v1/feed/fortigate/clean" -H "Authorization: Bearer fgt-test-token")
C=$(curl -s "localhost:8899/api/v1/feed/fortigate.txt"   -H "Authorization: Bearer fgt-test-token")
D=$(curl -s "localhost:8899/api/v1/feed/fortigate" -H "Authorization: Bearer fgt-test-token")
[[ "$A" == "$B" && "$A" == "$C" && "$A" == "$D" ]] && echo "  OK - keempatnya identik" || echo "  GAGAL - output berbeda"
echo -n "  tidak ada baris komentar? -> "; grep -c '^#' <<<"$A" || true

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
