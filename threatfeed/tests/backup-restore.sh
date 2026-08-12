#!/usr/bin/env bash
# Uji backup & pemulihan: jadwal, rotasi, validasi berkas, path traversal,
# konfirmasi password, dan pemulihan sungguhan lewat helper root tiruan.
set -uo pipefail
cd "$(dirname "$0")/.."

WORK=/tmp/bktest
rm -rf "$WORK"; mkdir -p "$WORK/backups"

export TF_DB_PATH="$WORK/threatfeed.db"
export TF_BACKUP_DIR="$WORK/backups"
export TF_INGEST_TOKENS=ingtok TF_FEED_TOKENS=fgttok
export TF_ADMIN_PASSWORD=RahasiaSekali12 TF_SECRET_KEY=abc123 TF_COOKIE_SECURE=false
export TF_BACKUP_ENABLED=true TF_BACKUP_KEEP=3
export TF_RESTORE_HELPER="$WORK/restore-db"

# Helper root tiruan: skrip asli dengan path diarahkan ke $WORK. Logika penukaran
# berkas, pembuangan -wal/-shm, dan snapshot pra-pulih diuji apa adanya.
sed -e "s|^DATA_DIR=.*|DATA_DIR=$WORK|" \
    -e "s|^APP_USER=.*|APP_USER=$(id -un)|" \
    -e 's|^\[\[ \$EUID -eq 0 \]\].*||' \
    -e 's|systemctl stop "\$UNIT"|true|g' \
    -e 's|! systemctl start "\$UNIT"|! true|g' \
    -e 's|systemctl start "\$UNIT"|true|g' \
    -e 's|chown "\$APP_USER":"\$APP_USER"|true |g' \
    deploy/threatfeed-restore-db > "$WORK/restore-db"
chmod +x "$WORK/restore-db"
bash -n "$WORK/restore-db" || { echo "HARNESS RUSAK: helper tiruan tidak valid"; exit 1; }

# Pengganti threatfeed-restore-db.path
watcher(){ while sleep 0.3; do
  [[ -f "$WORK/restore-pending.db" ]] && "$WORK/restore-db" || true
done; }
watcher >>"$WORK/watcher.log" 2>&1 & WATCHER=$!

PORT=8905
pkill -f "uvicorn app.main:app --host 127.0.0.1 --port $PORT" 2>/dev/null || true
sleep 0.5

start_srv(){
  python3 -m uvicorn app.main:app --host 127.0.0.1 --port $PORT --log-level error \
    >>"$WORK/srv.log" 2>&1 &
  SRV=$!
  for i in $(seq 1 40); do curl -sf localhost:$PORT/healthz >/dev/null && break; sleep 0.25; done
}
trap 'kill $SRV $WATCHER 2>/dev/null' EXIT
rm -f "$TF_DB_PATH"*
start_srv

U=http://127.0.0.1:$PORT; J='Content-Type: application/json'
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" -d '{"password":"RahasiaSekali12"}' >/dev/null
hr(){ printf '\n── %s\n' "$1"; }

curl -s -X POST $U/api/v1/ingest -H "Authorization: Bearer ingtok" -H "$J" \
  -d '{"entries":["203.0.113.1","203.0.113.2","203.0.113.3"]}' >/dev/null

hr "0. Prasyarat harness"
echo "   helper tiruan  : $TF_RESTORE_HELPER"
echo "   ada di disk    : $([[ -f $TF_RESTORE_HELPER ]] && echo ya || echo TIDAK)"
echo "   dilihat server : $(curl -s -b "$WORK/jar" $U/api/v1/backups | python3 -c 'import json,sys;print(json.load(sys.stdin)["stats"]["restore_available"])')"

hr "1. Jadwal backup otomatis terbaca"
curl -s -b "$WORK/jar" $U/api/v1/backups | python3 -c "
import json,sys; s=json.load(sys.stdin)['stats']
print(f\"   otomatis={s['enabled']} tiap {s['interval_hours']} jam · simpan {s['keep']} · \"
      f\"helper pemulihan={s['restore_available']}\")"

hr "2. Buat backup manual"
curl -s -b "$WORK/jar" -X POST $U/api/v1/backups | python3 -c "
import json,sys; d=json.load(sys.stdin); print(f\"   {d['name']} · {d['size']} byte\")"

hr "3. Rotasi menghormati TF_BACKUP_KEEP=3"
for i in 1 2 3 4; do sleep 1.1; curl -s -b "$WORK/jar" -X POST $U/api/v1/backups >/dev/null; done
curl -s -b "$WORK/jar" $U/api/v1/backups | python3 -c "
import json,sys; n=len(json.load(sys.stdin)['backups'])
print(f\"   tersisa {n} dari 5 dibuat — {'benar' if n==3 else 'SALAH'}\")"
# Titik pemulihan diambil SETELAH rotasi: backup pertama sudah ikut terbuang.
SNAP=$(curl -s -b "$WORK/jar" $U/api/v1/backups | python3 -c "import json,sys;print(json.load(sys.stdin)['backups'][0]['name'])")
echo "   titik pemulihan: $SNAP"

hr "4. Path traversal pada nama backup ditolak"
for BAD in "../../etc/passwd" "....//threatfeed.db" "bukan.txt"; do
  printf '   %-30s %s\n' "$BAD" \
    "$(curl -s -o /dev/null -w '%{http_code}' -b "$WORK/jar" "$U/api/v1/backups/$BAD")"
done

hr "5. Inspeksi berkas unggahan tanpa mengubah apa pun"
head -c 8192 /dev/urandom > "$WORK/sampah.db"
curl -s -b "$WORK/jar" -F "file=@$WORK/sampah.db" $U/api/v1/backups/inspect \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('   sampah acak :', d.get('valid'), '-', str(d.get('error',''))[:45])"
printf 'bukan sqlite sama sekali' > "$WORK/teks.db"
curl -s -b "$WORK/jar" -F "file=@$WORK/teks.db" $U/api/v1/backups/inspect \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('   berkas teks :', d.get('valid'), '-', str(d.get('error',''))[:45])"
cp "$WORK/backups/$SNAP" "$WORK/valid.db"
curl -s -b "$WORK/jar" -F "file=@$WORK/valid.db" $U/api/v1/backups/inspect \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(f\"   backup sah  : {d.get('valid')} - {d.get('indicators')} indikator, {d.get('audit_entries')} audit\")"

hr "6. Tambah data, lalu pastikan pemulihan mengembalikannya"
curl -s -X POST $U/api/v1/ingest -H "Authorization: Bearer ingtok" -H "$J" \
  -d '{"entries":["198.51.100.10","198.51.100.11","198.51.100.12","198.51.100.13"]}' >/dev/null
echo -n "   indikator sekarang: "
curl -s "$U/api/v1/feed/fortigate/clean" -H "Authorization: Bearer fgttok" | grep -c .

hr "7. Restore dengan password salah ditolak"
curl -s -o /dev/null -w "   %{http_code} (401 = benar)\n" -b "$WORK/jar" -X POST $U/api/v1/backups/restore \
  -H "$J" -d "{\"name\":\"$SNAP\",\"confirm_password\":\"salah\"}"

hr "8. Restore dengan password benar"
curl -s --max-time 90 -b "$WORK/jar" -X POST $U/api/v1/backups/restore -H "$J" \
  -d "{\"name\":\"$SNAP\",\"confirm_password\":\"RahasiaSekali12\"}" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('  ', str(d.get('message') or d.get('detail'))[:120])
r=d.get('restored') or {}
if r: print('   dipulihkan:', r.get('indicators'), 'indikator')"

hr "9. Database benar-benar kembali ke isi backup"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; start_srv
curl -s "$U/api/v1/feed/fortigate/clean" -H "Authorization: Bearer fgttok" | sed 's/^/   /'

hr "10. Snapshot pra-pulih tersimpan"
ls -1 "$WORK/backups" | grep -i "pre-restore" | sed 's/^/   /' || echo "   TIDAK ADA"

hr "11. Berkas -wal/-shm lama tidak tertinggal"
ls -1 "$WORK"/threatfeed.db* 2>/dev/null | sed 's/^/   /'

hr "11b. Pemulihan tercatat di database HASIL pemulihan"
sqlite3 "$WORK/threatfeed.db" \
  "SELECT '   ' || ts || '  ' || action || '  ' || substr(detail,1,52)
   FROM audit_log WHERE action='restore_applied' ORDER BY id DESC LIMIT 2;" 2>/dev/null \
  || echo "   TIDAK TERCATAT"

hr "12. Jejak audit"
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" -d '{"password":"RahasiaSekali12"}' >/dev/null
curl -s -b "$WORK/jar" "$U/api/v1/audit?limit=15" | python3 -c "
import json,sys
for a in json.load(sys.stdin)['items']:
    if a['action'].startswith(('backup','restore')):
        print(f\"   {a['action']:<18} {a['detail'][:58]}\")"
echo
