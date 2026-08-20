#!/usr/bin/env bash
# Uji init_db() terhadap database PRODUKSI LAMA sungguhan di disk — bukan
# skema kosong. Ini menangkap kelas bug yang sempat lolos ke produksi: index
# baru di SCHEMA yang dieksekusi lewat executescript() SEBELUM _migrate()
# sempat menambahkan kolom yang diindeks, membuat setiap server dengan
# database yang sudah ada gagal start dengan "no such column".
set -uo pipefail
cd /home/claude/threatfeed

WORK=/tmp/dbmigtest
rm -rf "$WORK"; mkdir -p "$WORK"

hr(){ printf '\n── %s\n' "$1"; }

hr "1. init_db() terhadap database lama sungguhan (skema sebelum ioc_type)"
python3 - <<'PY'
import sqlite3, sys, os, importlib
sys.path.insert(0, ".")

db_path = "/tmp/dbmigtest/old.db"
conn = sqlite3.connect(db_path)
conn.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE COLLATE NOCASE,
    type TEXT NOT NULL DEFAULT 'IP Address',
    severity TEXT NOT NULL DEFAULT 'Medium',
    confidence INTEGER NOT NULL DEFAULT 50,
    tlp TEXT NOT NULL DEFAULT 'TLP:AMBER',
    source TEXT NOT NULL DEFAULT 'FortiSOAR',
    comment TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    feed_name TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '', entries_ok INTEGER NOT NULL DEFAULT 0,
    entries_fail INTEGER NOT NULL DEFAULT 0, status_code INTEGER NOT NULL DEFAULT 200,
    duration_ms INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);
""")
conn.execute("INSERT INTO indicators (ip_address, first_seen, created_at, updated_at) "
            "VALUES ('103.74.20.57','x','x','x')")
conn.commit()
conn.close()

os.environ["TF_DB_PATH"] = db_path
from app import config, database
importlib.reload(config)
importlib.reload(database)

# Inilah panggilan PERSIS yang dijalankan lifespan() saat startup service.
# Test yang hanya memanggil _migrate() secara terisolasi TIDAK menangkap bug
# ini — bug-nya ada di urutan antara executescript(SCHEMA) dan _migrate().
database.init_db()
print("   OK — init_db() tidak error terhadap database lama")

conn2 = sqlite3.connect(db_path)
cols = [r[1] for r in conn2.execute("PRAGMA table_info(indicators)")]
assert "ioc_type" in cols, f"kolom ioc_type tidak ada: {cols}"
row = conn2.execute("SELECT ioc_type FROM indicators WHERE ip_address='103.74.20.57'").fetchone()
assert row[0] == "ip", f"data lama harus default ioc_type='ip', dapat: {row[0]}"
print("   OK — kolom ioc_type ditambahkan, data lama default ke 'ip'")

indexes = [r[1] for r in conn2.execute("PRAGMA index_list(indicators)")]
assert "idx_ind_ioc_type" in indexes, f"index tidak terbuat: {indexes}"
print("   OK — index idx_ind_ioc_type terbuat setelah migrasi")
PY
[[ $? -eq 0 ]] && echo "   LULUS" || { echo "   GAGAL"; exit 1; }

hr "2. init_db() kedua kali (restart service) terhadap database yang SUDAH bermigrasi"
python3 - <<'PY'
import sys, os, importlib
sys.path.insert(0, ".")
os.environ["TF_DB_PATH"] = "/tmp/dbmigtest/old.db"
from app import config, database
importlib.reload(config)
importlib.reload(database)
database.init_db()   # idempoten — service sering restart, migrasi tidak boleh error kedua kali
database.init_db()
print("   OK — init_db() dipanggil 3x total tanpa error (idempoten)")
PY
[[ $? -eq 0 ]] && echo "   LULUS" || { echo "   GAGAL"; exit 1; }

hr "3. init_db() pada instalasi BARU (database kosong dari nol)"
python3 - <<'PY'
import sqlite3, sys, os, importlib
sys.path.insert(0, ".")
os.environ["TF_DB_PATH"] = "/tmp/dbmigtest/fresh.db"
from app import config, database
importlib.reload(config)
importlib.reload(database)

database.init_db()
conn = sqlite3.connect("/tmp/dbmigtest/fresh.db")
cols = [r[1] for r in conn.execute("PRAGMA table_info(indicators)")]
assert "ioc_type" in cols
indexes = [r[1] for r in conn.execute("PRAGMA index_list(indicators)")]
assert "idx_ind_ioc_type" in indexes, \
    f"instalasi baru juga harus punya index ini, dapat: {indexes}"
print("   OK — instalasi baru: kolom dan index ioc_type keduanya ada")

database.init_db()
print("   OK — init_db() kedua kali pada instalasi baru: tidak error")
PY
[[ $? -eq 0 ]] && echo "   LULUS" || { echo "   GAGAL"; exit 1; }

hr "4. Server sungguhan bisa start dan melayani request terhadap database lama yang dimigrasikan"
rm -f /tmp/dbmigtest/old.db-wal /tmp/dbmigtest/old.db-shm
export TF_DB_PATH=/tmp/dbmigtest/old.db
export TF_INGEST_TOKENS=x TF_FEED_TOKENS=y
export TF_ADMIN_PASSWORD=RahasiaSekali12 TF_SECRET_KEY=abc TF_COOKIE_SECURE=false
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8930 --log-level warning \
  >/tmp/dbmigtest/srv.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
ok=0
for i in $(seq 1 40); do curl -sf localhost:8930/healthz >/dev/null && ok=1 && break; sleep 0.25; done
if [[ $ok -eq 1 ]]; then
  echo "   OK — service benar-benar start terhadap database lama yang bermigrasi"
  curl -s -c /tmp/dbmigtest/jar -X POST localhost:8930/api/v1/auth/login \
    -H 'Content-Type: application/json' -d '{"password":"RahasiaSekali12"}' >/dev/null
  curl -s -b /tmp/dbmigtest/jar "localhost:8930/api/v1/indicators?q=103.74.20.57" \
    | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert d['total'] == 1 and d['items'][0]['ioc_type'] == 'ip'
print('   OK — indikator lama terbaca via API dengan ioc_type=ip')"
else
  echo "   GAGAL — service tidak start, lihat log:"
  cat /tmp/dbmigtest/srv.log
  exit 1
fi
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
echo
