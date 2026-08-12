#!/usr/bin/env bash
# Uji halaman Konfigurasi Sistem: parser .env, validasi, staging, helper root,
# konfirmasi password, dan penulisan berkas yang mempertahankan komentar.
set -uo pipefail
cd /home/claude/threatfeed

WORK=/tmp/envtest
rm -rf "$WORK"; mkdir -p "$WORK"

# --- berkas .env contoh dengan komentar dan urutan yang harus dipertahankan ---
cat > "$WORK/threatfeed.env" <<'EOF'
# /etc/threatfeed/threatfeed.env      chmod 640, chown root:threatfeed
# Baris komentar ini WAJIB tetap ada setelah penulisan ulang.

# --- identitas & storage ---------------------------------------------------
TF_APP_NAME="IoC-WATCH Threat Feed Server"
TF_DB_PATH=/var/lib/threatfeed/threatfeed.db

# --- kredensial ------------------------------------------------------------
TF_INGEST_TOKENS=ingtok12345678
TF_FEED_TOKENS=fgttok12345678
TF_ADMIN_PASSWORD=RahasiaSekali12
TF_SECRET_KEY=0123456789abcdef0123456789abcdef
TF_SESSION_TTL_HOURS=12
TF_COOKIE_SECURE=false
TF_ALLOW_ENV_WRITE=true

# --- kebijakan feed --------------------------------------------------------
TF_TTL_DAYS=30
TF_FEED_COMMENT_FORMAT=plain
TF_INGEST_ALLOWED_CIDRS=
TF_FEED_ALLOWED_CIDRS=
EOF

# --- helper root tiruan: memakai skrip asli, tetapi path diarahkan ke $WORK ---
# Hanya path dan pemeriksaan root/ownership yang diubah. Logika validasi,
# backup, penulisan atomik, dan pemanggilan restart diuji apa adanya — kalau
# blok restart ikut di-sed, justru bagian yang paling mudah rusak tidak teruji.
sed -e "s|^SPOOL=.*|SPOOL=$WORK/pending.env|" \
    -e "s|^TARGET=.*|TARGET=$WORK/threatfeed.env|" \
    -e "s|^BACKUP_DIR=.*|BACKUP_DIR=$WORK/backups|" \
    -e "s|^RESULT=.*|RESULT=$WORK/apply-result|" \
    -e "s|^APP_USER=.*|APP_USER=$(id -un)|" \
    -e 's|^\[\[ \$EUID -eq 0 \]\].*||' \
    -e 's|^install -d -m 750 -o root -g "\$APP_USER" "\$BACKUP_DIR"|mkdir -p "$BACKUP_DIR"|' \
    -e 's|^chown root:"\$APP_USER" "\$TMP"|true|' \
    deploy/threatfeed-apply-env > "$WORK/apply-env"
chmod +x "$WORK/apply-env"

# systemd tidak berjalan di lingkungan uji; sediakan tiruan yang mencatat panggilan
for stub in systemd-run systemctl; do
  cat > "$WORK/$stub" <<SH
#!/usr/bin/env bash
printf '%s %s\n' "$stub" "\$*" >> "$WORK/restart.log"
exit 0
SH
  chmod +x "$WORK/$stub"
done

export PATH="$WORK:$PATH"

# Tiruan systemd path unit: pengawas latar yang menjalankan helper begitu berkas
# kandidat muncul. Di server, peran ini dipegang threatfeed-apply-env.path.
watcher() {
  while sleep 0.2; do
    [[ -f "$WORK/pending.env" ]] && "$WORK/apply-env" >>"$WORK/helper.log" 2>&1
  done
}
watcher >>"$WORK/watcher.log" 2>&1 & WATCHER=$!

export TF_ENV_FILE="$WORK/threatfeed.env"
export TF_DB_PATH="$WORK/test.db"
export TF_INGEST_TOKENS=ingtok12345678 TF_FEED_TOKENS=fgttok12345678
export TF_ADMIN_PASSWORD=RahasiaSekali12 TF_SECRET_KEY=0123456789abcdef0123456789abcdef
export TF_COOKIE_SECURE=false TF_ALLOW_ENV_WRITE=true
rm -f "$TF_DB_PATH"*

python3 - <<PY
import pathlib, re
p = pathlib.Path("app/envfile.py"); t = p.read_text()
t = t.replace('APPLY_HELPER = "/usr/local/sbin/threatfeed-apply-env"',
              'APPLY_HELPER = os.getenv("TF_APPLY_HELPER", "/usr/local/sbin/threatfeed-apply-env")')
p.write_text(t)
PY
export TF_APPLY_HELPER="$WORK/apply-env"

python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8903 --log-level warning &
SRV=$!
trap 'kill $SRV $WATCHER 2>/dev/null' EXIT
for i in $(seq 1 40); do curl -sf localhost:8903/healthz >/dev/null && break; sleep 0.25; done
U=http://127.0.0.1:8903; J='Content-Type: application/json'
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" -d '{"password":"RahasiaSekali12"}' >/dev/null

hr(){ printf '\n── %s\n' "$1"; }

hr "1. GET tanpa sesi harus 401"
curl -s -o /dev/null -w "   %{http_code}\n" $U/api/v1/admin/settings

hr "2. Skema terbaca, rahasia TIDAK ikut terkirim ke browser"
curl -s -b "$WORK/jar" $U/api/v1/admin/settings | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('   jumlah field:', len(d['fields']), '| grup:', len(d['groups']), '| helper:', d['helper_available'])
for f in d['fields']:
    if f['secret']:
        leaked = f['value'] not in ('', d['mask'])
        print(f\"   {f['key']:<22} value={f['value']!r:<12} length={f['length']} bocor={leaked}\")"

hr "3. Validasi menolak nilai berbahaya"
for BAD in '{"TF_APP_NAME":"a$(id)"}' '{"TF_TTL_DAYS":"abc"}' '{"TF_FEED_MIN_CONFIDENCE":"500"}' \
           '{"TF_INGEST_ALLOWED_CIDRS":"999.1.1.1/32"}' '{"TF_ADMIN_PASSWORD":"pendek"}' \
           '{"TF_SECRET_KEY":"bukan-hex"}' '{"TF_DB_PATH":"../../etc/passwd"}' '{"PATH":"/tmp/evil"}'; do
  R=$(curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/settings -H "$J" \
      -d "$(python3 -c "import json,sys;print(json.dumps({'changes':json.loads(sys.argv[1]),'confirm_password':'RahasiaSekali12'}))" "$BAD")")
  printf '   %-46s %s\n' "$BAD" "$(printf '%s' "$R" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)['detail']
    print(list(d['errors'].values())[0][:60] if isinstance(d,dict) else str(d)[:60])
except Exception as e: print('?', e)")"
done

hr "4. Password konfirmasi salah harus ditolak"
curl -s -o /dev/null -w "   %{http_code} (401 = benar)\n" -b "$WORK/jar" -X POST $U/api/v1/admin/settings \
  -H "$J" -d '{"changes":{"TF_TTL_DAYS":"45"},"confirm_password":"salah"}'

hr "5. Simpan perubahan sah"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/settings -H "$J" -d '{
  "changes":{"TF_TTL_DAYS":"45","TF_FEED_COMMENT_FORMAT":"full",
             "TF_FEED_ALLOWED_CIDRS":"10.10.10.0/24","TF_APP_NAME":"IoC-WATCH Produksi"},
  "confirm_password":"RahasiaSekali12"}' | python3 -m json.tool

hr "6. Berkas .env sesudah ditulis ulang"
cat "$WORK/threatfeed.env"

hr "7. Cek yang harus dipertahankan"
grep -q '^# /etc/threatfeed/threatfeed.env' "$WORK/threatfeed.env" && echo "   ✓ komentar header utuh" || echo "   ✗ komentar hilang"
grep -q 'WAJIB tetap ada' "$WORK/threatfeed.env" && echo "   ✓ komentar tengah utuh" || echo "   ✗ komentar hilang"
grep -q '^TF_INGEST_TOKENS=ingtok12345678' "$WORK/threatfeed.env" && echo "   ✓ rahasia tidak tersentuh" || echo "   ✗ rahasia berubah"
grep -q '127.0.0.1/32' "$WORK/threatfeed.env" && echo "   ✓ loopback disisipkan otomatis" || echo "   ✗ loopback hilang"
[[ $(stat -c '%a' "$WORK/threatfeed.env") == 640 ]] && echo "   ✓ mode 640" || echo "   ✗ mode $(stat -c '%a' "$WORK/threatfeed.env")"
ls "$WORK/backups"/ | sed 's/^/   backup: /'

hr "7b. Restart dijadwalkan lewat systemd-run (bukan restart langsung)"
sed 's/^/   /' "$WORK/restart.log" 2>/dev/null || echo "   (tidak ada panggilan restart)"

hr "8. Rahasia baru benar-benar tertulis"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/settings -H "$J" -d '{
  "changes":{"TF_FEED_TOKENS":"tokenbaru1234567890"},"confirm_password":"RahasiaSekali12"}' \
  | python3 -c "import json,sys;print('   changed =',json.load(sys.stdin)['changed'])"
grep '^TF_FEED_TOKENS=' "$WORK/threatfeed.env" | sed 's/^/   /'

hr "9. Rahasia kosong = jangan ubah"
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/settings -H "$J" -d '{
  "changes":{"TF_FEED_TOKENS":"","TF_TTL_DAYS":"60"},"confirm_password":"RahasiaSekali12"}' \
  | python3 -c "import json,sys;print('   changed =',json.load(sys.stdin)['changed'])"
grep '^TF_FEED_TOKENS=' "$WORK/threatfeed.env" | sed 's/^/   /'

hr "10. Jejak audit mencatat nama kunci, bukan nilainya"
curl -s -b "$WORK/jar" "$U/api/v1/audit?limit=6" | python3 -c "
import json,sys
for a in json.load(sys.stdin)['items']:
    if a['action'].startswith('env_'):
        print('  ', a['action'], '|', a['detail'][:90])
        assert 'tokenbaru' not in a['detail'], 'NILAI RAHASIA BOCOR KE AUDIT'
print('   ✓ tidak ada nilai rahasia di jejak audit')"

hr "11. Pembangkit nilai acak"
curl -s -b "$WORK/jar" -X POST "$U/api/v1/admin/settings/generate?kind=hex32" \
  | python3 -c "import json,sys;v=json.load(sys.stdin)['value'];print('   hex32 panjang',len(v))"
curl -s -b "$WORK/jar" -X POST "$U/api/v1/admin/settings/generate?kind=pass20" \
  | python3 -c "import json,sys;v=json.load(sys.stdin)['value'];print('   pass20 panjang',len(v))"

hr "12. Fitur nonaktif saat TF_ALLOW_ENV_WRITE=false"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
TF_ALLOW_ENV_WRITE=false python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8903 --log-level warning &
SRV=$!
for i in $(seq 1 40); do curl -sf localhost:8903/healthz >/dev/null && break; sleep 0.25; done
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" -d '{"password":"RahasiaSekali12"}' >/dev/null
curl -s -b "$WORK/jar" $U/api/v1/admin/settings \
  | python3 -c "import json,sys;print('  ',json.load(sys.stdin)['detail'][:100])"
echo

hr "13. Kunci ganda di .env dirapikan, nilai efektif dipertahankan"
# Uji 12 mematikan fitur; hidupkan lagi service dengan flag aktif.
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
python3 - <<'PYX'
import pathlib, os
p = pathlib.Path(os.environ["TF_ENV_FILE"])
lines = p.read_text().splitlines()
# Duplikat disisipkan SEBELUM baris yang berlaku, dengan nilai berbeda.
# Nilai efektif tetap yang terakhir (true) — itulah yang harus bertahan.
idx = next(i for i, l in enumerate(lines) if l.startswith("TF_ALLOW_ENV_WRITE="))
lines.insert(idx, "TF_ALLOW_ENV_WRITE=false")
p.write_text("\n".join(lines) + "\n")
print("   duplikat bernilai false disisipkan sebelum baris yang berlaku (true)")
PYX
grep -c '^TF_ALLOW_ENV_WRITE=' "$TF_ENV_FILE" | sed 's/^/   kemunculan sebelum: /'
TF_ALLOW_ENV_WRITE=true python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8903 --log-level warning &
SRV=$!
for i in $(seq 1 40); do curl -sf localhost:8903/healthz >/dev/null && break; sleep 0.25; done
curl -s -c "$WORK/jar" -X POST $U/api/v1/auth/login -H "$J" -d '{"password":"RahasiaSekali12"}' >/dev/null
curl -s -b "$WORK/jar" -X POST $U/api/v1/admin/settings -H "$J" \
  -d '{"changes":{"TF_TTL_DAYS":"33"},"confirm_password":"RahasiaSekali12"}' \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('   hasil:',str(d.get('status') or d.get('detail'))[:70])"
grep -c '^TF_ALLOW_ENV_WRITE=' "$TF_ENV_FILE" | sed 's/^/   kemunculan aktif sesudah: /'
grep -n 'ALLOW_ENV_WRITE' "$TF_ENV_FILE" | sed 's/^/   /'
grep -q '^TF_ALLOW_ENV_WRITE=true' "$TF_ENV_FILE" && echo "   OK nilai efektif (true) dipertahankan" || echo "   GAGAL nilai efektif berubah"
grep -q '^TF_TTL_DAYS=33' "$TF_ENV_FILE" && echo "   OK perubahan tetap tersimpan" || echo "   GAGAL perubahan tidak tersimpan"
