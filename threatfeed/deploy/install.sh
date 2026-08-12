#!/usr/bin/env bash
# Installer native (tanpa container) untuk Ubuntu 22.04/24.04 & Debian 12.
# Idempoten: aman dijalankan ulang untuk upgrade.
#   sudo bash deploy/install.sh
set -Eeuo pipefail

APP_USER=threatfeed
APP_DIR=/opt/threatfeed
DATA_DIR=/var/lib/threatfeed
CONF_DIR=/etc/threatfeed
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mGAGAL:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Jalankan sebagai root (sudo)."

log "Memasang paket sistem"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip sqlite3 openssl curl

log "Membuat service account terkunci: $APP_USER"
id -u "$APP_USER" &>/dev/null || \
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"

log "Menyiapkan direktori"
install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$APP_DIR" "$DATA_DIR"
install -d -o root -g "$APP_USER" -m 750 "$CONF_DIR"

log "Menyalin kode aplikasi"
# Salin bukan symlink, supaya ProtectSystem=strict tetap bisa diterapkan.
rm -rf "$APP_DIR/app" "$APP_DIR/static"
cp -r "$SRC_DIR/app" "$SRC_DIR/static" "$SRC_DIR/requirements.txt" "$APP_DIR/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

log "Membangun virtualenv"
if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip wheel
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/.venv"

log "Menyiapkan konfigurasi"
if [[ ! -f "$CONF_DIR/threatfeed.env" ]]; then
  # Rakit satu per satu; hindari 'cmd | head' agar tidak kena SIGPIPE di pipefail.
  ING=$(openssl rand -hex 32)
  FGT=$(openssl rand -hex 32)
  SEC=$(openssl rand -hex 32)
  ADM=$(openssl rand -base64 18 | tr -d '/+=')

  sed -e "s|^TF_INGEST_TOKENS=.*|TF_INGEST_TOKENS=$ING|" \
      -e "s|^TF_FEED_TOKENS=.*|TF_FEED_TOKENS=$FGT|" \
      -e "s|^TF_SECRET_KEY=.*|TF_SECRET_KEY=$SEC|" \
      -e "s|^TF_ADMIN_PASSWORD=.*|TF_ADMIN_PASSWORD=$ADM|" \
      -e "s|^TF_INGEST_ALLOWED_CIDRS=.*|TF_INGEST_ALLOWED_CIDRS=|" \
      -e "s|^TF_FEED_ALLOWED_CIDRS=.*|TF_FEED_ALLOWED_CIDRS=|" \
      "$SRC_DIR/deploy/threatfeed.env.example" > "$CONF_DIR/threatfeed.env"

  chown root:"$APP_USER" "$CONF_DIR/threatfeed.env"
  chmod 640 "$CONF_DIR/threatfeed.env"
  CREDS_BARU=1
else
  log "  $CONF_DIR/threatfeed.env sudah ada — dipertahankan"
  CREDS_BARU=0
fi

log "Memasang unit systemd"
install -m 644 "$SRC_DIR/deploy/threatfeed.service" /etc/systemd/system/threatfeed.service
systemctl daemon-reload
systemctl enable --now threatfeed
sleep 2
systemctl is-active --quiet threatfeed || {
  journalctl -u threatfeed -n 30 --no-pager
  die "Service tidak aktif. Lihat log di atas."
}

curl -fsS http://127.0.0.1:8080/healthz >/dev/null || die "Health check gagal."
log "Service aktif dan sehat."

if [[ $CREDS_BARU -eq 1 ]]; then
  echo
  echo "──────────────── KREDENSIAL BARU (catat sekarang) ────────────────"
  grep -E '^TF_(INGEST_TOKENS|FEED_TOKENS|ADMIN_PASSWORD)=' "$CONF_DIR/threatfeed.env"
  echo "──────────────────────────────────────────────────────────────────"
  echo "Tersimpan di $CONF_DIR/threatfeed.env (mode 640)."
fi

cat <<EOF

Langkah berikutnya:
  1. Batasi akses  : isi TF_INGEST_ALLOWED_CIDRS dan TF_FEED_ALLOWED_CIDRS
  2. Pasang TLS    : cp deploy/nginx-threatfeed.conf /etc/nginx/sites-available/
  3. Cek status    : systemctl status threatfeed
  4. Ikuti log     : journalctl -u threatfeed -f
EOF
