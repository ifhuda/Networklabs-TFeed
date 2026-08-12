#!/usr/bin/env bash
#===============================================================================
#  IoC-WATCH Threat Feed Server — installer sekali jalan
#
#  Menyiapkan SEMUANYA sampai siap dipakai: paket sistem, service account,
#  virtualenv, database, kredensial, unit systemd, nginx + TLS, aturan firewall,
#  self-test, perintah bantu `threatfeedctl`, dan konfigurasi FortiGate siap tempel.
#
#  Pakai:
#     sudo bash deploy/setup.sh                    # wizard interaktif
#     sudo bash deploy/setup.sh --yes              # pakai semua nilai default
#     sudo bash deploy/setup.sh --domain feed.networklabs.id \
#          --soar-ip 10.10.10.20 --fgt-ip 10.10.10.1 --tls self-signed --yes
#     sudo bash deploy/setup.sh --upgrade          # perbarui kode, kredensial tetap
#     sudo bash deploy/setup.sh --uninstall        # copot bersih
#===============================================================================
set -Eeuo pipefail

APP_NAME="IoC-WATCH Threat Feed Server"
APP_USER=threatfeed
APP_DIR=/opt/threatfeed
DATA_DIR=/var/lib/threatfeed
CONF_DIR=/etc/threatfeed
ENV_FILE="$CONF_DIR/threatfeed.env"
UNIT=/etc/systemd/system/threatfeed.service
CTL=/usr/local/bin/threatfeedctl
SUMMARY="$CONF_DIR/INSTALL-SUMMARY.txt"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------- nilai default
DOMAIN=""
SOAR_IP=""
FGT_IP=""
BIND_PORT=8080
TTL_DAYS=30
TLS_MODE=""            # self-signed | existing | none
CERT_FILE=""
KEY_FILE=""
ASSUME_YES=0
MODE=install           # install | upgrade | uninstall
INSTALL_NGINX=1
ROLLBACK_ON_FAIL=0
FEED_COMMENTS=""        # yes | no
ENV_EDITOR=0            # pasang helper root + sudoers untuk editor .env di GUI
COMMENT_FORMAT=plain

#================================================================== tampilan ===
if [[ -t 1 ]]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'
  C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_C=""; C_B=""; C_D=""; C_0=""
fi

step() { printf '\n%s==>%s %s%s%s\n' "$C_C" "$C_0" "$C_B" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '\n%sGAGAL:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

on_error() {
  local line=$1
  printf '\n%sInstalasi berhenti di baris %s.%s\n' "$C_R" "$line" "$C_0" >&2
  if [[ $ROLLBACK_ON_FAIL -eq 1 ]]; then
    printf 'Mengembalikan perubahan…\n' >&2
    systemctl stop threatfeed 2>/dev/null || true
    systemctl disable threatfeed 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
    rm -rf "$APP_DIR"
    printf 'Kode dan service dihapus. %s dan %s dibiarkan.\n' "$CONF_DIR" "$DATA_DIR" >&2
  fi
  printf 'Log: journalctl -u threatfeed -n 50 --no-pager\n' >&2
  exit 1
}
trap 'on_error $LINENO' ERR

#=================================================================== argumen ===
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)     DOMAIN="$2"; shift 2 ;;
    --soar-ip)    SOAR_IP="$2"; shift 2 ;;
    --fgt-ip)     FGT_IP="$2"; shift 2 ;;
    --port)       BIND_PORT="$2"; shift 2 ;;
    --ttl)        TTL_DAYS="$2"; shift 2 ;;
    --tls)        TLS_MODE="$2"; shift 2 ;;
    --cert)       CERT_FILE="$2"; shift 2 ;;
    --key)        KEY_FILE="$2"; shift 2 ;;
    --enable-env-editor)  ENV_EDITOR=1; shift ;;
    --comments)      FEED_COMMENTS=yes; shift ;;
    --no-comments)   FEED_COMMENTS=no;  shift ;;
    --comment-format) COMMENT_FORMAT="$2"; shift 2 ;;
    --no-nginx)   INSTALL_NGINX=0; TLS_MODE=none; shift ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    --upgrade)    MODE=upgrade; shift ;;
    --uninstall)  MODE=uninstall; shift ;;
    -h|--help)    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)            die "Argumen tidak dikenal: $1  (lihat --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Jalankan sebagai root:  sudo bash $0"

# Argumen divalidasi SEBELUM wizard, supaya salah ketik ketahuan seketika
# dan bukan setelah operator menjawab lima pertanyaan.
case "$COMMENT_FORMAT" in plain|short|full) : ;;
  *) die "--comment-format harus plain, short, atau full (diberikan: $COMMENT_FORMAT)" ;; esac
case "${TLS_MODE:-}" in ""|self-signed|existing|none) : ;;
  *) die "--tls harus self-signed, existing, atau none (diberikan: $TLS_MODE)" ;; esac
[[ $TTL_DAYS  =~ ^[0-9]+$ ]] || die "--ttl harus angka (diberikan: $TTL_DAYS)"
[[ $BIND_PORT =~ ^[0-9]+$ ]] || die "--port harus angka (diberikan: $BIND_PORT)"

# IP utama host. `ip route get` gagal di server tanpa default route (air-gapped),
# jadi kegagalannya harus diserap — bukan menjatuhkan skrip lewat `set -e`.
primary_ip() {
  local ip=""
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p') || true
  [[ -z $ip ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}') || true
  printf '%s' "$ip"
}

#================================================================== uninstall ==
if [[ $MODE == uninstall ]]; then
  printf '%sMencopot %s%s\n' "$C_B" "$APP_NAME" "$C_0"
  if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "Hapus juga database di $DATA_DIR? [y/N] " a
    [[ ${a,,} == y ]] && PURGE=1 || PURGE=0
  else
    PURGE=0
  fi
  systemctl disable --now threatfeed 2>/dev/null || true
  systemctl disable --now threatfeed-apply-env.path 2>/dev/null || true
  systemctl disable --now threatfeed-restore-db.path 2>/dev/null || true
  rm -f "$UNIT" "$CTL" /etc/sudoers.d/threatfeed \
        /etc/systemd/system/threatfeed-apply-env.{path,service} \
        /etc/systemd/system/threatfeed-restore-db.{path,service} \
        /usr/local/sbin/threatfeed-apply-env /usr/local/sbin/threatfeed-restore-db
  systemctl daemon-reload
  rm -f /etc/nginx/sites-enabled/threatfeed.conf /etc/nginx/sites-available/threatfeed.conf
  systemctl reload nginx 2>/dev/null || true
  rm -rf "$APP_DIR"
  if [[ ${PURGE:-0} -eq 1 ]]; then
    rm -rf "$DATA_DIR" "$CONF_DIR"
    userdel "$APP_USER" 2>/dev/null || true
    ok "Dicopot sepenuhnya termasuk database."
  else
    ok "Dicopot. Database di $DATA_DIR dan konfigurasi di $CONF_DIR dipertahankan."
  fi
  exit 0
fi

#=============================================================== pra-penerbangan
step "Pemeriksaan pra-instalasi"

[[ -d "$SRC_DIR/app" && -f "$SRC_DIR/static/index.html" ]] || \
  die "Folder app/ atau static/index.html tidak ditemukan di $SRC_DIR.
    Jalankan skrip ini dari dalam folder project yang utuh."

command -v systemctl >/dev/null || die "systemd tidak tersedia di sistem ini."

if [[ -r /etc/os-release ]]; then . /etc/os-release; else die "/etc/os-release tidak terbaca."; fi
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) : ;;
  *) warn "Distro '${PRETTY_NAME:-?}' belum diuji. Skrip mengandalkan apt-get." ;;
esac
ok "OS: ${PRETTY_NAME:-unknown}"

PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
python3 - <<'PY' || die "Butuh Python 3.10 atau lebih baru (terdeteksi: $PYV)."
import sys; sys.exit(0 if sys.version_info[:2] >= (3,10) else 1)
PY
ok "Python $PYV"

# Port bentrok?
if command -v ss >/dev/null && ss -ltnH "sport = :$BIND_PORT" 2>/dev/null | grep -q .; then
  if ! systemctl is-active --quiet threatfeed; then
    die "Port $BIND_PORT sudah dipakai proses lain. Pakai --port <lain>."
  fi
fi
ok "Port $BIND_PORT tersedia"

FRESH=1
[[ -f "$ENV_FILE" ]] && FRESH=0
if [[ $MODE == upgrade && $FRESH -eq 1 ]]; then
  die "--upgrade dipakai tapi $ENV_FILE belum ada. Jalankan tanpa --upgrade."
fi
[[ $FRESH -eq 1 ]] && ROLLBACK_ON_FAIL=1

#===================================================================== wizard ==
prompt() {   # prompt <var> <pertanyaan> <default>
  local __v=$1 q=$2 d=$3 ans
  if [[ ${!__v} != "" ]]; then return; fi
  if [[ $ASSUME_YES -eq 1 || ! -t 0 ]]; then printf -v "$__v" '%s' "$d"; return; fi
  read -r -p "    $q [$d]: " ans
  printf -v "$__v" '%s' "${ans:-$d}"
}

if [[ $MODE == install ]]; then
  printf '\n%s%s — pemasangan native (tanpa container)%s\n' "$C_B" "$APP_NAME" "$C_0"
  printf '%sTekan Enter untuk menerima nilai dalam kurung.%s\n\n' "$C_D" "$C_0"

  # Default ke IP utama, bukan hostname: FortiGate umumnya tidak bisa me-resolve
  # nama host lokal, dan URL berbasis hostname akan gagal di sisi sana.
  DEFAULT_HOST=$(primary_ip)
  [[ -z $DEFAULT_HOST ]] && DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
  prompt DOMAIN   "Alamat yang dipakai FortiGate & FortiSOAR (IP atau FQDN)" "$DEFAULT_HOST"
  prompt SOAR_IP  "IP FortiSOAR yang boleh push (kosong = semua)" ""
  prompt FGT_IP   "IP/subnet FortiGate yang boleh menarik feed (kosong = semua)" ""
  prompt TTL_DAYS "TTL indikator dalam hari" "30"

  if [[ -z $FEED_COMMENTS ]]; then
    if [[ $ASSUME_YES -eq 1 || ! -t 0 ]]; then
      FEED_COMMENTS=no
    else
      printf '\n    Sertakan komentar di feed FortiGate?\n'
      printf '      Contoh: 103.74.20.57 # C2 Server detected\n'
      printf '      %sCatatan:%s FortiOS hanya menjamin komentar baris-penuh. Kalau parser\n' "$C_Y" "$C_0"
      printf '      FortiGate Anda menolaknya, jumlah entri anjlok TANPA pesan error.\n'
      read -r -p "    Aktifkan? [y/N]: " ycm
      [[ ${ycm,,} == y ]] && FEED_COMMENTS=yes || FEED_COMMENTS=no
    fi
  fi

  if [[ -z $TLS_MODE ]]; then
    if [[ $ASSUME_YES -eq 1 || ! -t 0 ]]; then
      TLS_MODE=self-signed
    else
      printf '\n    Mode TLS:\n'
      printf '      1) self-signed  — nginx + sertifikat buatan sendiri (cepat, untuk lab)\n'
      printf '      2) existing     — nginx + sertifikat Anda (mis. Networklabs-Root-CA)\n'
      printf '      3) none         — tanpa nginx, uvicorn langsung di 127.0.0.1\n'
      read -r -p "    Pilih [1]: " t
      case "${t:-1}" in
        1) TLS_MODE=self-signed ;;
        2) TLS_MODE=existing ;;
        3) TLS_MODE=none; INSTALL_NGINX=0 ;;
        *) die "Pilihan tidak valid." ;;
      esac
    fi
  fi
  [[ $TLS_MODE == none ]] && INSTALL_NGINX=0

  if [[ $TLS_MODE == existing ]]; then
    prompt CERT_FILE "Path fullchain certificate (.pem)" "/etc/ssl/certs/threatfeed-fullchain.pem"
    prompt KEY_FILE  "Path private key (.pem)"           "/etc/ssl/private/threatfeed.key"
    [[ -r $CERT_FILE ]] || die "Sertifikat tidak terbaca: $CERT_FILE"
    [[ -r $KEY_FILE  ]] || die "Private key tidak terbaca: $KEY_FILE"
  fi
fi

#================================================= mode upgrade: pakai nilai lama
NGX_CONF=/etc/nginx/sites-available/threatfeed.conf
REUSE_NGINX=0
if [[ $MODE == upgrade ]]; then
  # Wizard dilewati pada --upgrade, sehingga DOMAIN/CERT_FILE/KEY_FILE kosong.
  # Baca kembali dari konfigurasi nginx yang sudah ada; kalau operator tidak
  # meminta perubahan apa pun, jangan sentuh nginx sama sekali — upgrade
  # seharusnya hanya memperbarui kode.
  if [[ -f $NGX_CONF ]]; then
    # [[:space:]], bukan \s: mawk (awk default Ubuntu) tidak mengenal \s.
    OLD_DOMAIN=$(awk '/^[[:space:]]*server_name/{print $2; exit}'         "$NGX_CONF" | tr -d ';')
    OLD_CERT=$(awk '/^[[:space:]]*ssl_certificate[[:space:]]/{print $2; exit}' "$NGX_CONF" | tr -d ';')
    OLD_KEY=$(awk '/^[[:space:]]*ssl_certificate_key/{print $2; exit}'    "$NGX_CONF" | tr -d ';')
    [[ -z $DOMAIN    ]] && DOMAIN=$OLD_DOMAIN
    [[ -z $CERT_FILE ]] && CERT_FILE=$OLD_CERT
    [[ -z $KEY_FILE  ]] && KEY_FILE=$OLD_KEY
    if [[ -z $TLS_MODE && $DOMAIN == "$OLD_DOMAIN" ]]; then
      REUSE_NGINX=1
      TLS_MODE=existing
    fi
  else
    INSTALL_NGINX=0
    [[ -z $TLS_MODE ]] && TLS_MODE=none
  fi
  [[ -z $DOMAIN ]] && DOMAIN=$(hostname -f 2>/dev/null || hostname)
fi

[[ -z $FEED_COMMENTS ]] && FEED_COMMENTS=no
# Pada --upgrade, .env lama dipertahankan; pilihan komentar dibaca dari sana
# supaya self-test dan ringkasan mencerminkan konfigurasi yang benar-benar aktif.
if [[ $MODE == upgrade && -f $ENV_FILE ]]; then
  grep -qi '^TF_FEED_INLINE_COMMENTS=true' "$ENV_FILE" && FEED_COMMENTS=yes || FEED_COMMENTS=no
fi
if [[ $FEED_COMMENTS == yes ]]; then
  FGT_PATH=/api/v1/feed/fortigate/annotated
else
  FGT_PATH=/api/v1/feed/fortigate
fi

#===================================================================== paket ====
step "Memasang paket sistem"
export DEBIAN_FRONTEND=noninteractive
PKGS=(python3 python3-venv python3-pip sqlite3 openssl curl ca-certificates)
[[ $INSTALL_NGINX -eq 1 ]] && PKGS+=(nginx)

MISSING=()
for p in "${PKGS[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || MISSING+=("$p")
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
  ok "Semua paket sudah terpasang — apt dilewati"
else
  # Repo pihak ketiga yang rusak (PPA lama, nodesource, dsb.) sering membuat
  # `apt-get update` gagal padahal paket yang kita butuhkan ada di repo resmi.
  # Karena itu update bersifat opsional; yang menentukan adalah install-nya.
  apt-get update -qq 2>/dev/null || warn "apt-get update tidak bersih (repo pihak ketiga?) — dilanjutkan"
  apt-get install -y -qq "${MISSING[@]}" \
    || die "Gagal memasang: ${MISSING[*]}
    Perbaiki repo apt lalu ulangi, atau pasang manual:  apt-get install ${MISSING[*]}"
  ok "Dipasang: ${MISSING[*]}"
fi

#============================================================ user & direktori ==
step "Menyiapkan service account dan direktori"
if ! id -u "$APP_USER" &>/dev/null; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
  ok "User sistem '$APP_USER' dibuat (nologin, tanpa password)"
else
  ok "User sistem '$APP_USER' sudah ada"
fi
install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$APP_DIR" "$DATA_DIR"
install -d -o root       -g "$APP_USER" -m 750 "$CONF_DIR"
ok "$APP_DIR  $DATA_DIR  $CONF_DIR"

#======================================================================= kode ===
step "Menyalin kode aplikasi"
if [[ -d "$APP_DIR/app" ]]; then
  BK="$DATA_DIR/rollback-$(date +%Y%m%d-%H%M%S)"
  install -d -o "$APP_USER" -g "$APP_USER" -m 750 "$BK"
  cp -r "$APP_DIR/app" "$APP_DIR/static" "$BK/" 2>/dev/null || true
  info "Versi lama dicadangkan ke $BK"
fi
rm -rf "$APP_DIR/app" "$APP_DIR/static"
cp -r "$SRC_DIR/app" "$SRC_DIR/static" "$SRC_DIR/requirements.txt" "$APP_DIR/"
[[ -d "$SRC_DIR/tests" ]] && cp -r "$SRC_DIR/tests" "$APP_DIR/"
find "$APP_DIR/app" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
ok "Kode terpasang di $APP_DIR"

step "Membangun virtualenv"
[[ -x "$APP_DIR/.venv/bin/python" ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip wheel
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/.venv"
FASTAPI_V=$("$APP_DIR/.venv/bin/python" -c 'import fastapi;print(fastapi.__version__)')
ok "fastapi $FASTAPI_V + uvicorn terpasang"

#================================================================== kredensial ==
step "Menyiapkan konfigurasi"
if [[ $FRESH -eq 1 ]]; then
  # Dibangkitkan satu per satu. Hindari pola `cmd | head` di bawah `set -o pipefail`:
  # head menutup pipe lebih dulu dan memicu SIGPIPE palsu pada proses hulu.
  ING_TOKEN=$(openssl rand -hex 32)
  FGT_TOKEN=$(openssl rand -hex 32)
  SEC_KEY=$(openssl rand -hex 32)
  ADM_PASS=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)

  COOKIE_SECURE=true
  [[ $TLS_MODE == none ]] && COOKIE_SECURE=false

  # Terima "10.10.10.20" maupun "10.10.10.0/24" tanpa merusaknya jadi "…/24/32".
  as_cidr() { [[ $1 == */* ]] && printf '%s' "$1" || printf '%s/32' "$1"; }

  # Loopback selalu masuk daftar: self-test installer dan `threatfeedctl` memanggil
  # API dari 127.0.0.1. Ditulis eksplisit di berkas config, bukan disembunyikan di
  # dalam kode, supaya operator bisa melihat dan mencabutnya bila perlu.
  LOOPBACK="127.0.0.1/32,::1/128"
  ING_CIDRS=$LOOPBACK; [[ -n $SOAR_IP ]] && ING_CIDRS="$LOOPBACK,$(as_cidr "$SOAR_IP")"
  FEED_CIDRS=$LOOPBACK; [[ -n $FGT_IP ]] && FEED_CIDRS="$LOOPBACK,$(as_cidr "$FGT_IP")"
  # Tanpa pembatasan yang diminta, biarkan kosong (= semua diizinkan).
  [[ -z $SOAR_IP ]] && ING_CIDRS=""
  [[ -z $FGT_IP  ]] && FEED_CIDRS=""

  umask 027
  sed -e "s|^TF_INGEST_TOKENS=.*|TF_INGEST_TOKENS=$ING_TOKEN|" \
      -e "s|^TF_FEED_TOKENS=.*|TF_FEED_TOKENS=$FGT_TOKEN|" \
      -e "s|^TF_SECRET_KEY=.*|TF_SECRET_KEY=$SEC_KEY|" \
      -e "s|^TF_ADMIN_PASSWORD=.*|TF_ADMIN_PASSWORD=$ADM_PASS|" \
      -e "s|^TF_TTL_DAYS=.*|TF_TTL_DAYS=$TTL_DAYS|" \
      -e "s|^TF_COOKIE_SECURE=.*|TF_COOKIE_SECURE=$COOKIE_SECURE|" \
      -e "s|^TF_FEED_INLINE_COMMENTS=.*|TF_FEED_INLINE_COMMENTS=$([[ $FEED_COMMENTS == yes ]] && echo true || echo false)|" \
      -e "s|^TF_FEED_COMMENT_FORMAT=.*|TF_FEED_COMMENT_FORMAT=$COMMENT_FORMAT|" \
      -e "s|^TF_ALLOW_ENV_WRITE=.*|TF_ALLOW_ENV_WRITE=$([[ $ENV_EDITOR -eq 1 ]] && echo true || echo false)|" \
      -e "s|^TF_INGEST_ALLOWED_CIDRS=.*|TF_INGEST_ALLOWED_CIDRS=$ING_CIDRS|" \
      -e "s|^TF_FEED_ALLOWED_CIDRS=.*|TF_FEED_ALLOWED_CIDRS=$FEED_CIDRS|" \
      "$SRC_DIR/deploy/threatfeed.env.example" > "$ENV_FILE"
  chown root:"$APP_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
  ok "Kredensial acak dibangkitkan → $ENV_FILE (mode 640)"
else
  ok "$ENV_FILE sudah ada — dipertahankan apa adanya"
  ING_TOKEN=$(awk -F= '/^TF_INGEST_TOKENS=/{print $2;exit}' "$ENV_FILE")
  FGT_TOKEN=$(awk -F= '/^TF_FEED_TOKENS=/{print $2;exit}'   "$ENV_FILE")
  ADM_PASS=$(awk  -F= '/^TF_ADMIN_PASSWORD=/{print $2;exit}' "$ENV_FILE")
fi
# Token pertama saja (kolom ke-1) untuk contoh perintah, bila ada rotasi berkoma
ING_TOKEN=${ING_TOKEN%%,*}
FGT_TOKEN=${FGT_TOKEN%%,*}

#===================================================================== systemd ==
step "Memasang unit systemd"
sed "s|--port 8080|--port $BIND_PORT|" "$SRC_DIR/deploy/threatfeed.service" > "$UNIT"
chmod 644 "$UNIT"
systemctl daemon-reload
systemctl enable threatfeed >/dev/null 2>&1
systemctl restart threatfeed

for i in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$BIND_PORT/healthz" >/dev/null && break
  sleep 0.25
done
systemctl is-active --quiet threatfeed || { journalctl -u threatfeed -n 30 --no-pager; die "Service tidak aktif."; }
curl -sf "http://127.0.0.1:$BIND_PORT/healthz" >/dev/null || die "Health check gagal di port $BIND_PORT."
ok "Service aktif, health check lulus"

#======================================================================= nginx ==
if [[ $INSTALL_NGINX -eq 1 && $REUSE_NGINX -eq 1 ]]; then
  step "nginx"
  nginx -t >/dev/null 2>&1 || { nginx -t; die "Konfigurasi nginx yang ada tidak valid."; }
  systemctl reload nginx
  ok "Konfigurasi lama dipertahankan untuk $DOMAIN (tidak ada perubahan diminta)"
  info "Untuk mengubahnya: setup.sh --upgrade --domain <baru> --tls self-signed|existing"
  BASE_URL="https://$DOMAIN"
elif [[ $INSTALL_NGINX -eq 1 ]]; then
  step "Mengonfigurasi nginx + TLS"

  [[ -n $DOMAIN    ]] || die "DOMAIN kosong — jalankan dengan --domain <ip-atau-fqdn>"
  if [[ $TLS_MODE == existing ]]; then
    [[ -r $CERT_FILE ]] || die "Sertifikat tidak terbaca: ${CERT_FILE:-<kosong>}"
    [[ -r $KEY_FILE  ]] || die "Private key tidak terbaca: ${KEY_FILE:-<kosong>}"
  fi

  if [[ $TLS_MODE == self-signed ]]; then
    CERT_FILE=/etc/ssl/certs/threatfeed-fullchain.pem
    KEY_FILE=/etc/ssl/private/threatfeed.key
    if [[ ! -f $CERT_FILE ]]; then
      # SAN diisi hostname DAN alamat IP utama. FortiGate umumnya dikonfigurasi
      # dengan IP, bukan nama host, dan sertifikat ber-CN hostname saja akan
      # ditolak dengan pesan menyesatkan "Server not reachable".
      HOST_IP=$(primary_ip)
      if [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="IP:$DOMAIN"
        [[ -n $HOST_IP && $HOST_IP != "$DOMAIN" ]] && SAN="$SAN,IP:$HOST_IP"
      else
        SAN="DNS:$DOMAIN"
        [[ -n $HOST_IP ]] && SAN="$SAN,IP:$HOST_IP"
      fi
      openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=$DOMAIN/O=networklabs.id" -addext "subjectAltName=$SAN" 2>/dev/null
      chmod 600 "$KEY_FILE"; chmod 644 "$CERT_FILE"
      ok "Sertifikat self-signed dibuat (CN=$DOMAIN, SAN=$SAN, 825 hari)"
      warn "FortiGate perlu 'set server-identity-check none' untuk sertifikat ini,"
      warn "atau ganti dengan sertifikat terbitan Networklabs-Root-CA."
    else
      ok "Sertifikat sudah ada — dipakai ulang"
    fi
  else
    ok "Memakai sertifikat: $CERT_FILE"
  fi

  sed -e "s|threatfeed.networklabs.id|$DOMAIN|g" \
      -e "s|127.0.0.1:8080|127.0.0.1:$BIND_PORT|g" \
      -e "s|/etc/ssl/certs/threatfeed-fullchain.pem|$CERT_FILE|" \
      -e "s|/etc/ssl/private/threatfeed.key|$KEY_FILE|" \
      "$SRC_DIR/deploy/nginx-threatfeed.conf" > /etc/nginx/sites-available/threatfeed.conf

  # Direktif `http2 on;` baru ada di nginx 1.25.1. Ubuntu 22.04 mengirim 1.18,
  # yang memakai bentuk lama `listen 443 ssl http2;`. Tanpa penyesuaian ini
  # nginx -t gagal dengan: unknown directive "http2".
  # sed -n 1p, bukan head -n1: head menutup pipe lebih dulu dan memicu SIGPIPE
  # pada `sort` di bawah `set -o pipefail`.
  ver_lt() {
    [[ $1 != "$2" ]] && [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | sed -n 1p) == "$1" ]]
  }
  NGX_VER=$(nginx -v 2>&1 | sed -n 's|.*/\([0-9.]*\).*|\1|p')
  if [[ -n $NGX_VER ]] && ver_lt "$NGX_VER" 1.25.1; then
    sed -i -e 's|^\(\s*listen 443 ssl\);|\1 http2;|' \
           -e 's|^\(\s*listen \[::\]:443 ssl\);|\1 http2;|' \
           -e '/^\s*http2 on;\s*$/d' \
           /etc/nginx/sites-available/threatfeed.conf
    info "nginx $NGX_VER — memakai sintaks 'listen … http2' (gaya lama)"
  else
    info "nginx ${NGX_VER:-?} — memakai direktif 'http2 on'"
  fi

  # proxy_params tidak selalu ada di Debian minimal
  if [[ ! -f /etc/nginx/proxy_params ]]; then
    cat > /etc/nginx/proxy_params <<'EOF'
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
EOF
    info "/etc/nginx/proxy_params dibuat"
  fi

  ln -sf /etc/nginx/sites-available/threatfeed.conf /etc/nginx/sites-enabled/threatfeed.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 || { nginx -t; die "Konfigurasi nginx tidak valid."; }
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx
  ok "nginx aktif untuk https://$DOMAIN/"

  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp  >/dev/null 2>&1 || true
    ok "Aturan ufw untuk 80/443 ditambahkan"
  fi
  BASE_URL="https://$DOMAIN"
else
  BASE_URL="http://127.0.0.1:$BIND_PORT"
  warn "Tanpa nginx — server hanya mendengar di 127.0.0.1:$BIND_PORT."
fi

#================================================================== self-test ==
step "Uji fungsional"
TEST_URL="http://127.0.0.1:$BIND_PORT"
RESP=$(curl -sS -X POST "$TEST_URL/api/v1/ingest" \
  -H "Authorization: Bearer $ING_TOKEN" -H 'Content-Type: application/json' \
  -d '{"commands":[{"name":"setup-selftest","command":"add","entries":[
       {"ip":"192.0.2.99","type":"Selftest","severity":"Low","confidence":1,
        "tlp":"TLP:WHITE","source":"setup.sh","comment":"Entri uji instalasi - aman dihapus"}]}]}')
grep -q '"status"' <<<"$RESP" || die "Ingest gagal. Respons: $RESP"
# Payload dibaca lewat stdin, bukan argv: menghindari neraka kutip bersarang
# antara bash dan Python (backslash-quote di dalam '…' adalah SyntaxError).
ING_SUM=$(printf '%s' "$RESP" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print(d["inserted"], "baru,", d["updated"], "diperbarui")')
ok "Ingest  → $ING_SUM"

# Path /clean dipakai di sini supaya hasilnya deterministik: kalau instalasi
# mengaktifkan komentar inline, baris menjadi "192.0.2.99 # ..." dan pencocokan
# baris-penuh (grep -qx) akan meleset padahal feed sebenarnya baik-baik saja.
FEED=$(curl -sS "$TEST_URL/api/v1/feed/fortigate/clean" -H "Authorization: Bearer $FGT_TOKEN")
grep -qx '192.0.2.99' <<<"$FEED" || die "Entri uji tidak muncul di feed.
    Diagnosa: curl -sS -H 'Authorization: Bearer <token>' $TEST_URL/api/v1/feed/fortigate/clean"
ok "Feed    → $(grep -c . <<<"$FEED") entri disajikan"

# Path yang akan benar-benar dipakai FortiGate, sesuai pilihan komentar.
FEED_LIVE=$(curl -sS "$TEST_URL${FGT_PATH:-/api/v1/feed/fortigate}" -H "Authorization: Bearer $FGT_TOKEN")
grep -q '192\.0\.2\.99' <<<"$FEED_LIVE" || die "Entri uji tidak muncul di path yang dipakai FortiGate."
ok "Format  → $(grep '192\.0\.2\.99' <<<"$FEED_LIVE" | sed -n 1p)"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TEST_URL/api/v1/ingest" \
       -H "Authorization: Bearer token-salah" -H 'Content-Type: application/json' -d '[]')
[[ $CODE == 401 ]] || die "Token salah seharusnya ditolak 401, dapat $CODE."
ok "Auth    → token salah ditolak (401)"

#=============================================================== threatfeedctl ==
if [[ $ENV_EDITOR -eq 1 ]]; then
  step "Mengaktifkan editor .env di dashboard"
  install -m 750 -o root -g root "$SRC_DIR/deploy/threatfeed-apply-env" \
    /usr/local/sbin/threatfeed-apply-env
  # Path unit systemd, BUKAN sudo. Unit utama berjalan dengan
  # NoNewPrivileges=true yang memblokir sudo sepenuhnya; melemahkan flag itu demi
  # satu fitur admin bukan pertukaran yang sepadan. Aplikasi cukup menuliskan
  # berkas kandidat, systemd yang menjalankan helper sebagai root.
  install -m 644 -o root -g root "$SRC_DIR/deploy/threatfeed-apply-env.service" \
    /etc/systemd/system/threatfeed-apply-env.service
  install -m 644 -o root -g root "$SRC_DIR/deploy/threatfeed-apply-env.path" \
    /etc/systemd/system/threatfeed-apply-env.path
  # Helper pemulihan database memakai pola yang sama: aplikasi menuliskan berkas
  # kandidat, systemd menjalankan helper sebagai root. Menukar berkas database
  # harus dilakukan dengan service berhenti, dan aplikasi tidak boleh punya hak
  # untuk menghentikan dirinya sendiri.
  install -m 750 -o root -g root "$SRC_DIR/deploy/threatfeed-restore-db" \
    /usr/local/sbin/threatfeed-restore-db
  install -m 644 -o root -g root "$SRC_DIR/deploy/threatfeed-restore-db.service" \
    /etc/systemd/system/threatfeed-restore-db.service
  install -m 644 -o root -g root "$SRC_DIR/deploy/threatfeed-restore-db.path" \
    /etc/systemd/system/threatfeed-restore-db.path
  systemctl daemon-reload
  systemctl enable --now threatfeed-apply-env.path >/dev/null 2>&1
  systemctl enable --now threatfeed-restore-db.path >/dev/null 2>&1
  # Aturan sudoers lama dari versi sebelumnya tidak lagi dipakai dan dibuang.
  rm -f /etc/sudoers.d/threatfeed
  if systemctl is-active --quiet threatfeed-restore-db.path; then
    ok "Helper pemulihan database aktif — tombol Pulihkan di dashboard siap"
  else
    warn "threatfeed-restore-db.path tidak aktif. Cek: systemctl status threatfeed-restore-db.path"
  fi
  if systemctl is-active --quiet threatfeed-apply-env.path; then
    ok "Helper root aktif lewat systemd path unit — halaman Konfigurasi Sistem siap"
  else
    warn "threatfeed-apply-env.path tidak aktif. Cek: systemctl status threatfeed-apply-env.path"
  fi
  # Nyalakan pada instalasi yang .env-nya dipertahankan. Hitung dulu jumlah
  # kemunculannya: menambah baris tanpa memeriksa akan menghasilkan kunci ganda,
  # dan helper root menolak berkas seperti itu.
  COUNT=$(grep -c '^TF_ALLOW_ENV_WRITE=' "$ENV_FILE" || true)
  if [[ ${COUNT:-0} -gt 1 ]]; then
    # Sisakan kemunculan terakhir — itulah nilai yang berlaku bagi systemd.
    LAST=$(grep -n '^TF_ALLOW_ENV_WRITE=' "$ENV_FILE" | sed -n '$p' | cut -d: -f1)
    awk -v keep="$LAST" 'NR!=keep && /^TF_ALLOW_ENV_WRITE=/ {next} {print}' \
      "$ENV_FILE" > "$ENV_FILE.dedup" && mv "$ENV_FILE.dedup" "$ENV_FILE"
    chown root:"$APP_USER" "$ENV_FILE"; chmod 640 "$ENV_FILE"
    warn "Kunci TF_ALLOW_ENV_WRITE ganda ditemukan dan sudah dirapikan"
    COUNT=1
  fi
  if [[ ${COUNT:-0} -eq 0 ]]; then
    printf '\n# Editor konfigurasi lewat dashboard (butuh helper root)\nTF_ALLOW_ENV_WRITE=true\n' >> "$ENV_FILE"
    systemctl restart threatfeed
  elif ! grep -q '^TF_ALLOW_ENV_WRITE=true' "$ENV_FILE"; then
    sed -i 's|^TF_ALLOW_ENV_WRITE=.*|TF_ALLOW_ENV_WRITE=true|' "$ENV_FILE"
    systemctl restart threatfeed
  fi
fi

step "Memasang perintah bantu 'threatfeedctl'"
install -m 755 "$SRC_DIR/deploy/threatfeedctl" "$CTL" 2>/dev/null \
  || warn "deploy/threatfeedctl tidak ditemukan — dilewati"
[[ -x $CTL ]] && ok "$CTL siap"

#==================================================================== ringkasan =
# Tanpa query string: CLI FortiGate kadang memakan karakter "?" saat `set resource`
# diketik langsung, menghasilkan 404 yang dilaporkan sebagai "Server not reachable".
FGT_RESOURCE="$BASE_URL$FGT_PATH"
IDENTITY_CHECK=$([[ $TLS_MODE == self-signed ]] && echo none || echo full)

{
cat <<EOF
$APP_NAME — ringkasan instalasi
Dipasang: $(date -Is)   Host: $DOMAIN   Port internal: $BIND_PORT   TTL: $TTL_DAYS hari

DASHBOARD
  URL       : $BASE_URL/
  Password  : $ADM_PASS

TOKEN FORTISOAR (Authorization: Bearer ...)
  Endpoint  : $BASE_URL/api/v1/ingest
  Token     : $ING_TOKEN

TOKEN FORTIGATE
  Endpoint  : $FGT_RESOURCE
  Token     : $FGT_TOKEN

KONFIGURASI FORTIGATE — salin-tempel ke CLI
config system external-resource
    edit "IoC-WATCH-Blocklist"
        set type address
        set resource "$FGT_RESOURCE"
        set refresh-rate 5
        set server-identity-check $IDENTITY_CHECK
        set username "fortigate"
        set password $FGT_TOKEN
        set status enable
    next
end

UJI PUSH DARI FORTISOAR
curl -sS -X POST $BASE_URL/api/v1/ingest \\
  -H "Authorization: Bearer $ING_TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"commands":[{"name":"test","command":"add","entries":[
       {"ip":"103.74.20.57","type":"Malware","severity":"Malicious",
        "confidence":100,"tlp":"TLP:RED","comment":"C2 Server"}]}]}'

BERKAS
  Kode      : $APP_DIR
  Database  : $DATA_DIR/threatfeed.db
  Konfigurasi: $ENV_FILE
  Unit      : $UNIT
EOF
} > "$SUMMARY"
chown root:"$APP_USER" "$SUMMARY"; chmod 640 "$SUMMARY"

printf '\n%s' "$C_G"
printf '═%.0s' {1..74}; printf '%s\n' "$C_0"
printf '  %sInstalasi selesai — %s siap dipakai%s\n' "$C_B" "$APP_NAME" "$C_0"
printf '%s' "$C_G"; printf '═%.0s' {1..74}; printf '%s\n\n' "$C_0"

printf '  %sDashboard%s   %s/\n' "$C_B" "$C_0" "$BASE_URL"
printf '  %sPassword%s    %s%s%s\n\n' "$C_B" "$C_0" "$C_Y" "$ADM_PASS" "$C_0"
printf '  %sToken FortiSOAR%s\n    %s\n' "$C_B" "$C_0" "$ING_TOKEN"
printf '  %sToken FortiGate%s\n    %s\n\n' "$C_B" "$C_0" "$FGT_TOKEN"
printf '  %sKonfigurasi FortiGate siap tempel dan contoh curl tersimpan di:%s\n' "$C_B" "$C_0"
printf '    %s\n\n' "$SUMMARY"
printf '  Lihat lagi kapan saja : %sthreatfeedctl creds%s\n' "$C_C" "$C_0"
printf '  Status & log          : %sthreatfeedctl status%s  /  %sthreatfeedctl logs%s\n' "$C_C" "$C_0" "$C_C" "$C_0"
printf '  Kirim IoC uji         : %sthreatfeedctl test 1.2.3.4%s\n' "$C_C" "$C_0"
printf '  Intip isi feed        : %sthreatfeedctl feed%s\n\n' "$C_C" "$C_0"

if [[ -z $SOAR_IP || -z $FGT_IP ]]; then
  printf '  %sLangkah lanjutan yang disarankan%s\n' "$C_Y" "$C_0"
  [[ -z $SOAR_IP ]] && printf '    · Batasi ingest ke IP FortiSOAR  → TF_INGEST_ALLOWED_CIDRS di %s\n' "$ENV_FILE"
  [[ -z $FGT_IP  ]] && printf '    · Batasi feed ke IP FortiGate    → TF_FEED_ALLOWED_CIDRS di %s\n' "$ENV_FILE"
  printf '    · Setelah diubah: %ssystemctl restart threatfeed%s\n\n' "$C_C" "$C_0"
fi
if [[ $TLS_MODE == self-signed ]]; then
  printf '  %sSertifikat masih self-signed.%s FortiGate dipasang dengan\n' "$C_Y" "$C_0"
  printf '  server-identity-check none. Untuk produksi, terbitkan sertifikat dari\n'
  printf '  Networklabs-Root-CA, ganti berkas di /etc/ssl, lalu naikkan ke "full".\n\n'
fi

trap - ERR
