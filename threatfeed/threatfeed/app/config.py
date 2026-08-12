"""Konfigurasi terpusat. Semua nilai dibaca dari environment (systemd EnvironmentFile)."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def _list(key: str, default: str = "") -> list[str]:
    raw = os.getenv(key, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


# --- Identitas -------------------------------------------------------------
APP_NAME = os.getenv("TF_APP_NAME", "IoC-WATCH Threat Feed Server")
APP_ENV = os.getenv("TF_ENV", "production")

# --- Storage ---------------------------------------------------------------
DB_PATH = os.getenv("TF_DB_PATH", str(BASE_DIR / "data" / "threatfeed.db"))

# --- Kredensial ------------------------------------------------------------
# Token untuk FortiSOAR -> POST /api/v1/ingest  (boleh lebih dari satu, koma)
INGEST_TOKENS = _list("TF_INGEST_TOKENS")
# Token untuk FortiGate -> GET /api/v1/feed/fortigate (kosong = feed publik)
FEED_TOKENS = _list("TF_FEED_TOKENS")
# Username HTTP Basic yang dikirim FortiGate (`set username` pada external-resource).
# Kosong = username apa pun diterima, hanya password/token yang diperiksa. Ini
# perilaku lama dan tetap menjadi default supaya instalasi yang sudah berjalan
# tidak putus saat aplikasi ditingkatkan.
FEED_USERNAME = os.getenv("TF_FEED_USERNAME", "").strip()
# Password login dashboard
ADMIN_PASSWORD = os.getenv("TF_ADMIN_PASSWORD", "")
# Kunci HMAC untuk signed session cookie
SECRET_KEY = os.getenv("TF_SECRET_KEY") or secrets.token_hex(32)
SESSION_TTL_HOURS = _int("TF_SESSION_TTL_HOURS", 12)
COOKIE_SECURE = _bool("TF_COOKIE_SECURE", True)
# Halaman System Configuration menulis ulang /etc/threatfeed/threatfeed.env lewat
# helper root. Nonaktif secara default: fitur ini memperluas dampak pembajakan
# sesi dashboard dari "ubah kebijakan" menjadi "ubah kredensial", jadi harus
# dinyalakan secara sadar oleh operator.
ALLOW_ENV_WRITE = _bool("TF_ALLOW_ENV_WRITE", False)

# --- Kebijakan feed --------------------------------------------------------
TTL_DAYS = _int("TF_TTL_DAYS", 30)              # indikator dianggap basi setelah N hari
HARD_DELETE_DAYS = _int("TF_HARD_DELETE_DAYS", 0)  # 0 = jangan pernah hapus permanen
PRUNE_INTERVAL_SECONDS = _int("TF_PRUNE_INTERVAL_SECONDS", 3600)
FEED_MAX_ENTRIES = _int("TF_FEED_MAX_ENTRIES", 131072)  # batas keras FortiOS
# Default OFF: dokumentasi FortiOS hanya menjamin komentar baris-penuh (# ...),
# bukan komentar inline setelah IP. Aktifkan hanya setelah divalidasi di FortiGate.
FEED_INLINE_COMMENTS = _bool("TF_FEED_INLINE_COMMENTS", False)
FEED_MIN_CONFIDENCE = _int("TF_FEED_MIN_CONFIDENCE", 0)
# Isi komentar inline: full | short | plain
FEED_COMMENT_FORMAT = os.getenv("TF_FEED_COMMENT_FORMAT", "plain").strip().lower()
# CIDR yang boleh menarik feed (kosong = semua). Contoh: "10.0.0.0/8,203.0.113.5/32"
FEED_ALLOWED_CIDRS = _list("TF_FEED_ALLOWED_CIDRS")
INGEST_ALLOWED_CIDRS = _list("TF_INGEST_ALLOWED_CIDRS")

# --- Jaringan --------------------------------------------------------------
TRUST_PROXY = _bool("TF_TRUST_PROXY", True)   # baca X-Forwarded-For dari nginx
AUDIT_RETENTION_DAYS = _int("TF_AUDIT_RETENTION_DAYS", 90)

# --- Nilai default entri ---------------------------------------------------
DEFAULT_TYPE = os.getenv("TF_DEFAULT_TYPE", "IP Address")
DEFAULT_SEVERITY = os.getenv("TF_DEFAULT_SEVERITY", "Medium")
DEFAULT_TLP = os.getenv("TF_DEFAULT_TLP", "TLP:AMBER")
DEFAULT_SOURCE = os.getenv("TF_DEFAULT_SOURCE", "FortiSOAR")
DEFAULT_CONFIDENCE = _int("TF_DEFAULT_CONFIDENCE", 50)
