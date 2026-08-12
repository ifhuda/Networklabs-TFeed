"""Pengaturan yang dapat diubah lewat dashboard.

Berkas `.env` tetap menjadi sumber nilai awal. Perubahan dari dashboard disimpan
sebagai override di tabel `settings` lalu diterapkan ke modul `config` saat itu
juga, sehingga berlaku tanpa restart.

Alasan override disimpan di database dan bukan ditulis balik ke `.env`: service
berjalan sebagai akun `threatfeed`, sedangkan `/etc/threatfeed/threatfeed.env`
dimiliki root dengan mode 640. Memberi izin tulis ke berkas itu berarti proses
yang menghadap jaringan bisa mengubah konfigurasinya sendiri — termasuk kredensial.
Batasan itu sengaja dipertahankan.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable

from . import config
from .database import get_conn, transaction, utcnow


class ValidationError(ValueError):
    pass


# --------------------------------------------------------------- validator ---
def _int(lo: int, hi: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        try:
            n = int(str(v).strip())
        except (TypeError, ValueError):
            raise ValidationError(f"harus berupa angka, diberikan: {v!r}")
        if not lo <= n <= hi:
            raise ValidationError(f"harus antara {lo} dan {hi}, diberikan: {n}")
        return n
    return check


def _bool(v: Any) -> bool:
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    raise ValidationError(f"harus true atau false, diberikan: {v!r}")


def _enum(*allowed: str) -> Callable[[Any], str]:
    def check(v: Any) -> str:
        s = str(v).strip().lower()
        if s not in allowed:
            raise ValidationError(f"harus salah satu dari {', '.join(allowed)}")
        return s
    return check


def _text(limit: int = 128) -> Callable[[Any], str]:
    def check(v: Any) -> str:
        s = " ".join(str(v or "").split())
        if len(s) > limit:
            raise ValidationError(f"maksimal {limit} karakter")
        return s
    return check


def _cidr_list(v: Any) -> str:
    """Daftar CIDR dipisah koma. Loopback selalu dipertahankan.

    Tanpa penjagaan ini, satu salah ketik di dashboard bisa mengunci
    `threatfeedctl` — yang memanggil API dari 127.0.0.1 — dan memutus jalur
    pemulihan lewat CLI.
    """
    raw = [x.strip() for x in str(v or "").split(",") if x.strip()]
    if not raw:
        return ""
    out: list[str] = []
    for item in raw:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValidationError(f"bukan CIDR yang valid: {item}")
        if item not in out:
            out.append(item)
    for loop in ("127.0.0.1/32", "::1/128"):
        if loop not in out:
            out.insert(0, loop)
    return ",".join(out)


# ------------------------------------------------------------------ skema ----
# key: (atribut di config, validator, label, grup, keterangan)
EDITABLE: dict[str, tuple] = {
    "TF_TTL_DAYS": (
        "TTL_DAYS", _int(0, 3650), "TTL indikator (hari)", "Kebijakan feed",
        "Indikator berhenti disajikan setelah sekian hari tanpa pembaruan. 0 = tidak pernah kedaluwarsa."),
    "TF_HARD_DELETE_DAYS": (
        "HARD_DELETE_DAYS", _int(0, 3650), "Hapus permanen setelah (hari)", "Kebijakan feed",
        "Baris kedaluwarsa dihapus permanen setelah sekian hari. 0 = simpan selamanya."),
    "TF_FEED_MIN_CONFIDENCE": (
        "FEED_MIN_CONFIDENCE", _int(0, 100), "Confidence minimum", "Kebijakan feed",
        "Indikator di bawah nilai ini tidak disajikan ke FortiGate."),
    "TF_FEED_MAX_ENTRIES": (
        "FEED_MAX_ENTRIES", _int(1, 131072), "Batas entri per feed", "Kebijakan feed",
        "Batas keras FortiOS adalah 131072 entri atau 10 MB."),

    "TF_FEED_INLINE_COMMENTS": (
        "FEED_INLINE_COMMENTS", _bool, "Komentar inline di feed", "Format feed",
        "Sertakan komentar setelah IP pada path dasar. FortiOS tidak menjamin format ini — validasi jumlah entri di FortiGate."),
    "TF_FEED_COMMENT_FORMAT": (
        "FEED_COMMENT_FORMAT", _enum("plain", "short", "full"), "Isi komentar", "Format feed",
        "plain = kolom comment saja · short = tipe + comment · full = seluruh metadata."),

    "TF_DEFAULT_TYPE": (
        "DEFAULT_TYPE", _text(64), "Type", "Nilai default entri",
        "Dipakai bila pengirim tidak menyertakan field ini."),
    "TF_DEFAULT_SEVERITY": (
        "DEFAULT_SEVERITY", _text(32), "Severity", "Nilai default entri", ""),
    "TF_DEFAULT_TLP": (
        "DEFAULT_TLP", _enum("tlp:red", "tlp:amber", "tlp:amber+strict", "tlp:green", "tlp:white"),
        "TLP", "Nilai default entri", ""),
    "TF_DEFAULT_SOURCE": (
        "DEFAULT_SOURCE", _text(128), "Source", "Nilai default entri", ""),
    "TF_DEFAULT_CONFIDENCE": (
        "DEFAULT_CONFIDENCE", _int(0, 100), "Confidence", "Nilai default entri", ""),

    "TF_INGEST_ALLOWED_CIDRS": (
        "INGEST_ALLOWED_CIDRS", _cidr_list, "Allowlist ingest", "Kontrol akses",
        "CIDR yang boleh push indikator, dipisah koma. Kosong = semua IP. Loopback selalu ditambahkan."),
    "TF_FEED_ALLOWED_CIDRS": (
        "FEED_ALLOWED_CIDRS", _cidr_list, "Allowlist feed", "Kontrol akses",
        "CIDR yang boleh menarik feed. Kosong = semua IP. Loopback selalu ditambahkan."),

    "TF_PRUNE_INTERVAL_SECONDS": (
        "PRUNE_INTERVAL_SECONDS", _int(60, 86400), "Interval pruning (detik)", "Pemeliharaan",
        "Seberapa sering indikator basi ditandai kedaluwarsa."),
    "TF_AUDIT_RETENTION_DAYS": (
        "AUDIT_RETENTION_DAYS", _int(1, 3650), "Retensi audit (hari)", "Pemeliharaan",
        "Jejak audit yang lebih tua dari ini dipangkas otomatis."),
}

# Sengaja TIDAK dapat diubah lewat dashboard: token, password, kunci sesi, path
# database, dan flag proxy. Semuanya berada di .env dan hanya bisa diubah oleh
# root di server — mengubahnya lewat antarmuka web akan memperluas dampak
# pembajakan sesi dashboard menjadi pengambilalihan penuh.
SECRET_KEYS = ("TF_INGEST_TOKENS", "TF_FEED_TOKENS", "TF_ADMIN_PASSWORD",
               "TF_SECRET_KEY", "TF_DB_PATH", "TF_TRUST_PROXY", "TF_COOKIE_SECURE")


# ------------------------------------------------------------- penyimpanan ---
def _as_env_string(attr: str) -> str:
    val = getattr(config, attr)
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, list):
        return ",".join(val)
    return str(val)


def overrides() -> dict[str, str]:
    rows = get_conn().execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


def apply_to_config() -> list[str]:
    """Terapkan override dari database ke modul config. Kembalikan kunci yang gagal."""
    failed: list[str] = []
    for key, value in overrides().items():
        spec = EDITABLE.get(key)
        if not spec:
            continue
        attr, validate = spec[0], spec[1]
        try:
            parsed = validate(value)
        except ValidationError:
            failed.append(key)
            continue
        if key.endswith("_CIDRS"):
            parsed = [x.strip() for x in str(parsed).split(",") if x.strip()]
        elif key == "TF_DEFAULT_TLP":
            parsed = str(parsed).upper()
        setattr(config, attr, parsed)
    return failed


def current() -> list[dict]:
    """Nilai efektif setiap pengaturan, plus asalnya (.env atau dashboard)."""
    ov = overrides()
    out = []
    for key, (attr, _v, label, group, help_text) in EDITABLE.items():
        out.append({
            "key": key, "label": label, "group": group, "help": help_text,
            "value": _as_env_string(attr),
            "source": "dashboard" if key in ov else "env",
            "kind": ("bool" if key in ("TF_FEED_INLINE_COMMENTS",) else
                     "enum" if key in ("TF_FEED_COMMENT_FORMAT", "TF_DEFAULT_TLP") else
                     "int" if key.endswith(("_DAYS", "_SECONDS", "_ENTRIES", "_CONFIDENCE")) else
                     "text"),
            "options": (["plain", "short", "full"] if key == "TF_FEED_COMMENT_FORMAT" else
                        ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:WHITE"]
                        if key == "TF_DEFAULT_TLP" else []),
        })
    return out


def update(changes: dict[str, Any], actor: str = "") -> dict:
    """Validasi seluruh perubahan lebih dulu, baru simpan. Semua-atau-tidak sama sekali."""
    if not changes:
        return {"changed": [], "values": {}}

    unknown = [k for k in changes if k not in EDITABLE]
    if unknown:
        raise ValidationError(f"pengaturan tidak dikenal atau tidak dapat diubah: {', '.join(unknown)}")

    validated: dict[str, str] = {}
    errors: dict[str, str] = {}
    for key, raw in changes.items():
        try:
            parsed = EDITABLE[key][1](raw)
        except ValidationError as exc:
            errors[key] = str(exc)
            continue
        validated[key] = "true" if parsed is True else "false" if parsed is False else str(parsed)

    if errors:
        raise ValidationError("; ".join(f"{k}: {v}" for k, v in errors.items()))

    now = utcnow()
    with transaction() as conn:
        for key, value in validated.items():
            conn.execute(
                "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (key, value, now, actor[:64]))

    apply_to_config()
    return {"changed": sorted(validated), "values": validated}


def reset(keys: list[str] | None = None, actor: str = "") -> list[str]:
    """Buang override sehingga nilai kembali mengikuti .env."""
    targets = [k for k in (keys or list(EDITABLE)) if k in EDITABLE]
    existing = set(overrides())
    targets = [k for k in targets if k in existing]   # laporkan yang benar-benar dibuang
    if not targets:
        return []
    with transaction() as conn:
        conn.execute(f"DELETE FROM settings WHERE key IN ({','.join('?' * len(targets))})", targets)

    # config dimuat ulang agar nilai .env terbaca dari awal, lalu override yang
    # tersisa ditumpuk kembali. SECRET_KEY diselamatkan lebih dulu: config.py
    # membangkitkan kunci acak baru bila TF_SECRET_KEY tidak diset, dan reload
    # tanpa penjagaan ini akan memutus setiap sesi dashboard yang sedang aktif —
    # termasuk sesi yang baru saja menekan tombol reset.
    import importlib
    preserved_key = config.SECRET_KEY
    importlib.reload(config)
    config.SECRET_KEY = preserved_key
    apply_to_config()
    return targets
