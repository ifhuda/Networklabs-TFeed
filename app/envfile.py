"""Baca dan tulis /etc/threatfeed/threatfeed.env tanpa merusak strukturnya.

Modul ini TIDAK menulis langsung ke /etc. Service berjalan sebagai akun
`threatfeed` yang tidak punya izin tulis ke sana — itu disengaja. Alur
penulisannya:

    aplikasi  ──stage──▶  /var/lib/threatfeed/pending.env   (milik threatfeed, 600)
                          │
                          └─sudo──▶  threatfeed-apply-env   (root)
                                     validasi ulang, backup, pasang, restart

Helper root memvalidasi ulang setiap baris dari nol. Aplikasi yang menghadap
jaringan diperlakukan sebagai pihak yang tidak dipercaya, sehingga bug atau
pembajakan sesi di sisi web tidak otomatis berarti kendali penuh atas
konfigurasi.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Callable

from . import config

ENV_PATH = Path(os.getenv("TF_ENV_FILE", "/etc/threatfeed/threatfeed.env"))
SPOOL_PATH = Path(config.DB_PATH).parent / "pending.env"
RESULT_PATH = Path(config.DB_PATH).parent / "apply-result"
APPLY_HELPER = os.getenv("TF_APPLY_HELPER", "/usr/local/sbin/threatfeed-apply-env")
APPLY_UNIT = "threatfeed-apply-env.path"

# Nilai yang tidak diubah pengguna dikirim kembali sebagai sentinel ini, bukan
# sebagai nilai aslinya: rahasia tidak pernah keluar dari server ke browser.
UNCHANGED = "\x00__TF_UNCHANGED__"
MASK = "••••••••"


class EnvError(ValueError):
    pass


# ------------------------------------------------------------------ validator
def v_int(lo: int, hi: int) -> Callable[[Any], str]:
    def check(v: Any) -> str:
        try:
            n = int(str(v).strip())
        except (TypeError, ValueError):
            raise EnvError(f"harus angka, diberikan: {v!r}")
        if not lo <= n <= hi:
            raise EnvError(f"harus antara {lo} dan {hi}, diberikan: {n}")
        return str(n)
    return check


def v_bool(v: Any) -> str:
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return "true"
    if s in {"0", "false", "no", "off"}:
        return "false"
    raise EnvError(f"harus true atau false, diberikan: {v!r}")


def v_enum(*allowed: str) -> Callable[[Any], str]:
    def check(v: Any) -> str:
        s = str(v).strip()
        match = next((a for a in allowed if a.lower() == s.lower()), None)
        if match is None:
            raise EnvError(f"harus salah satu dari: {', '.join(allowed)}")
        return match
    return check


_SAFE = re.compile(r'^[A-Za-z0-9 _\-./:+@,=\[\]()%|]*$')


def v_text(limit: int = 256, allow_empty: bool = True) -> Callable[[Any], str]:
    """Charset konservatif. Menolak kutip, $, backtick, backslash, dan karakter
    kontrol — berkas ini dibaca systemd EnvironmentFile dan kadang di-`source`
    oleh skrip shell, sehingga nilai bebas bisa berubah menjadi eksekusi perintah."""
    def check(v: Any) -> str:
        s = " ".join(str(v or "").split())
        if not s and not allow_empty:
            raise EnvError("tidak boleh kosong")
        if len(s) > limit:
            raise EnvError(f"maksimal {limit} karakter")
        if not _SAFE.match(s):
            raise EnvError("mengandung karakter yang tidak diizinkan "
                           "(kutip, $, backtick, backslash, atau karakter kontrol)")
        return s
    return check


def v_token_list(v: Any) -> str:
    """Satu atau beberapa token dipisah koma. Rotasi tanpa downtime memakai dua nilai."""
    parts = [p.strip() for p in str(v or "").split(",") if p.strip()]
    if not parts:
        raise EnvError("tidak boleh kosong — endpoint akan menolak semua request")
    for p in parts:
        if not re.fullmatch(r"[A-Za-z0-9_\-.:]{8,256}", p):
            raise EnvError("token hanya boleh huruf, angka, _ - . : dan minimal 8 karakter")
    if len(parts) > 4:
        raise EnvError("maksimal 4 token sekaligus")
    return ",".join(parts)


def v_username(v: Any) -> str:
    """Username Basic auth FortiGate. Kosong = terima username apa pun."""
    s = str(v or "").strip()
    if not s:
        return ""
    if ":" in s:
        raise EnvError("tidak boleh mengandung ':' — karakter itu memisahkan "
                       "username dan password pada HTTP Basic")
    if not re.fullmatch(r"[A-Za-z0-9_\-.@]{1,64}", s):
        raise EnvError("hanya huruf, angka, _ - . @ dan maksimal 64 karakter")
    return s


def v_password(v: Any) -> str:
    s = str(v or "")
    if len(s) < 12:
        raise EnvError("minimal 12 karakter")
    if len(s) > 128:
        raise EnvError("maksimal 128 karakter")
    if not _SAFE.match(s):
        raise EnvError("mengandung karakter yang tidak diizinkan "
                       "(kutip, $, backtick, backslash, atau spasi ganda)")
    return s


def v_hexkey(v: Any) -> str:
    s = str(v or "").strip()
    if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", s):
        raise EnvError("harus hex 32–128 karakter (buat dengan: openssl rand -hex 32)")
    return s


def v_path(v: Any) -> str:
    s = str(v or "").strip()
    if not s.startswith("/"):
        raise EnvError("harus path absolut")
    if not re.fullmatch(r"[A-Za-z0-9_\-./]{2,255}", s) or ".." in s:
        raise EnvError("path hanya boleh huruf, angka, _ - . / dan tanpa '..'")
    return s


def v_cidrs(v: Any) -> str:
    """Daftar CIDR dipisah koma. Loopback selalu dipertahankan.

    Tanpa penjagaan ini, satu salah ketik di GUI bisa mengunci `threatfeedctl`
    yang memanggil API dari 127.0.0.1, sekaligus memutus jalur pemulihan CLI.
    """
    raw = [x.strip() for x in str(v or "").split(",") if x.strip()]
    if not raw:
        return ""
    out: list[str] = []
    for item in raw:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise EnvError(f"bukan CIDR yang valid: {item}")
        if item not in out:
            out.append(item)
    for loop in ("127.0.0.1/32", "::1/128"):
        if loop not in out:
            out.insert(0, loop)
    return ",".join(out)


# ---------------------------------------------------------------------- skema
# key: dict(group, label, kind, validate, secret, help, options, default)
SCHEMA: dict[str, dict] = {
    # --- 1. Identitas & storage ---------------------------------------------
    "TF_APP_NAME": dict(
        group="Identitas & Storage", label="Nama aplikasi", kind="text",
        validate=v_text(64, allow_empty=False), default="IoC-WATCH Threat Feed Server",
        help="Muncul di judul dashboard dan baris header berkas feed."),
    "TF_DB_PATH": dict(
        group="Identitas & Storage", label="Path database", kind="text",
        validate=v_path, default="/var/lib/threatfeed/threatfeed.db",
        help="Memindahkan path berarti memulai database kosong. Backup dulu, "
             "lalu pindahkan berkasnya secara manual sebelum menyimpan.",
        danger="Salah isi = service kehilangan seluruh indikator yang ada."),

    # --- 2. Kredensial & keamanan -------------------------------------------
    "TF_INGEST_TOKENS": dict(
        group="Kredensial & Keamanan", label="Token ingest (FortiSOAR)", kind="secret",
        validate=v_token_list, secret=True, generate="hex32",
        help="Dipakai FortiSOAR dan integrasi lain. Pisahkan dua token dengan koma "
             "untuk rotasi tanpa downtime: token_baru,token_lama."),
    "TF_FEED_USERNAME": dict(
        group="Kredensial & Keamanan", label="Username feed (FortiGate)", kind="text",
        validate=v_username, default="",
        help="Nilai untuk `set username` pada external-resource FortiGate. "
             "Kosongkan agar username apa pun diterima — hanya token yang diperiksa. "
             "Diisi berarti FortiGate harus mengirim username yang sama persis.",
        danger="Mengisi ini setelah FortiGate berjalan akan memutus tarikan feed "
               "sampai `set username` di FortiGate diselaraskan."),
    "TF_FEED_TOKENS": dict(
        group="Kredensial & Keamanan", label="Token feed (FortiGate)", kind="secret",
        validate=v_token_list, secret=True, generate="hex32",
        help="Dikirim FortiGate sebagai HTTP Basic password. Ubah di sini berarti "
             "harus diperbarui juga di `config system external-resource`."),
    "TF_ADMIN_PASSWORD": dict(
        group="Kredensial & Keamanan", label="Password dashboard", kind="secret",
        validate=v_password, secret=True, generate="pass20",
        help="Minimal 12 karakter. Mengubahnya akan memutus sesi Anda sendiri "
             "setelah service restart."),
    "TF_SECRET_KEY": dict(
        group="Kredensial & Keamanan", label="Kunci sesi (HMAC)", kind="secret",
        validate=v_hexkey, secret=True, generate="hex32",
        help="Menandatangani cookie sesi. Mengubahnya memutus semua sesi aktif."),
    "TF_SESSION_TTL_HOURS": dict(
        group="Kredensial & Keamanan", label="Masa berlaku sesi (jam)", kind="int",
        validate=v_int(1, 720), default="12",
        help="Berapa lama login dashboard bertahan sebelum diminta ulang."),
    "TF_COOKIE_SECURE": dict(
        group="Kredensial & Keamanan", label="Cookie hanya lewat HTTPS", kind="bool",
        validate=v_bool, default="true",
        help="Biarkan true bila diakses lewat HTTPS. Set false HANYA untuk lab "
             "HTTP polos — kalau tidak, browser membuang cookie dan login gagal terus."),

    # --- 3. Kebijakan feed ---------------------------------------------------
    "TF_TTL_DAYS": dict(
        group="Kebijakan Feed", label="TTL indikator (hari)", kind="int",
        validate=v_int(0, 3650), default="30",
        help="Indikator berhenti disajikan setelah sekian hari tanpa pembaruan "
             "dari FortiSOAR. 0 = tidak pernah kedaluwarsa."),
    "TF_HARD_DELETE_DAYS": dict(
        group="Kebijakan Feed", label="Hapus permanen setelah (hari)", kind="int",
        validate=v_int(0, 3650), default="0",
        help="Baris kedaluwarsa dihapus dari database setelah sekian hari. "
             "0 = simpan selamanya untuk keperluan audit."),
    "TF_PRUNE_INTERVAL_SECONDS": dict(
        group="Kebijakan Feed", label="Interval pruning (detik)", kind="int",
        validate=v_int(60, 86400), default="3600",
        help="Seberapa sering indikator basi ditandai kedaluwarsa. Feed sendiri "
             "sudah menyaring saat dibaca, jadi ini hanya perawatan."),
    "TF_FEED_MAX_ENTRIES": dict(
        group="Kebijakan Feed", label="Batas entri per feed", kind="int",
        validate=v_int(1, 131072), default="131072",
        help="Batas keras FortiOS: 131072 entri atau 10 MB, mana yang lebih dulu."),
    "TF_FEED_MIN_CONFIDENCE": dict(
        group="Kebijakan Feed", label="Confidence minimum", kind="int",
        validate=v_int(0, 100), default="0",
        help="Indikator di bawah nilai ini tidak disajikan ke FortiGate."),
    "TF_FEED_INLINE_COMMENTS": dict(
        group="Kebijakan Feed", label="Komentar inline di feed", kind="bool",
        validate=v_bool, default="false",
        help="Sertakan komentar setelah IP pada path dasar. FortiOS hanya menjamin "
             "komentar baris-penuh — setelah mengaktifkan ini, cocokkan jumlah entri "
             "di `diagnose sys external-resource entry-list` dengan `threatfeedctl feed`."),
    "TF_FEED_COMMENT_FORMAT": dict(
        group="Kebijakan Feed", label="Isi komentar", kind="enum",
        options=["plain", "short", "full"], validate=v_enum("plain", "short", "full"),
        default="plain",
        help="plain: hanya kolom comment · short: tipe + comment · "
             "full: tipe, severity/confidence, TLP, source, comment."),

    # --- 4. Kontrol akses jaringan ------------------------------------------
    "TF_INGEST_ALLOWED_CIDRS": dict(
        group="Kontrol Akses Jaringan", label="CIDR yang boleh push", kind="text",
        validate=v_cidrs, default="",
        help="Contoh: 192.168.120.9/32,10.10.10.0/24. Kosong berarti SEMUA alamat "
             "diizinkan. Loopback ditambahkan otomatis."),
    "TF_FEED_ALLOWED_CIDRS": dict(
        group="Kontrol Akses Jaringan", label="CIDR yang boleh menarik feed", kind="text",
        validate=v_cidrs, default="",
        help="Isi dengan alamat FortiGate. Kosong berarti SEMUA alamat diizinkan. "
             "Pakai IP asli setelah NAT — lihat kolom Klien pada jejak audit."),
    "TF_TRUST_PROXY": dict(
        group="Kontrol Akses Jaringan", label="Percayai header proxy", kind="bool",
        validate=v_bool, default="true",
        help="Baca X-Forwarded-For dari nginx. Set false bila uvicorn diakses langsung, "
             "kalau tidak klien bisa memalsukan alamatnya sendiri.",
        danger="true tanpa reverse proxy di depan = allowlist CIDR dapat dilewati."),

    # --- 5. Retensi & default entri -----------------------------------------
    "TF_AUDIT_RETENTION_DAYS": dict(
        group="Retensi & Default Entri", label="Retensi jejak audit (hari)", kind="int",
        validate=v_int(1, 3650), default="90",
        help="Entri audit lebih tua dari ini dipangkas saat pruning."),
    "TF_BACKUP_ENABLED": dict(
        group="Backup & Pemulihan", label="Backup otomatis", kind="bool",
        validate=v_bool, default="true",
        help="Service membuat snapshot database sendiri sesuai jadwal di bawah."),
    "TF_BACKUP_INTERVAL_HOURS": dict(
        group="Backup & Pemulihan", label="Interval backup (jam)", kind="int",
        validate=v_int(1, 8760), default="24",
        help="Jarak antar snapshot. Dihitung dari backup terakhir, bukan dari jam service start."),
    "TF_BACKUP_KEEP": dict(
        group="Backup & Pemulihan", label="Jumlah backup disimpan", kind="int",
        validate=v_int(1, 500), default="14",
        help="Snapshot terlama dibuang setelah melewati jumlah ini. "
             "Salinan pre-restore dikecualikan dan tidak pernah dibuang otomatis."),
    "TF_BACKUP_DIR": dict(
        group="Backup & Pemulihan", label="Direktori backup", kind="text",
        validate=v_path, default="/var/lib/threatfeed/backups",
        help="Harus dapat ditulis akun service. Unit systemd hanya mengizinkan "
             "penulisan di /var/lib/threatfeed — path lain perlu ReadWritePaths tambahan.",
        danger="Mengubah path tidak memindahkan backup lama."),
    "TF_SOAR_TAXII_ENABLED": dict(
        group="Tarik dari FortiSOAR", label="Aktifkan penarikan TAXII", kind="bool",
        validate=v_bool, default="false",
        help="Bila aktif, server menarik indikator dari koleksi TAXII FortiSOAR "
             "secara berkala — arah sebaliknya dari ingest push yang biasa."),
    "TF_SOAR_TAXII_URL": dict(
        group="Tarik dari FortiSOAR", label="Server Address (api-root)", kind="text",
        validate=v_text(256), default="",
        help="Dari FortiSOAR: Threat Feeds -> TAXII Server -> Server Address. "
             "Contoh: https://192.168.120.9:443/api/taxii/1/"),
    "TF_SOAR_TAXII_KEY_NAME": dict(
        group="Tarik dari FortiSOAR", label="Nama API Key", kind="text",
        validate=v_text(128), default="",
        help="Username autentikasi Basic — nama key di FortiSOAR, bukan key itu sendiri."),
    "TF_SOAR_TAXII_API_KEY": dict(
        group="Tarik dari FortiSOAR", label="API Key", kind="text",
        validate=v_text(256), secret=True, default="",
        help="Password autentikasi Basic. Dibuat di FortiSOAR: Settings -> API Key."),
    "TF_SOAR_TAXII_COLLECTION_ID": dict(
        group="Tarik dari FortiSOAR", label="ID Koleksi (bisa lebih dari satu)", kind="text",
        validate=v_text(512), default="",
        help="Satu atau lebih UUID koleksi TAXII, dipisah koma: "
             "25d1110d-...,34a3f04d-.... Setiap koleksi punya jadwal tarikannya "
             "sendiri. Isi lewat panel Tarik FortiSOAR -> Uji Koneksi, centang "
             "koleksi yang diinginkan, bukan diketik manual di sini."),
    "TF_SOAR_TAXII_COLLECTION_NAME": dict(
        group="Tarik dari FortiSOAR", label="Nama Koleksi", kind="text",
        validate=v_text(200), default="",
        help="Hanya untuk tampilan di dashboard — tidak memengaruhi penarikan."),
    "TF_SOAR_TAXII_FEED_NAME": dict(
        group="Tarik dari FortiSOAR", label="Nama feed lokal", kind="text",
        validate=v_text(64, allow_empty=False), default="FortiSOAR-TAXII",
        help="Label sumber indikator hasil tarikan ini di dashboard dan filter feed FortiGate."),
    "TF_SOAR_TAXII_POLL_MINUTES": dict(
        group="Tarik dari FortiSOAR", label="Interval polling (menit)", kind="int",
        validate=v_int(1, 1440), default="15",
        help="Jeda antar penarikan. FortiSOAR juga punya beban dari sisi query — "
             "jangan terlalu agresif pada koleksi besar."),
    "TF_SOAR_TAXII_VERIFY_TLS": dict(
        group="Tarik dari FortiSOAR", label="Verifikasi sertifikat TLS", kind="bool",
        validate=v_bool, default="true",
        danger="Nonaktifkan hanya untuk lab dengan sertifikat self-signed FortiSOAR. "
               "API key dikirim lewat koneksi itu — jangan matikan di jalur produksi."),
    "TF_DEFAULT_TYPE": dict(
        group="Retensi & Default Entri", label="Type", kind="text",
        validate=v_text(64, allow_empty=False), default="IP Address",
        help="Dipakai bila pengirim tidak menyertakan field type."),
    "TF_DEFAULT_SEVERITY": dict(
        group="Retensi & Default Entri", label="Severity", kind="enum",
        options=["Low", "Medium", "High", "Critical", "Malicious"],
        validate=v_enum("Low", "Medium", "High", "Critical", "Malicious"), default="Medium",
        help="Dipakai bila pengirim tidak menyertakan field severity."),
    "TF_DEFAULT_TLP": dict(
        group="Retensi & Default Entri", label="TLP", kind="enum",
        options=["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
        validate=v_enum("TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"), default="TLP:AMBER",
        help="Dipakai bila pengirim tidak menyertakan field tlp."),
    "TF_DEFAULT_SOURCE": dict(
        group="Retensi & Default Entri", label="Source", kind="text",
        validate=v_text(128, allow_empty=False), default="FortiSOAR",
        help="Label sumber untuk entri yang tidak menyebutkan asalnya."),
    "TF_DEFAULT_CONFIDENCE": dict(
        group="Retensi & Default Entri", label="Confidence", kind="int",
        validate=v_int(0, 100), default="50",
        help="Nilai confidence untuk entri yang tidak menyebutkannya."),
}

GROUP_ORDER = ["Identitas & Storage", "Kredensial & Keamanan", "Kebijakan Feed",
               "Kontrol Akses Jaringan", "Backup & Pemulihan", "Tarik dari FortiSOAR",
               "Retensi & Default Entri"]

# Perubahan yang membuat operator berpotensi mengunci diri sendiri.
LOCKOUT_KEYS = {"TF_ADMIN_PASSWORD", "TF_SECRET_KEY", "TF_COOKIE_SECURE", "TF_DB_PATH"}


# ---------------------------------------------------------------------- baca
_ASSIGN = re.compile(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')


def _unquote(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _quote(value: str) -> str:
    """Kutip hanya bila perlu — menjaga diff berkas tetap kecil dan terbaca."""
    return f'"{value}"' if (value == "" or re.search(r'[\s#]', value)) else value


def read_raw() -> list[str]:
    if not ENV_PATH.exists():
        raise EnvError(f"{ENV_PATH} tidak ditemukan")
    try:
        return ENV_PATH.read_text(encoding="utf-8").splitlines()
    except PermissionError as exc:
        raise EnvError(
            f"tidak dapat membaca {ENV_PATH}: {exc}. "
            f"Pastikan berkas dimiliki root:threatfeed dengan mode 640."
        ) from exc


def parse(lines: list[str] | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (lines if lines is not None else read_raw()):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ASSIGN.match(line)
        if m:
            values[m.group(2)] = _unquote(m.group(3))
    return values


def render(lines: list[str], updates: dict[str, str]) -> list[str]:
    """Ganti nilai di tempat. Komentar, baris kosong, dan urutan dipertahankan.

    Kunci yang belum ada ditambahkan di akhir dengan header sendiri, sehingga
    berkas yang dibuat versi lama tetap terbaca setelah aplikasi ditingkatkan.
    """
    remaining = dict(updates)

    # Kunci ganda dinonaktifkan, bukan dibiarkan: helper root menolaknya, dan
    # berkas seperti itu ambigu. Yang DIPERTAHANKAN adalah kemunculan TERAKHIR,
    # karena itulah nilai yang benar-benar berlaku — systemd EnvironmentFile
    # memakai penugasan terakhir. Menyimpan yang pertama justru akan diam-diam
    # mengembalikan nilai lama.
    last_index: dict[str, int] = {}
    for i, line in enumerate(lines):
        if line.strip() and not line.lstrip().startswith("#"):
            m = _ASSIGN.match(line)
            if m:
                last_index[m.group(2)] = i

    out: list[str] = []
    for i, line in enumerate(lines):
        m = _ASSIGN.match(line) if line.strip() and not line.lstrip().startswith("#") else None
        if not m:
            out.append(line)
            continue
        key = m.group(2)
        if last_index.get(key) != i:
            out.append(f"# [duplikat dinonaktifkan oleh dashboard] {line.strip()}")
            continue
        if key in remaining:
            out.append(f"{m.group(1)}{key}={_quote(remaining.pop(key))}")
        else:
            out.append(line)

    if remaining:
        out += ["", "# --- ditambahkan oleh dashboard " + "-" * 44]
        for key in SCHEMA:
            if key in remaining:
                out.append(f"{key}={_quote(remaining.pop(key))}")
        for key, val in remaining.items():
            out.append(f"{key}={_quote(val)}")
    return out


# ------------------------------------------------------------------- deskripsi
def describe() -> list[dict]:
    """Skema + nilai sekarang untuk dashboard. Rahasia dikirim sebagai topeng."""
    current = parse()
    out = []
    for key, spec in SCHEMA.items():
        raw = current.get(key, spec.get("default", ""))
        is_secret = spec.get("secret", False)
        out.append({
            "key": key,
            "group": spec["group"],
            "label": spec["label"],
            "kind": spec["kind"],
            "options": spec.get("options"),
            "help": spec.get("help", ""),
            "danger": spec.get("danger", ""),
            "secret": is_secret,
            "generate": spec.get("generate"),
            "present": key in current,
            # Nilai rahasia tidak pernah dikirim ke browser. Yang dikirim hanya
            # topeng dan panjangnya, cukup untuk memastikan field terisi.
            "value": MASK if (is_secret and raw) else ("" if is_secret else raw),
            "length": len(raw) if is_secret else None,
        })
    return out


def validate(changes: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Validasi seluruh perubahan. Kembalikan (nilai_bersih, error_per_field)."""
    clean: dict[str, str] = {}
    errors: dict[str, str] = {}
    for key, raw in changes.items():
        spec = SCHEMA.get(key)
        if spec is None:
            errors[key] = "kunci tidak dikenal"
            continue
        if raw == UNCHANGED or (spec.get("secret") and raw in ("", MASK)):
            continue  # tidak disentuh pengguna
        try:
            clean[key] = spec["validate"](raw)
        except EnvError as exc:
            errors[key] = str(exc)
    return clean, errors


def generate(kind: str) -> str:
    if kind == "hex32":
        return secrets.token_hex(32)
    if kind == "pass20":
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        return "".join(secrets.choice(alphabet) for _ in range(20))
    raise EnvError(f"jenis pembangkit tidak dikenal: {kind}")


# -------------------------------------------------------------------- staging
def stage(updates: dict[str, str]) -> Path:
    """Tulis berkas kandidat ke spool. Helper root yang memasangnya."""
    if not updates:
        raise EnvError("tidak ada perubahan")
    lines = render(read_raw(), updates)
    SPOOL_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SPOOL_PATH.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)      # 600
    os.replace(tmp, SPOOL_PATH)                 # atomik
    return SPOOL_PATH


def helper_available() -> bool:
    """Cukup periksa keberadaan berkasnya.

    Jangan uji os.access(X_OK): helper sengaja bermode 750 root:root, sehingga
    akun service memang TIDAK boleh mengeksekusinya sendiri — systemd yang
    menjalankannya sebagai root. Menguji izin eksekusi dari sudut pandang
    aplikasi akan selalu gagal justru ketika pemasangannya sudah benar.
    """
    return Path(APPLY_HELPER).is_file()


def trigger_and_wait(timeout: float = 25.0) -> tuple[bool, str]:
    """Tunggu path unit systemd memproses berkas kandidat.

    Aplikasi tidak memanggil helper secara langsung. Unit utama berjalan dengan
    NoNewPrivileges=true, yang memblokir sudo sepenuhnya — dan melemahkan flag
    itu demi satu fitur admin adalah harga yang terlalu mahal. Sebagai gantinya
    aplikasi hanya menuliskan berkas kandidat; systemd path unit yang mendeteksi
    dan menjalankan helper sebagai root. Statusnya dibaca dari berkas hasil.
    """
    deadline = time.monotonic() + timeout
    try:
        RESULT_PATH.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass

    while time.monotonic() < deadline:
        time.sleep(0.4)
        try:
            raw = RESULT_PATH.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if not raw:
            continue
        parts = raw.split("|", 2)
        status = parts[0]
        message = parts[2] if len(parts) > 2 else raw
        return status == "ok", message

    if SPOOL_PATH.exists():
        return False, (
            f"Berkas kandidat masih tertahan di {SPOOL_PATH} setelah {timeout:.0f} detik. "
            f"Unit {APPLY_UNIT} kemungkinan belum aktif — jalankan di server: "
            f"systemctl status {APPLY_UNIT}")
    return False, ("Tidak ada berkas hasil dari helper. Periksa: "
                   "journalctl -u threatfeed-apply-env.service -n 30")
