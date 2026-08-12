"""Backup otomatis, rotasi, dan pemulihan database.

Backup ditulis ke direktori yang dimiliki akun service, sehingga penjadwalnya
tidak butuh hak istimewa apa pun. Pemulihan berbeda: menukar berkas database di
bawah koneksi yang sedang hidup tidak aman, jadi jalurnya lewat systemd path
unit yang menghentikan service, menukar berkas, lalu menjalankannya kembali —
pola yang sama dengan penerapan .env.
"""
from __future__ import annotations

import os
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import config, crud
from .database import get_conn, utcnow

DB_PATH = Path(config.DB_PATH)
BACKUP_DIR = Path(os.getenv("TF_BACKUP_DIR", str(DB_PATH.parent / "backups")))
RESTORE_SPOOL = DB_PATH.parent / "restore-pending.db"
RESTORE_RESULT = DB_PATH.parent / "restore-result"
RESTORE_HELPER = os.getenv("TF_RESTORE_HELPER", "/usr/local/sbin/threatfeed-restore-db")

_NAME = re.compile(r"^threatfeed-\d{8}-\d{6}(-pre-restore)?\.db$")


class BackupError(RuntimeError):
    pass


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def ensure_dir() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BACKUP_DIR.chmod(stat.S_IRWXU)          # 700
    except OSError:
        pass
    return BACKUP_DIR


# ------------------------------------------------------------------- membuat
def create(label: str = "") -> dict:
    """Snapshot konsisten memakai API backup SQLite (aman saat service hidup)."""
    ensure_dir()
    suffix = "-pre-restore" if label == "pre-restore" else ""
    dest = BACKUP_DIR / f"threatfeed-{_stamp()}{suffix}.db"
    tmp = dest.with_suffix(".part")
    try:
        with sqlite3.connect(tmp) as out:
            get_conn().backup(out)
        tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)   # 600
        os.replace(tmp, dest)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise BackupError(f"snapshot gagal: {exc}") from exc
    return {"name": dest.name, "size": dest.stat().st_size, "created_at": utcnow()}


def rotate(keep: int) -> list[str]:
    """Buang backup terlama. Salinan pre-restore tidak pernah ikut dirotasi —
    itulah jaring pengaman terakhir bila sebuah pemulihan ternyata keliru."""
    if keep <= 0:
        return []
    items = [p for p in listing_paths() if "-pre-restore" not in p.name]
    removed = []
    for path in items[keep:]:
        try:
            path.unlink()
            removed.append(path.name)
        except OSError:
            pass
    return removed


def listing_paths() -> list[Path]:
    if not BACKUP_DIR.is_dir():
        return []
    files = [p for p in BACKUP_DIR.iterdir() if p.is_file() and _NAME.match(p.name)]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


def listing() -> list[dict]:
    out = []
    for p in listing_paths():
        st = p.stat()
        out.append({
            "name": p.name,
            "size": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pre_restore": "-pre-restore" in p.name,
        })
    return out


def resolve(name: str) -> Path:
    """Cegah path traversal: hanya nama berkas yang cocok pola dan benar-benar
    berada di dalam direktori backup yang diterima."""
    if not _NAME.match(name or ""):
        raise BackupError("nama backup tidak valid")
    path = (BACKUP_DIR / name).resolve()
    if path.parent != BACKUP_DIR.resolve() or not path.is_file():
        raise BackupError("berkas backup tidak ditemukan")
    return path


def delete(name: str) -> None:
    resolve(name).unlink()


def stats() -> dict:
    items = listing()
    latest = items[0] if items else None
    return {
        "enabled": config.BACKUP_ENABLED,
        "interval_hours": config.BACKUP_INTERVAL_HOURS,
        "keep": config.BACKUP_KEEP,
        "directory": str(BACKUP_DIR),
        "count": len(items),
        "total_bytes": sum(i["size"] for i in items),
        "latest": latest,
        "restore_available": Path(RESTORE_HELPER).is_file(),
    }


# ------------------------------------------------------------------ validasi
REQUIRED_TABLES = {"indicators", "audit_log"}
REQUIRED_COLUMNS = {"ip_address", "type", "severity", "confidence", "tlp",
                    "source", "comment", "status", "updated_at"}


def validate(path: Path) -> dict:
    """Pastikan berkas benar-benar database IoC-WATCH sebelum dipakai memulihkan.

    Tanpa ini, sebuah unggahan yang keliru akan menghentikan service dan
    menukar database dengan berkas yang tidak dapat dibuka — kegagalan baru
    terlihat setelah service mati.
    """
    if not path.is_file() or path.stat().st_size < 4096:
        raise BackupError("berkas terlalu kecil untuk sebuah database SQLite")
    with path.open("rb") as fh:
        if fh.read(16) != b"SQLite format 3\x00":
            raise BackupError("bukan berkas database SQLite")

    uri = f"file:{path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise BackupError(f"tidak dapat dibuka: {exc}") from exc
    try:
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise BackupError("pemeriksaan integritas SQLite gagal")
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        missing = REQUIRED_TABLES - tables
        if missing:
            raise BackupError(f"tabel wajib tidak ada: {', '.join(sorted(missing))}")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(indicators)")}
        missing_cols = REQUIRED_COLUMNS - cols
        if missing_cols:
            raise BackupError(f"kolom tidak lengkap: {', '.join(sorted(missing_cols))}")
        return {
            "indicators": conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
            "audit_entries": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
            "newest": conn.execute(
                "SELECT MAX(updated_at) FROM indicators").fetchone()[0] or "-",
            "size": path.stat().st_size,
        }
    finally:
        conn.close()


# ------------------------------------------------------------------ restore
def stage_restore(source: Path) -> dict:
    """Salin kandidat ke spool setelah divalidasi. Helper root yang menukarnya."""
    info = validate(source)
    create("pre-restore")                     # jaring pengaman sebelum apa pun ditukar
    tmp = RESTORE_SPOOL.with_suffix(".part")
    shutil.copyfile(source, tmp)
    tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, RESTORE_SPOOL)
    RESTORE_RESULT.unlink(missing_ok=True)
    return info


def restore_available() -> bool:
    return Path(RESTORE_HELPER).is_file()


def wait_restore(timeout: float = 60.0) -> tuple[bool, str]:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.5)
        try:
            raw = RESTORE_RESULT.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if not raw:
            continue
        parts = raw.split("|", 2)
        return parts[0] == "ok", (parts[2] if len(parts) > 2 else raw)
    if RESTORE_SPOOL.exists():
        return False, ("Kandidat masih tertahan di spool. Unit "
                       "threatfeed-restore-db.path kemungkinan belum aktif — "
                       "jalankan: systemctl status threatfeed-restore-db.path")
    return False, "Tidak ada berkas hasil dari helper restore."


# ------------------------------------------------------------------ penjadwal
def due() -> bool:
    if not config.BACKUP_ENABLED or config.BACKUP_INTERVAL_HOURS <= 0:
        return False
    items = listing_paths()
    if not items:
        return True
    import time
    newest = max(p.stat().st_mtime for p in items)
    return (time.time() - newest) >= config.BACKUP_INTERVAL_HOURS * 3600


def run_scheduled() -> dict | None:
    if not due():
        return None
    info = create()
    removed = rotate(config.BACKUP_KEEP)
    crud.log_event("backup_auto", actor="system", entries_ok=1,
                   detail=f"{info['name']} bytes={info['size']} dibuang={len(removed)}")
    return {**info, "removed": removed}
