"""Layer SQLite. WAL mode, koneksi per-request, tanpa ORM."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config

_local = threading.local()
_write_lock = threading.Lock()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS indicators (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    ioc_type    TEXT    NOT NULL DEFAULT 'ip' CHECK (ioc_type IN ('ip','domain','hash','url')),
    type        TEXT    NOT NULL DEFAULT 'IP Address',
    severity    TEXT    NOT NULL DEFAULT 'Medium',
    confidence  INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    tlp         TEXT    NOT NULL DEFAULT 'TLP:AMBER',
    source      TEXT    NOT NULL DEFAULT 'FortiSOAR',
    comment     TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','expired','revoked')),
    feed_name   TEXT    NOT NULL DEFAULT '',
    hit_count   INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ind_status_updated ON indicators(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ind_updated       ON indicators(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ind_severity      ON indicators(severity);
CREATE INDEX IF NOT EXISTS idx_ind_tlp           ON indicators(tlp);
CREATE INDEX IF NOT EXISTS idx_ind_source        ON indicators(source);
CREATE INDEX IF NOT EXISTS idx_ind_type          ON indicators(type);
-- idx_ind_ioc_type SENGAJA tidak di sini. Kolom ioc_type ditambahkan lewat
-- ALTER TABLE di _migrate() untuk database lama, dan executescript(SCHEMA) di
-- bawah berjalan SEBELUM _migrate() dipanggil — index di kolom yang belum ada
-- akan membuat seluruh service gagal start di server produksi manapun yang
-- tabelnya sudah ada sebelum kolom ini diperkenalkan (CREATE TABLE IF NOT
-- EXISTS jadi no-op, tapi CREATE INDEX tetap mencoba jalan). Index dibuat di
-- _migrate() setelah ALTER TABLE, bukan di sini.

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    actor         TEXT    NOT NULL DEFAULT '',
    client_ip     TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    entries_ok    INTEGER NOT NULL DEFAULT 0,
    entries_fail  INTEGER NOT NULL DEFAULT 0,
    status_code   INTEGER NOT NULL DEFAULT 200,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    detail        TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, ts DESC);
"""


def utcnow() -> str:
    """ISO-8601 UTC, aman untuk perbandingan leksikografis di SQLite."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(config.DB_PATH, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


@contextmanager
def transaction():
    """Serialisasi penulisan di level proses; SQLite hanya punya satu writer."""
    conn = get_conn()
    with _write_lock:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def init_db() -> None:
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    conn.executescript(SCHEMA)
    _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Tambahkan kolom baru ke database produksi yang sudah ada.

    `CREATE TABLE IF NOT EXISTS` di SCHEMA di atas hanya berlaku untuk instalasi
    baru — database yang sudah berjalan sejak sebelum kolom ini ada tidak pernah
    menjalankan ulang CREATE TABLE, jadi kolomnya harus ditambahkan manual lewat
    ALTER TABLE. Tanpa ini, upgrade ke versi yang menambah `ioc_type` akan
    membuat service gagal start di server produksi dengan data yang sudah ada.

    Index untuk kolom ini SENGAJA dibuat di sini juga (bukan di SCHEMA statis),
    setelah ALTER TABLE selesai — CREATE INDEX di SCHEMA berjalan lewat
    executescript() sebelum fungsi ini sempat dipanggil, jadi di database lama
    yang kolomnya belum ada, index itu akan gagal dengan "no such column"
    sebelum ALTER TABLE di bawah ini sempat menyelamatkannya.
    """
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(indicators)")}
    if "ioc_type" not in cols:
        conn.execute(
            "ALTER TABLE indicators ADD COLUMN ioc_type TEXT NOT NULL DEFAULT 'ip'")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ind_ioc_type ON indicators(ioc_type)")

    if _needs_url_check_rebuild(conn):
        _rebuild_indicators_table_for_url(conn)


def _needs_url_check_rebuild(conn: sqlite3.Connection) -> bool:
    """True hanya untuk instalasi yang fresh-install lewat CREATE TABLE di jendela
    singkat sebelum 'url' ditambahkan sebagai ioc_type yang sah (CHECK constraint
    lama membatasi ke ip/domain/hash saja). Database yang sudah ada sejak sebelum
    ioc_type diperkenalkan sama sekali TIDAK PERNAH punya CHECK ini — ditambahkan
    lewat ALTER TABLE ADD COLUMN di atas, dan SQLite tidak menaruh CHECK pada
    ALTER TABLE ADD COLUMN — jadi baris itu selalu aman untuk mayoritas instalasi.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='indicators'"
    ).fetchone()
    sql = (row["sql"] if row else "") or ""
    return "ioc_type" in sql and "check" in sql.lower() and "'url'" not in sql.lower()


def _rebuild_indicators_table_for_url(conn: sqlite3.Connection) -> None:
    """CHECK constraint tertanam di definisi tabel SQLite, bukan sesuatu yang bisa
    diubah lewat ALTER TABLE — satu-satunya cara memperluas nilai yang diizinkan
    adalah membangun ulang tabel dengan definisi baru, memindahkan data, lalu
    membuang tabel lama. Dibungkus transaksi eksplisit supaya tidak pernah
    berhenti di tengah dengan data di dua tabel sekaligus.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("ALTER TABLE indicators RENAME TO indicators_pre_url_rebuild")
        conn.executescript(SCHEMA)   # CREATE TABLE IF NOT EXISTS -> definisi terbaru
        conn.execute(
            "INSERT INTO indicators SELECT * FROM indicators_pre_url_rebuild")
        conn.execute("DROP TABLE indicators_pre_url_rebuild")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
