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
