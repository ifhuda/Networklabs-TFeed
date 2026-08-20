"""Operasi data: upsert/dedup, query, generator feed FortiGate, pruning, audit."""
from __future__ import annotations

import shutil
from pathlib import Path

from . import config
from datetime import datetime, timezone

from .database import days_ago, get_conn, transaction, utcnow

INDICATOR_COLUMNS = (
    "id, ip_address, ioc_type, type, severity, confidence, tlp, source, comment, "
    "status, feed_name, hit_count, first_seen, created_at, updated_at"
)

_UPSERT = """
INSERT INTO indicators
    (ip_address, ioc_type, type, severity, confidence, tlp, source, comment,
     status, feed_name, hit_count, first_seen, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, 1, ?, ?, ?)
ON CONFLICT(ip_address) DO UPDATE SET
    ioc_type   = excluded.ioc_type,
    type       = excluded.type,
    severity   = excluded.severity,
    confidence = excluded.confidence,
    tlp        = excluded.tlp,
    source     = excluded.source,
    -- komentar kosong dari SOAR tidak boleh menghapus konteks yang sudah ada
    comment    = CASE WHEN excluded.comment <> '' THEN excluded.comment ELSE indicators.comment END,
    feed_name  = CASE WHEN excluded.feed_name <> '' THEN excluded.feed_name ELSE indicators.feed_name END,
    status     = 'active',
    hit_count  = indicators.hit_count + 1,
    updated_at = excluded.updated_at
RETURNING hit_count
"""


# --------------------------------------------------------------------- ingest
def upsert_many(records: list[dict]) -> dict:
    """Dedup by ip_address. Kembalikan jumlah baris baru vs yang diperbarui."""
    now = utcnow()
    inserted = updated = 0
    seen: set[str] = set()

    with transaction() as conn:
        for r in records:
            ip = r["ip_address"]
            if ip in seen:          # dedup di dalam satu payload
                continue
            seen.add(ip)
            row = conn.execute(_UPSERT, (
                ip, r.get("ioc_type", "ip"), r["type"], r["severity"], r["confidence"],
                r["tlp"], r["source"], r["comment"], r["feed_name"], now, now, now,
            )).fetchone()
            # hit_count == 1 hanya mungkin pada jalur INSERT; jalur UPDATE selalu menaikkannya.
            # (Jangan pakai perbandingan timestamp: resolusinya detik dan bisa bertabrakan.)
            if row and row["hit_count"] == 1:
                inserted += 1
            else:
                updated += 1

    return {"inserted": inserted, "updated": updated, "deduplicated": len(records) - len(seen)}


def revoke_many(ips: list[str]) -> int:
    if not ips:
        return 0
    now = utcnow()
    with transaction() as conn:
        cur = conn.execute(
            f"UPDATE indicators SET status='revoked', updated_at=? "
            f"WHERE ip_address IN ({','.join('?' * len(ips))}) AND status <> 'revoked'",
            [now, *ips],
        )
        return cur.rowcount


def revoke_feed(feed_name: str, keep_ips: list[str]) -> int:
    """Untuk command 'replace': cabut semua indikator feed ini kecuali yang baru dikirim."""
    if not feed_name:
        return 0
    now = utcnow()
    placeholders = ",".join("?" * len(keep_ips)) if keep_ips else "NULL"
    with transaction() as conn:
        cur = conn.execute(
            f"UPDATE indicators SET status='revoked', updated_at=? "
            f"WHERE feed_name=? AND status='active' AND ip_address NOT IN ({placeholders})",
            [now, feed_name, *keep_ips],
        )
        return cur.rowcount


def delete_indicator(indicator_id: int) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM indicators WHERE id=?", (indicator_id,)).rowcount > 0


# ------------------------------------------------------------------ feed build
def feed_rows(ttl_days: int | None = None, severity: str | None = None,
              tlp: str | None = None, feed_name: str | None = None,
              min_confidence: int | None = None, limit: int | None = None,
              type_: str | None = None, ioc_type: str | None = None) -> list:
    ttl = config.TTL_DAYS if ttl_days is None else ttl_days
    where = ["status = 'active'"]
    params: list = []

    if ttl > 0:
        where.append("updated_at >= ?")
        params.append(days_ago(ttl))

    minc = config.FEED_MIN_CONFIDENCE if min_confidence is None else min_confidence
    if minc > 0:
        where.append("confidence >= ?")
        params.append(minc)

    def add_ci_filter(column: str, raw: str) -> None:
        """Filter tanpa membedakan huruf besar-kecil.

        Nilai tersimpan dinormalisasi ke Title Case ('High', 'Deception'), tetapi
        URL di FortiGate lazim ditulis huruf kecil (?severity=high). Perbandingan
        peka huruf akan mengembalikan feed KOSONG tanpa pesan apa pun — dan
        blocklist yang diam-diam kosong adalah kegagalan yang tidak terlihat
        sampai ada yang lolos.
        """
        vals = [v.strip().lower() for v in raw.split(",") if v.strip()]
        if vals:
            where.append(f"LOWER({column}) IN ({','.join('?' * len(vals))})")
            params.extend(vals)

    if severity:
        add_ci_filter("severity", severity)
    if tlp:
        add_ci_filter("tlp", tlp)
    if type_:
        add_ci_filter("type", type_)
    if feed_name:
        add_ci_filter("feed_name", feed_name)
    if ioc_type:
        # TIDAK memakai add_ci_filter: nilai ini datang dari kode (endpoint
        # FortiGate feed mengunci ke 'ip' secara hardcode), bukan dari query
        # string pengguna, jadi tidak perlu split-koma multi-nilai.
        where.append("LOWER(ioc_type) = ?")
        params.append(ioc_type.strip().lower())

    cap = min(limit or config.FEED_MAX_ENTRIES, config.FEED_MAX_ENTRIES)
    sql = (f"SELECT ip_address, ioc_type, type, severity, confidence, tlp, source, "
           f"comment, updated_at "
           f"FROM indicators WHERE {' AND '.join(where)} "
           f"ORDER BY updated_at DESC LIMIT ?")
    return get_conn().execute(sql, [*params, cap]).fetchall()


def format_comment(row) -> str:
    """Susun komentar inline. Format dapat diatur lewat TF_FEED_COMMENT_FORMAT:
       full  -> Malware | Malicious/100 | TLP:RED | FortiSOAR | C2 Server detected
       short -> Malware | C2 Server detected
       plain -> C2 Server detected        (hanya kolom comment)
    """
    fmt = config.FEED_COMMENT_FORMAT
    comment = row["comment"] or ""
    if fmt == "plain":
        return comment
    if fmt == "short":
        parts = [row["type"]]
        if comment:
            parts.append(comment)
        return " | ".join(parts)
    parts = [row["type"], f"{row['severity']}/{row['confidence']}", row["tlp"], row["source"]]
    if comment:
        parts.append(comment)
    return " | ".join(parts)


def _ascii_safe_comment(text: str) -> str:
    """Buang byte non-ASCII sebelum masuk ke komentar inline feed.

    FortiOS memotong field description pada external-resource malware-hash
    begitu bertemu byte non-ASCII pertama (dikonfirmasi lewat `diagnose sys
    scanunit file-hash list malware` di server produksi — em-dash UTF-8
    tiga-byte membuat separator "Sumber — Reputasi" terpotong jadi "Sumber "
    saja, membuang seluruh info reputasi). Komentar bisa berasal dari mana
    saja yang tidak kita kendalikan penuh (push FortiSOAR, webhook, TAXII),
    jadi disaring di titik keluar tunggal ini — bukan hanya di satu sumber —
    supaya karakter non-ASCII apa pun tidak diam-diam memotong baris feed.
    """
    return text.encode("ascii", "ignore").decode("ascii")


def render_feed(rows, inline_comments: bool, header: bool = True, ttl_days: int = 0) -> str:
    lines: list[str] = []
    if header:
        # Komentar baris-penuh dengan '#' resmi didukung FortiOS external-resource.
        lines += [
            f"# {config.APP_NAME}",
            f"# generated={utcnow()} entries={len(rows)} ttl_days={ttl_days}",
        ]
    for r in rows:
        if inline_comments:
            meta = _ascii_safe_comment(format_comment(r))
            # Tanpa metadata (mis. format 'plain' pada entri tanpa komentar,
            # atau seluruhnya non-ASCII lalu tersaring habis), tulis IP polos
            # — jangan tinggalkan "#" menggantung.
            lines.append(f"{r['ip_address']} # {meta}" if meta else r["ip_address"])
        else:
            lines.append(r["ip_address"])
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- dashboard API
_SORTABLE = {"updated_at", "created_at", "ip_address", "ioc_type", "severity",
            "confidence", "source", "type", "hit_count"}


def search_indicators(q: str = "", severity: str = "", tlp: str = "", type_: str = "",
                      source: str = "", status: str = "", ioc_type: str = "",
                      page: int = 1, size: int = 50,
                      sort: str = "updated_at", order: str = "desc") -> dict:
    where: list[str] = []
    params: list = []

    if q:
        where.append("(ip_address LIKE ? OR type LIKE ? OR source LIKE ? OR "
                     "comment LIKE ? OR tlp LIKE ? OR severity LIKE ? OR feed_name LIKE ?)")
        params += [f"%{q}%"] * 7
    for column, value in (("severity", severity), ("tlp", tlp), ("type", type_),
                          ("source", source), ("status", status), ("ioc_type", ioc_type)):
        if value:
            vals = [v.strip() for v in value.split(",") if v.strip()]
            where.append(f"{column} IN ({','.join('?' * len(vals))})")
            params += vals

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) c FROM indicators {clause}", params).fetchone()["c"]

    sort = sort if sort in _SORTABLE else "updated_at"
    order = "ASC" if order.lower() == "asc" else "DESC"
    size = max(1, min(size, 500))
    page = max(1, page)

    rows = conn.execute(
        f"SELECT {INDICATOR_COLUMNS} FROM indicators {clause} "
        f"ORDER BY {sort} {order} LIMIT ? OFFSET ?",
        [*params, size, (page - 1) * size],
    ).fetchall()

    return {"total": total, "page": page, "size": size,
            "pages": max(1, -(-total // size)), "items": [dict(r) for r in rows]}


def stats() -> dict:
    conn = get_conn()
    cutoff = days_ago(config.TTL_DAYS)
    one = lambda sql, p=(): conn.execute(sql, p).fetchone()  # noqa: E731

    total = one("SELECT COUNT(*) c FROM indicators")["c"]
    active = one("SELECT COUNT(*) c FROM indicators WHERE status='active'")["c"]
    in_feed = one("SELECT COUNT(*) c FROM indicators WHERE status='active' AND updated_at>=?",
                  (cutoff,))["c"]
    expired = one("SELECT COUNT(*) c FROM indicators WHERE status='expired'")["c"]
    added_24h = one("SELECT COUNT(*) c FROM indicators WHERE created_at>=?", (days_ago(1),))["c"]

    last_ingest = one("SELECT ts, client_ip, entries_ok FROM audit_log "
                      "WHERE action='ingest' AND status_code<300 ORDER BY ts DESC LIMIT 1")
    last_pull = one("SELECT ts, client_ip, entries_ok FROM audit_log "
                    "WHERE action='feed_pull' ORDER BY ts DESC LIMIT 1")
    pulls_24h = one("SELECT COUNT(*) c FROM audit_log WHERE action='feed_pull' AND ts>=?",
                    (days_ago(1),))["c"]

    return {
        "total": total, "active": active, "in_feed": in_feed, "expired": expired,
        "revoked": total - active - expired, "added_24h": added_24h,
        "ttl_days": config.TTL_DAYS, "pulls_24h": pulls_24h,
        "last_ingest": dict(last_ingest) if last_ingest else None,
        "last_pull": dict(last_pull) if last_pull else None,
        "by_severity": [dict(r) for r in conn.execute(
            "SELECT severity k, COUNT(*) c FROM indicators WHERE status='active' "
            "GROUP BY severity ORDER BY c DESC")],
        "by_tlp": [dict(r) for r in conn.execute(
            "SELECT tlp k, COUNT(*) c FROM indicators WHERE status='active' "
            "GROUP BY tlp ORDER BY c DESC")],
        "sources": [dict(r) for r in conn.execute(
            "SELECT source k, COUNT(*) c, MAX(updated_at) last_seen FROM indicators "
            "GROUP BY source ORDER BY c DESC LIMIT 12")],
        "age_buckets": age_buckets(),
    }


def age_buckets() -> list[dict]:
    """Distribusi indikator aktif per hari-umur — dasar strip 'TTL decay' di dashboard.

    replace(...,'Z','') dipakai karena SQLite < 3.38 (Ubuntu 22.04 = 3.37)
    belum menerima sufiks Z pada fungsi tanggal.
    """
    rows = get_conn().execute(
        "SELECT CAST(julianday('now') - julianday(replace(updated_at,'Z','')) AS INTEGER) age, "
        "       severity, COUNT(*) c "
        "FROM indicators WHERE status='active' GROUP BY age, severity"
    ).fetchall()
    return [{"age": max(0, r["age"] or 0), "severity": r["severity"], "count": r["c"]} for r in rows]


def distinct_values() -> dict:
    conn = get_conn()
    pick = lambda col: [r[0] for r in conn.execute(  # noqa: E731
        f"SELECT DISTINCT {col} FROM indicators WHERE {col} <> '' ORDER BY {col}")]
    return {"types": pick("type"), "severities": pick("severity"),
            "tlps": pick("tlp"), "sources": pick("source")}


# ---------------------------------------------------------------------- audit
def log_event(action: str, actor: str = "", client_ip: str = "", user_agent: str = "",
              entries_ok: int = 0, entries_fail: int = 0, status_code: int = 200,
              duration_ms: int = 0, detail: str = "") -> None:
    try:
        with transaction() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, action, actor, client_ip, user_agent, entries_ok, "
                "entries_fail, status_code, duration_ms, detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (utcnow(), action, actor, client_ip, user_agent[:256], entries_ok,
                 entries_fail, status_code, duration_ms, detail[:1024]),
            )
    except Exception:  # audit tidak boleh menjatuhkan request utama
        pass


def audit_tail(limit: int = 100, action: str = "") -> list[dict]:
    sql = "SELECT * FROM audit_log"
    params: list = []
    if action:
        sql += " WHERE action=?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    return [dict(r) for r in get_conn().execute(sql, params)]


# -------------------------------------------------------------------- pruning
def prune() -> dict:
    now = utcnow()
    with transaction() as conn:
        expired = conn.execute(
            # updated_at sengaja TIDAK disentuh: nilainya adalah dasar perhitungan TTL
            "UPDATE indicators SET status='expired' "
            "WHERE status='active' AND updated_at < ?", (days_ago(config.TTL_DAYS),)).rowcount
        deleted = 0
        if config.HARD_DELETE_DAYS > 0:
            deleted = conn.execute(
                "DELETE FROM indicators WHERE status <> 'active' AND updated_at < ?",
                (days_ago(config.HARD_DELETE_DAYS),)).rowcount
        audit_purged = conn.execute(
            "DELETE FROM audit_log WHERE ts < ?", (days_ago(config.AUDIT_RETENTION_DAYS),)).rowcount
    return {"ts": now, "expired": expired, "deleted": deleted, "audit_purged": audit_purged}

# --------------------------------------------------------------------- ekspor
EXPORT_COLUMNS = ("id", "ip_address", "ioc_type", "type", "severity", "confidence", "tlp",
                  "source", "comment", "status", "feed_name", "hit_count",
                  "first_seen", "created_at", "updated_at")


def _search_clause(q: str = "", severity: str = "", tlp: str = "", type_: str = "",
                   source: str = "", status: str = "", ioc_type: str = "") -> tuple[str, list]:
    """Klausa WHERE yang sama persis dengan yang dipakai tabel dashboard,
    supaya 'ekspor hasil filter saat ini' benar-benar cocok dengan yang dilihat."""
    where: list[str] = []
    params: list = []
    if q:
        where.append("(ip_address LIKE ? OR type LIKE ? OR source LIKE ? OR "
                     "comment LIKE ? OR tlp LIKE ? OR severity LIKE ? OR feed_name LIKE ?)")
        params += [f"%{q}%"] * 7
    for column, value in (("severity", severity), ("tlp", tlp), ("type", type_),
                          ("source", source), ("status", status), ("ioc_type", ioc_type)):
        if value:
            vals = [v.strip() for v in value.split(",") if v.strip()]
            where.append(f"{column} IN ({','.join('?' * len(vals))})")
            params += vals
    return (f"WHERE {' AND '.join(where)}" if where else ""), params


def iter_indicators(q: str = "", severity: str = "", tlp: str = "", type_: str = "",
                    source: str = "", status: str = "", ioc_type: str = "",
                    sort: str = "updated_at", order: str = "desc", batch: int = 500):
    """Alirkan baris per potongan.

    Generator, bukan fetchall(): ekspor 130 ribu indikator yang dimuat sekaligus
    akan menahan puluhan MB di memori sebuah service yang dibatasi MemoryMax=1G.
    """
    clause, params = _search_clause(q, severity, tlp, type_, source, status, ioc_type)
    sort = sort if sort in _SORTABLE else "updated_at"
    order = "ASC" if str(order).lower() == "asc" else "DESC"
    sql = (f"SELECT {', '.join(EXPORT_COLUMNS)} FROM indicators {clause} "
           f"ORDER BY {sort} {order}")
    cur = get_conn().execute(sql, params)
    while True:
        rows = cur.fetchmany(batch)
        if not rows:
            return
        for row in rows:
            yield dict(row)


def count_indicators(q: str = "", severity: str = "", tlp: str = "", type_: str = "",
                     source: str = "", status: str = "", ioc_type: str = "") -> int:
    clause, params = _search_clause(q, severity, tlp, type_, source, status, ioc_type)
    return get_conn().execute(
        f"SELECT COUNT(*) c FROM indicators {clause}", params).fetchone()["c"]


def iter_audit(limit: int = 5000, action: str = ""):
    sql = "SELECT * FROM audit_log"
    params: list = []
    if action:
        sql += " WHERE action = ?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 100000)))
    cur = get_conn().execute(sql, params)
    while True:
        rows = cur.fetchmany(500)
        if not rows:
            return
        for row in rows:
            yield dict(row)


def snapshot(dest: str) -> int:
    """Salinan konsisten memakai API backup bawaan SQLite.

    Menyalin berkasnya dengan `cp` saat service hidup tidak aman: transaksi
    terakhir masih bisa berada di berkas -wal, dan salinannya kehilangan itu.
    """
    import sqlite3
    src = get_conn()
    with sqlite3.connect(dest) as out:
        src.backup(out)
    return Path(dest).stat().st_size
