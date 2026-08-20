"""IoC-WATCH Threat Feed Server — FastAPI, native systemd, tanpa container."""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import shutil
import tempfile
import json
import logging
from urllib.parse import quote
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import (BackgroundTasks, Body, Depends, FastAPI, File, Form,
                     HTTPException, Query, Request, Response, UploadFile, status)
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, StreamingResponse)
from pydantic import BaseModel, Field

from . import backup as backup_mod
from . import config, crud, envfile, security, settings as settings_store
from . import taxii_client
from .database import init_db, utcnow
from .normalize import NormalizeError, deep_find_ips, flatten, parse_payload

log = logging.getLogger("threatfeed")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

STATIC_DIR = config.BASE_DIR / "static"


async def _pruner():
    while True:
        try:
            await asyncio.sleep(config.PRUNE_INTERVAL_SECONDS)
            result = await asyncio.to_thread(crud.prune)
            if result["expired"] or result["deleted"]:
                log.info("prune %s", result)
                await asyncio.to_thread(
                    crud.log_event, "prune", actor="system", detail=json.dumps(result))
            # Backup menumpang siklus yang sama, bukan task terpisah: satu loop
            # lebih mudah ditelusuri, dan jadwalnya dihitung dari waktu backup
            # terakhir sehingga interval tetap benar meski service sering restart.
            done = await asyncio.to_thread(backup_mod.run_scheduled)
            if done:
                log.info("backup otomatis: %s (%s byte)", done["name"], done["size"])
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("prune gagal")


def _last_pull_ts_for(collection_id: str) -> str | None:
    """Cursor `added_after` per-koleksi, bukan global.

    Bila lebih dari satu koleksi pernah ditarik (mis. lewat 'Tarik Sekarang' yang
    menguji koleksi berbeda-beda), memakai timestamp tarikan TERAKHIR APA PUN akan
    salah menerapkan cursor koleksi lain ke koleksi yang sedang ditarik — cocok
    kebetulan bila hanya ada satu koleksi yang pernah dikonfigurasi, tapi diam-diam
    salah begitu ada yang kedua. Cari beberapa event terakhir dan pakai yang
    collection_id-nya cocok.
    """
    for row in crud.audit_tail(20, "soar_pull"):
        if row["status_code"] >= 400:
            continue
        try:
            detail = json.loads(row["detail"])
        except (ValueError, TypeError):
            continue
        if detail.get("collection_id") == collection_id:
            return row["ts"]
    return None


def _run_soar_pull(collection_id: str, added_after: str | None) -> dict:
    """Tarik satu siklus dari SATU koleksi TAXII dan upsert hasilnya.

    Fungsi sinkron dipanggil lewat asyncio.to_thread — httpx.Client dan crud
    keduanya blocking, dan menjalankannya di loop event akan menahan seluruh
    server selama request ke FortiSOAR berlangsung.
    """
    result = taxii_client.pull_collection(
        base_url=config.SOAR_TAXII_URL, key_name=config.SOAR_TAXII_KEY_NAME,
        api_key=config.SOAR_TAXII_API_KEY, collection_id=collection_id,
        feed_name=config.SOAR_TAXII_FEED_NAME, added_after=added_after,
        verify_tls=config.SOAR_TAXII_VERIFY_TLS)
    stats = crud.upsert_many(result["records"]) if result["records"] else \
        {"inserted": 0, "updated": 0, "deduplicated": 0}
    summary = {"collection_id": collection_id,
               "raw_objects": result["raw_objects"], "pages": result["pages"], **stats}
    crud.log_event("soar_pull", actor="system", entries_ok=stats["inserted"] + stats["updated"],
                   detail=json.dumps(summary))
    return summary


async def _soar_poller():
    """Siklus terpisah dari pruner: TAXII server yang lambat tidak boleh menunda TTL.

    Beberapa koleksi bisa dikonfigurasi sekaligus (dipisah koma). Masing-masing
    dicek kelayakan jadwalnya sendiri-sendiri per tick 60 detik — koleksi yang
    baru ditambahkan tidak menunggu koleksi lain, dan satu koleksi yang gagal
    tidak menghalangi koleksi lain ditarik pada tick yang sama.
    """
    last_pull_iso: dict[str, str] = {}   # cache in-memory per collection_id
    while True:
        try:
            await asyncio.sleep(60)
            if not (config.SOAR_TAXII_ENABLED and config.SOAR_TAXII_URL
                    and config.SOAR_TAXII_COLLECTION_IDS):
                continue

            for cid in config.SOAR_TAXII_COLLECTION_IDS:
                # Cek jadwal dari waktu tarikan terakhir tersimpan, bukan timer
                # di memori — sama seperti auto-backup, ini menjaga interval
                # tetap benar meski service sering restart.
                ts = last_pull_iso.get(cid)
                if ts is None:
                    ts = await asyncio.to_thread(_last_pull_ts_for, cid)
                due = True
                if ts:
                    elapsed = (datetime.now(timezone.utc)
                              - datetime.fromisoformat(ts.replace("Z", "+00:00")))
                    due = elapsed.total_seconds() >= config.SOAR_TAXII_POLL_MINUTES * 60
                if not due:
                    continue
                try:
                    summary = await asyncio.to_thread(_run_soar_pull, cid, ts)
                    last_pull_iso[cid] = utcnow()
                    log.info("tarik TAXII FortiSOAR (%s): %s", cid, summary)
                except taxii_client.TaxiiError as exc:
                    log.warning("tarik TAXII gagal (%s): %s", cid, exc)
                    await asyncio.to_thread(
                        crud.log_event, "soar_pull", actor="system", status_code=502,
                        detail=json.dumps({"collection_id": cid, "error": str(exc)[:400]}))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("penjadwal tarik TAXII gagal tak terduga")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Panel "Pengaturan" (perubahan instan tanpa restart) sudah dipensiunkan —
    # semua pengaturan sekarang lewat Konfigurasi Sistem (.env + restart) saja,
    # supaya cuma ada SATU tempat untuk mengubah kebijakan yang sama. Override
    # yang sempat tersimpan di database dari versi sebelumnya TETAP diterapkan
    # di sini (supaya server yang sudah berjalan tidak diam-diam kembali ke
    # nilai .env begitu upgrade) — tapi dengan peringatan eksplisit, karena
    # sekarang tidak ada lagi GUI untuk melihat atau mengubahnya.
    stale = settings_store.overrides()
    failed = settings_store.apply_to_config()
    if failed:
        log.warning("Override pengaturan tidak valid, diabaikan: %s", ", ".join(failed))
    if stale:
        log.warning(
            "%d pengaturan dari panel 'Pengaturan' (sudah dipensiunkan) masih aktif "
            "dari database lama: %s. Nilai ini TIDAK lagi terlihat atau bisa diubah "
            "lewat dashboard. Pindahkan ke /etc/threatfeed/threatfeed.env lewat "
            "Konfigurasi Sistem, lalu jalankan 'sudo threatfeedctl "
            "clear-legacy-settings' untuk membuang override basi ini dari database.",
            len(stale), ", ".join(sorted(stale)))
    if not config.INGEST_TOKENS:
        log.warning("TF_INGEST_TOKENS kosong — endpoint /api/v1/ingest akan menolak semua request.")
    if not config.ADMIN_PASSWORD:
        log.warning("TF_ADMIN_PASSWORD kosong — login dashboard tidak dapat dilakukan.")
    tasks = [asyncio.create_task(_pruner()), asyncio.create_task(_soar_poller())]
    if config.BACKUP_ENABLED:
        log.info("backup otomatis aktif: tiap %s jam, simpan %s, dir=%s",
                 config.BACKUP_INTERVAL_HOURS, config.BACKUP_KEEP, config.BACKUP_DIR)
    if config.SOAR_TAXII_ENABLED:
        log.info("tarik TAXII FortiSOAR aktif: tiap %s menit, %d koleksi (%s)",
                 config.SOAR_TAXII_POLL_MINUTES, len(config.SOAR_TAXII_COLLECTION_IDS),
                 ", ".join(config.SOAR_TAXII_COLLECTION_IDS) or "belum diatur")
    log.info("%s siap. db=%s ttl=%sd", config.APP_NAME, config.DB_PATH, config.TTL_DAYS)
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title=config.APP_NAME, version="1.0.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")


# ============================================================== model & helper
class IngestResult(BaseModel):
    status: str = "ok"
    received: int = 0
    inserted: int = 0
    updated: int = 0
    deduplicated: int = 0
    revoked: int = 0
    rejected: int = 0
    errors: list[dict] = Field(default_factory=list)
    processed_at: str = ""


def _req_meta(request: Request) -> tuple[str, str]:
    return security.client_ip(request), request.headers.get("user-agent", "")[:256]


# ==================================================================== INGESTION
# Varian berbasis path untuk integrasi yang tidak mengizinkan kita menyusun body,
# seperti webhook Block/Unblock FortiDeceptor: aksinya ditentukan URL, bukan JSON.
@app.post("/api/v1/ingest", response_model=IngestResult, tags=["ingest"])
@app.post("/api/v1/ingest/add", response_model=IngestResult, tags=["ingest"],
          include_in_schema=False)
@app.post("/api/v1/ingest/block", response_model=IngestResult, tags=["ingest"],
          include_in_schema=False)
@app.post("/api/v1/ingest/delete", response_model=IngestResult, tags=["ingest"],
          include_in_schema=False)
@app.post("/api/v1/ingest/unblock", response_model=IngestResult, tags=["ingest"],
          include_in_schema=False)
async def ingest(
    request: Request,
    payload=Body(...),
    actor: str = Depends(security.require_ingest),
    deep: bool = Query(False, description="Pindai seluruh JSON untuk mencari IP"),
    source: str = Query("", description="Timpa nilai source"),
    type: str = Query("", description="Timpa nilai type"),
    severity: str = Query("", description="Timpa nilai severity"),
    tlp: str = Query("", description="Timpa nilai TLP"),
    confidence: int | None = Query(None, ge=0, le=100),
    feed_name: str = Query("", description="Nama feed untuk entri ini"),
    comment: str = Query("", description="Komentar default bila payload tidak punya"),
):
    """Terima push indikator. Mendukung rich object, array string, dan webhook pihak lain."""
    started = time.perf_counter()
    ip, ua = _req_meta(request)

    path = request.url.path
    forced = "delete" if path.endswith(("/delete", "/unblock")) else \
             "add" if path.endswith(("/add", "/block")) else ""

    try:
        commands = parse_payload(payload)
    except (NormalizeError, ValueError) as exc:
        if not deep:
            await asyncio.to_thread(crud.log_event, "ingest", actor, ip, ua,
                                    status_code=400, detail=str(exc))
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Payload tidak dikenali: {exc}. "
                f"Untuk webhook dengan format tak dikenal, tambahkan ?deep=true, "
                f"atau periksa isi payload lewat POST /api/v1/ingest/echo",
            )
        commands = []

    if deep:
        # Kumpulkan IP dari mana pun di dalam JSON, lalu satukan dengan hasil
        # parser normal supaya payload campuran tetap tertangani.
        found = deep_find_ips(payload)
        known = {e if isinstance(e, str) else e.get("ip")
                 for c in commands for e in c.get("entries", [])}
        extra = [x for x in found if x not in known]
        if extra:
            commands.append({"name": feed_name, "command": forced or "add", "entries": extra})

    if forced:
        for c in commands:
            c["command"] = forced

    upserts, deletes, replace_feeds, errors = flatten(commands)

    # Nilai dari query string menimpa isi payload — dipakai integrasi yang
    # tidak bisa mengirim metadata sendiri.
    overrides = {"source": source, "type": type, "severity": severity, "tlp": tlp,
                 "comment": comment, "feed_name": feed_name}
    for rec in upserts:
        for key, val in overrides.items():
            if val:
                rec[key] = val
        if confidence is not None:
            rec["confidence"] = confidence
    received = sum(len(c.get("entries", [])) for c in commands)

    result = await asyncio.to_thread(crud.upsert_many, upserts) if upserts else {
        "inserted": 0, "updated": 0, "deduplicated": 0}

    revoked = 0
    if deletes:
        revoked += await asyncio.to_thread(crud.revoke_many, [d["ip_address"] for d in deletes])
    for feed in replace_feeds:
        keep = [u["ip_address"] for u in upserts if u["feed_name"] == feed]
        revoked += await asyncio.to_thread(crud.revoke_feed, feed, keep)

    out = IngestResult(
        received=received, inserted=result["inserted"], updated=result["updated"],
        deduplicated=result["deduplicated"], revoked=revoked,
        rejected=len(errors), errors=errors[:25], processed_at=utcnow(),
        status="ok" if not errors else "partial",
    )
    await asyncio.to_thread(
        crud.log_event, "ingest", actor, ip, ua,
        entries_ok=result["inserted"] + result["updated"], entries_fail=len(errors),
        status_code=200, duration_ms=int((time.perf_counter() - started) * 1000),
        detail=f"feeds={[c.get('name') for c in commands]} revoked={revoked}",
    )
    return out


@app.post("/api/v1/ingest/echo", tags=["ingest"])
async def ingest_echo(request: Request, payload=Body(...),
                      actor: str = Depends(security.require_ingest)):
    """Kembalikan payload apa adanya beserta IP yang terdeteksi. Tidak menyimpan apa pun.

    Dipakai untuk membedah format webhook pihak ketiga sebelum dikonfigurasi:
    arahkan integrasi ke sini sekali, picu satu kejadian, lalu baca hasilnya.
    """
    ip, ua = _req_meta(request)
    found = deep_find_ips(payload)
    await asyncio.to_thread(
        crud.log_event, "ingest_echo", actor, ip, ua, entries_ok=len(found),
        detail=json.dumps(payload)[:1000])
    return {"detected_ips": found, "content_type": request.headers.get("content-type", ""),
            "payload": payload,
            "hint": "Pakai ?deep=true jika detected_ips sudah benar."}


# ============================================================ FORTIGATE CONSUMER
# Tiga path yang setara. Alasannya praktis: CLI FortiGate kadang memakan karakter
# "?" saat `set resource` diketik langsung, sehingga URL berparameter berubah jadi
# path yang tidak ada dan dijawab 404 — dilaporkan GUI sebagai "Server not
# reachable". Path tanpa query string menghilangkan seluruh kelas masalah itu.
async def _build_feed_response(
    request: Request, response: Response, ioc_type: str,
    clean: bool | None, comments: bool | None, severity: str, type: str, tlp: str,
    feed_name: str, min_confidence: int | None, ttl_days: int | None, limit: int | None,
    actor: str,
) -> PlainTextResponse:
    """Inti pembuatan feed teks-biasa, dipakai bersama oleh endpoint IP/domain/hash.

    `ioc_type` SELALU dikunci oleh endpoint pemanggil, tidak pernah dari query
    string pengguna — mencampur alamat IP dengan domain atau hash dalam satu
    feed `config system external-resource / set type address` akan membuat
    FortiGate menolak seluruh feed atau memperlakukan baris yang salah bentuk
    sebagai entri sampah, tanpa pesan error yang jelas ke operator.
    """
    started = time.perf_counter()
    ip, ua = _req_meta(request)

    rows = await asyncio.to_thread(
        crud.feed_rows, ttl_days, severity, tlp, feed_name, min_confidence, limit,
        type, ioc_type)

    path = request.url.path
    if path.endswith(("/clean", ".txt")):
        inline = False
    elif path.endswith("/annotated"):
        inline = True
    elif comments is not None:
        inline = comments
    elif clean is not None:
        inline = not clean
    else:
        inline = config.FEED_INLINE_COMMENTS
    header = inline

    body = crud.render_feed(rows, inline_comments=inline, header=header,
                            ttl_days=config.TTL_DAYS if ttl_days is None else ttl_days)
    etag = '"' + hashlib.sha256(body.encode()).hexdigest()[:32] + '"'

    await asyncio.to_thread(
        crud.log_event, "feed_pull", actor, ip, ua, entries_ok=len(rows), status_code=200,
        duration_ms=int((time.perf_counter() - started) * 1000),
        detail=f"ioc_type={ioc_type} clean={clean} inline={inline} sev={severity or '*'} "
               f"type={type or '*'} tlp={tlp or '*'}",
    )

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache, must-revalidate"
    response.headers["X-Feed-Entries"] = str(len(rows))
    response.headers["X-Feed-Generated"] = utcnow()
    return PlainTextResponse(body, headers=dict(response.headers),
                             media_type="text/plain; charset=utf-8")


@app.get("/api/v1/feed/fortigate", response_class=PlainTextResponse, tags=["feed"])
@app.get("/api/v1/feed/fortigate/clean", response_class=PlainTextResponse, tags=["feed"],
         include_in_schema=False)
@app.get("/api/v1/feed/fortigate.txt", response_class=PlainTextResponse, tags=["feed"],
         include_in_schema=False)
@app.get("/api/v1/feed/fortigate/annotated", response_class=PlainTextResponse, tags=["feed"],
         include_in_schema=False)
async def fortigate_feed(
    request: Request,
    response: Response,
    clean: bool | None = Query(None, description="true = IP murni tanpa komentar"),
    comments: bool | None = Query(None, description="Paksa komentar inline on/off"),
    severity: str = Query("", description="Filter, pisahkan koma. Contoh: Malicious,Critical"),
    type: str = Query("", description="Filter tipe indikator. Contoh: Malware,Deception"),
    tlp: str = Query("", description="Filter TLP, pisahkan koma"),
    feed_name: str = Query("", description="Batasi ke satu feed FortiSOAR"),
    min_confidence: int | None = Query(None, ge=0, le=100),
    ttl_days: int | None = Query(None, ge=0, le=3650),
    limit: int | None = Query(None, ge=1),
    actor: str = Depends(security.require_feed),
):
    """Plain text, 1 entri per baris — format External Resource FortiOS `type address`.

    Hanya menyajikan indikator IP (ioc_type='ip'). Untuk domain, hash, atau URL,
    pakai /api/v1/feed/fortigate/domain, /hash, atau /url.
    """
    return await _build_feed_response(request, response, "ip", clean, comments, severity,
                                      type, tlp, feed_name, min_confidence, ttl_days,
                                      limit, actor)


@app.get("/api/v1/feed/fortigate/domain", response_class=PlainTextResponse, tags=["feed"])
@app.get("/api/v1/feed/fortigate/domain/clean", response_class=PlainTextResponse,
         tags=["feed"], include_in_schema=False)
@app.get("/api/v1/feed/fortigate/domain/annotated", response_class=PlainTextResponse,
         tags=["feed"], include_in_schema=False)
async def fortigate_feed_domain(
    request: Request,
    response: Response,
    clean: bool | None = Query(None),
    comments: bool | None = Query(None),
    severity: str = Query(""), type: str = Query(""), tlp: str = Query(""),
    feed_name: str = Query(""), min_confidence: int | None = Query(None, ge=0, le=100),
    ttl_days: int | None = Query(None, ge=0, le=3650), limit: int | None = Query(None, ge=1),
    actor: str = Depends(security.require_feed),
):
    """Plain text, 1 domain per baris — untuk external-resource `type domain`."""
    return await _build_feed_response(request, response, "domain", clean, comments, severity,
                                      type, tlp, feed_name, min_confidence, ttl_days,
                                      limit, actor)


@app.get("/api/v1/feed/fortigate/hash", response_class=PlainTextResponse, tags=["feed"])
@app.get("/api/v1/feed/fortigate/hash/clean", response_class=PlainTextResponse,
         tags=["feed"], include_in_schema=False)
async def fortigate_feed_hash(
    request: Request,
    response: Response,
    clean: bool | None = Query(None),
    comments: bool | None = Query(None),
    severity: str = Query(""), type: str = Query(""), tlp: str = Query(""),
    feed_name: str = Query(""), min_confidence: int | None = Query(None, ge=0, le=100),
    ttl_days: int | None = Query(None, ge=0, le=3650), limit: int | None = Query(None, ge=1),
    actor: str = Depends(security.require_feed),
):
    """Plain text, 1 hash file per baris.

    Dukungan FortiOS untuk external-resource berbasis hash file bervariasi
    antar versi (mis. malware-hash) — endpoint ini tetap berguna untuk ekspor
    dan integrasi lain (AV, EDR) meski tidak selalu dikonsumsi langsung oleh
    firewall policy seperti feed IP/domain.
    """
    return await _build_feed_response(request, response, "hash", clean, comments, severity,
                                      type, tlp, feed_name, min_confidence, ttl_days,
                                      limit, actor)


@app.get("/api/v1/feed/fortigate/url", response_class=PlainTextResponse, tags=["feed"])
@app.get("/api/v1/feed/fortigate/url/clean", response_class=PlainTextResponse,
         tags=["feed"], include_in_schema=False)
async def fortigate_feed_url(
    request: Request,
    response: Response,
    clean: bool | None = Query(None),
    comments: bool | None = Query(None),
    severity: str = Query(""), type: str = Query(""), tlp: str = Query(""),
    feed_name: str = Query(""), min_confidence: int | None = Query(None, ge=0, le=100),
    ttl_days: int | None = Query(None, ge=0, le=3650), limit: int | None = Query(None, ge=1),
    actor: str = Depends(security.require_feed),
):
    """Plain text, 1 URL lengkap per baris.

    FortiGate tidak punya external-resource `type url` — URL biasanya dikonsumsi
    lewat kategori web filter kustom (`type category`) atau diproses aplikasi lain
    (proxy, SIEM). Endpoint ini menyajikan URL apa adanya (skema+host+path) untuk
    integrasi semacam itu, terpisah dari feed IP/domain/hash.
    """
    return await _build_feed_response(request, response, "url", clean, comments, severity,
                                      type, tlp, feed_name, min_confidence, ttl_days,
                                      limit, actor)


@app.get("/api/v1/feed/stats", tags=["feed"])
async def feed_stats(actor: str = Depends(security.require_feed)):
    rows = await asyncio.to_thread(crud.feed_rows)
    return {"entries": len(rows), "ttl_days": config.TTL_DAYS, "generated_at": utcnow()}


# ================================================================= DASHBOARD API
class LoginBody(BaseModel):
    password: str


@app.post("/api/v1/auth/login", tags=["dashboard"])
async def login(request: Request, body: LoginBody):
    ip, ua = _req_meta(request)
    if not security.verify_password(body.password):
        await asyncio.to_thread(crud.log_event, "login_failed", "-", ip, ua, status_code=401)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Password salah.")
    token = security.issue_session()
    await asyncio.to_thread(crud.log_event, "login", "dashboard:admin", ip, ua)
    resp = JSONResponse({"status": "ok", "expires_in": config.SESSION_TTL_HOURS * 3600})
    resp.set_cookie(security.COOKIE_NAME, token, httponly=True, samesite="strict",
                    secure=config.COOKIE_SECURE, max_age=config.SESSION_TTL_HOURS * 3600, path="/")
    return resp


@app.post("/api/v1/auth/logout", tags=["dashboard"])
async def logout():
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(security.COOKIE_NAME, path="/")
    return resp


@app.get("/api/v1/auth/session", tags=["dashboard"])
async def session_check(actor: str = Depends(security.require_session)):
    return {"status": "ok", "actor": actor}


@app.get("/api/v1/stats", tags=["dashboard"])
async def get_stats(actor: str = Depends(security.require_session)):
    data = await asyncio.to_thread(crud.stats)
    data["app_name"] = config.APP_NAME
    data["inline_comments_default"] = config.FEED_INLINE_COMMENTS
    return data


@app.get("/api/v1/indicators", tags=["dashboard"])
async def list_indicators(
    actor: str = Depends(security.require_session),
    q: str = "", severity: str = "", tlp: str = "", type: str = "",
    source: str = "", status_: str = Query("", alias="status"),
    ioc_type: str = Query("", description="Filter jenis: ip, domain, hash (pisahkan koma)"),
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
    sort: str = "updated_at", order: str = "desc",
):
    return await asyncio.to_thread(crud.search_indicators, q, severity, tlp, type,
                                   source, status_, ioc_type, page, size, sort, order)


@app.get("/api/v1/filters", tags=["dashboard"])
async def filters(actor: str = Depends(security.require_session)):
    return await asyncio.to_thread(crud.distinct_values)


@app.delete("/api/v1/indicators/{indicator_id}", tags=["dashboard"])
async def remove_indicator(indicator_id: int, request: Request,
                           actor: str = Depends(security.require_session)):
    ok = await asyncio.to_thread(crud.delete_indicator, indicator_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indikator tidak ditemukan.")
    ip, ua = _req_meta(request)
    await asyncio.to_thread(crud.log_event, "delete", actor, ip, ua, entries_ok=1,
                            detail=f"id={indicator_id}")
    return {"status": "ok", "deleted": indicator_id}


# Endpoint /api/v1/settings (panel "Pengaturan" — perubahan instan tanpa restart)
# DIPENSIUNKAN. Seluruh field di sana 100% tumpang tindih dengan Konfigurasi
# Sistem, dan dua tempat untuk mengubah nilai yang sama membingungkan operator
# soal mana yang berlaku. Tabel `settings` tetap ada di skema database (lihat
# lifespan()) supaya server yang sempat memakai panel lama tidak diam-diam
# kehilangan nilai yang tersimpan di sana saat upgrade — tapi tidak ada lagi
# jalur GUI/API untuk menulis ke situ; pembersihannya lewat
# `threatfeedctl clear-legacy-settings`.


# ======================================================= SYSTEM CONFIGURATION
# Halaman admin yang menulis ulang /etc/threatfeed/threatfeed.env.
#
# Tiga lapis penjagaan, karena fitur ini memberi antarmuka web kemampuan
# mengubah kredensial servernya sendiri:
#   1. TF_ALLOW_ENV_WRITE harus dinyalakan di berkas .env — hanya root di server
#   2. Password dashboard harus diketik ulang pada setiap penyimpanan
#   3. Helper root memvalidasi ulang berkas kandidat dari nol sebelum memasangnya
class EnvSaveBody(BaseModel):
    changes: dict[str, str] = Field(default_factory=dict)
    confirm_password: str = ""
    restart: bool = True


def _require_env_write() -> None:
    if not config.ALLOW_ENV_WRITE:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Pengeditan berkas .env lewat dashboard dinonaktifkan. "
            "Nyalakan dengan TF_ALLOW_ENV_WRITE=true di /etc/threatfeed/threatfeed.env, "
            "lalu restart service.")


@app.get("/api/v1/admin/settings", tags=["admin"])
async def admin_settings_get(actor: str = Depends(security.require_session)):
    _require_env_write()
    try:
        fields = await asyncio.to_thread(envfile.describe)
    except envfile.EnvError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return {
        "fields": fields,
        "groups": envfile.GROUP_ORDER,
        "env_path": str(envfile.ENV_PATH),
        "helper_available": envfile.helper_available(),
        "lockout_keys": sorted(envfile.LOCKOUT_KEYS),
        "mask": envfile.MASK,
    }


@app.post("/api/v1/admin/settings/generate", tags=["admin"])
async def admin_settings_generate(kind: str = Query("hex32"),
                                  actor: str = Depends(security.require_session)):
    _require_env_write()
    try:
        return {"value": envfile.generate(kind)}
    except envfile.EnvError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


@app.post("/api/v1/admin/settings", tags=["admin"])
async def admin_settings_save(request: Request, body: EnvSaveBody,
                              actor: str = Depends(security.require_session)):
    _require_env_write()
    ip, ua = _req_meta(request)

    if not security.verify_password(body.confirm_password):
        await asyncio.to_thread(crud.log_event, "env_write_denied", actor, ip, ua,
                                status_code=401, detail="password konfirmasi salah")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Password dashboard salah. Konfirmasi diperlukan untuk "
                            "menulis ulang berkas konfigurasi.")

    clean, errors = envfile.validate(body.changes)
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            {"message": "Validasi gagal", "errors": errors})
    if not clean:
        return {"status": "noop", "changed": [], "message": "Tidak ada nilai yang berubah."}

    if not envfile.helper_available():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Helper {envfile.APPLY_HELPER} tidak terpasang. Jalankan "
            f"'sudo bash deploy/setup.sh --upgrade --enable-env-editor' di server.")

    try:
        await asyncio.to_thread(envfile.stage, clean)
    except envfile.EnvError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"Gagal menyiapkan berkas kandidat: {exc}")

    # Menulis berkas kandidat sudah cukup: systemd path unit yang mendeteksinya
    # dan menjalankan helper sebagai root. Aplikasi hanya menunggu berkas hasil.
    ok_applied, output = await asyncio.to_thread(envfile.trigger_and_wait)

    # Nama kunci dicatat, nilainya tidak: jejak audit tidak boleh menjadi tempat
    # kedua tersimpannya token dan password dalam bentuk terbaca.
    changed = sorted(clean)
    await asyncio.to_thread(
        crud.log_event, "env_write", actor, ip, ua, entries_ok=len(changed),
        status_code=200 if ok_applied else 500,
        detail=f"keys={','.join(changed)} applied={ok_applied} {output[:300]}")

    if not ok_applied:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"Perubahan tidak diterapkan: {output}")

    lockout = sorted(set(changed) & envfile.LOCKOUT_KEYS)
    return {
        "status": "ok",
        "changed": changed,
        "restart": "scheduled",
        "helper_output": output,
        "lockout_warning": lockout,
        "message": ("Konfigurasi tersimpan. Service akan restart dalam beberapa detik."
                    + (" Anda perlu login ulang." if lockout else "")),
    }


@app.get("/api/v1/admin/fortigate-snippet", tags=["admin"])
async def fortigate_snippet(request: Request, reveal: bool = Query(False),
                            name: str = Query("IoC-WATCH-Blocklist"),
                            type: str = Query("address"),
                            category: int = Query(192, ge=192, le=221),
                            identity_check: str = Query("none"),
                            refresh_rate: int = Query(5, ge=1, le=43200),
                            severity: str = Query(""),
                            indicator_type: str = Query("", description="Filter kolom type indikator"),
                            tlp: str = Query(""), feed_name: str = Query(""),
                            actor: str = Depends(security.require_session)):
    """Rakit blok `config system external-resource` siap tempel.

    Token dikirim tersamar kecuali diminta eksplisit dengan ?reveal=true, dan
    pengungkapannya dicatat di jejak audit — nilainya sama sensitifnya dengan
    isi berkas .env, jadi tidak dikirim ke browser hanya karena halaman dibuka.
    """
    ip, ua = _req_meta(request)

    # Basis URL diambil dari permintaan ini sendiri: itulah alamat yang terbukti
    # dapat dijangkau klien, bukan tebakan dari hostname server.
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    scheme = forwarded_proto or request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    base = f"{scheme}://{host}"

    identity_check = identity_check if identity_check in ("full", "basic", "none") else "none"
    valid_types = ("address", "domain", "malware", "mac-address", "category")
    res_type = type if type in valid_types else "address"

    # Path feed HARUS mengikuti tipe external-resource yang dipilih — server
    # ini menyajikan empat feed terpisah per ioc_type (ip/domain/hash/url) dan
    # mengunci masing-masing di sisi server. Snippet yang menunjuk 'category'
    # (URL) atau 'malware' (hash) ke endpoint IP polos akan selalu ditolak
    # FortiGate karena isinya tidak sesuai — itulah yang terjadi sebelum ini.
    if res_type == "domain":
        path = "/api/v1/feed/fortigate/domain/annotated" if config.FEED_INLINE_COMMENTS \
            else "/api/v1/feed/fortigate/domain"
    elif res_type == "malware":
        # Endpoint hash cuma punya varian /clean, tidak ada /annotated.
        path = "/api/v1/feed/fortigate/hash"
    elif res_type == "category":
        # Endpoint url cuma punya varian /clean, tidak ada /annotated.
        path = "/api/v1/feed/fortigate/url"
    else:
        path = "/api/v1/feed/fortigate/annotated" if config.FEED_INLINE_COMMENTS \
            else "/api/v1/feed/fortigate"

    params = []
    for key, val in (("severity", severity), ("type", indicator_type),
                     ("tlp", tlp), ("feed_name", feed_name)):
        if val.strip():
            params.append(f"{key}={quote(val.strip(), safe=',:')}")
    resource = base + path + ("?" + "&".join(params) if params else "")

    # Hitung berapa entri yang benar-benar akan diterima FortiGate dengan filter
    # ini. Filter yang salah ketik menghasilkan feed kosong tanpa pesan error,
    # dan itu baru ketahuan setelah ada yang lolos di firewall.
    matched = len(await asyncio.to_thread(
        crud.feed_rows, None, severity, tlp, feed_name, None, None, indicator_type))

    username = config.FEED_USERNAME or "fortigate"
    token_set = bool(config.FEED_TOKENS)
    if reveal and token_set:
        token = config.FEED_TOKENS[0]
        await asyncio.to_thread(crud.log_event, "feed_token_revealed", actor, ip, ua,
                                detail="token feed ditampilkan di dashboard")
    else:
        token = "<TOKEN_FEED>" if token_set else "<KOSONG — feed tanpa autentikasi>"

    lines = [
        "config system external-resource",
        f'    edit "{name}"',
        f"        set type {res_type}",
    ]
    if res_type == "category":
        # Feed tipe category wajib punya nomor kategori buatan sendiri (192–221);
        # tanpa itu FortiGate menolak konfigurasinya.
        lines.append(f"        set category {category}")
    lines += [
        f'        set resource "{resource}"',
        f"        set refresh-rate {refresh_rate}",
        f"        set server-identity-check {identity_check}",
    ]
    if token_set:
        lines += [f'        set username "{username}"', f"        set password {token}"]
    lines += ["        set status enable", "    next", "end"]

    notes = []
    if res_type == "mac-address":
        notes.append(
            "Server ini tidak punya jenis indikator MAC address (hanya IP/domain/hash/URL) — "
            "'set type mac-address' hampir pasti tidak cocok kecuali diarahkan ke sumber lain.")
    if res_type == "category":
        notes.append(f"Nomor kategori {category} harus unik di FortiGate dan berada "
                     f"pada rentang 192–221 yang dicadangkan untuk kategori buatan sendiri. "
                     f"Kategori 'Remote' baru berlaku setelah dipasang ke Web Filter profile "
                     f"(aksi Block) — dan trafik HTTPS butuh SSL Deep Inspection aktif di "
                     f"policy, karena tanpa itu FortiGate hanya melihat hostname (SNI), bukan "
                     f"path URL yang dicocokkan.")
    if res_type == "malware":
        notes.append("Feed tipe malware (hash) dipasang lewat AntiVirus profile -> "
                     "'Use external malware block list', bukan langsung ke firewall policy.")
    if not config.FEED_USERNAME:
        notes.append("TF_FEED_USERNAME kosong: username apa pun diterima. Isi di atas "
                     "hanya contoh; hanya token yang benar-benar diperiksa.")
    if identity_check == "none":
        notes.append("server-identity-check none melewati verifikasi sertifikat. "
                     "Pakai full bila FortiGate sudah mempercayai sertifikat server ini.")
    if config.FEED_INLINE_COMMENTS and res_type in ("address", "domain"):
        notes.append("Feed memakai komentar inline. Setelah diterapkan, cocokkan "
                     "'diagnose sys external-resource entry-list' dengan "
                     "'threatfeedctl feed | grep -c .' — FortiOS tidak menjamin format ini.")
    if not config.FEED_ALLOWED_CIDRS:
        notes.append("Allowlist feed kosong: semua alamat dapat menarik feed.")

    if matched == 0 and (severity or indicator_type or tlp or feed_name):
        notes.append("Filter ini tidak cocok dengan satu indikator pun — FortiGate akan "
                     "menerima feed KOSONG. Periksa ejaan nilai filter.")

    return {"snippet": "\n".join(lines), "resource": resource, "username": username,
            "matched": matched,
            "type": res_type, "category": category,
            "token_revealed": bool(reveal and token_set), "token_set": token_set,
            "curl": f"curl -v -u {username}:{token} \"{resource}\"",
            "notes": notes}


# ===================================================================== EKSPOR
def _csv_safe(value) -> str:
    """Netralkan formula injection sebelum nilai masuk ke berkas CSV.

    Excel dan LibreOffice mengeksekusi sel yang diawali = + - @ atau tab/CR.
    Kolom `comment` diisi dari FortiSOAR dan webhook pihak ketiga, jadi isinya
    tidak tepercaya: satu komentar berisi =HYPERLINK(...) cukup untuk menyerang
    analis yang membuka hasil ekspor. Awalan kutip tunggal membuat spreadsheet
    memperlakukannya sebagai teks.
    """
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def _csv_stream(rows, columns):
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    yield buf.getvalue()
    buf.seek(0), buf.truncate(0)
    for row in rows:
        writer.writerow([_csv_safe(row.get(c)) for c in columns])
        if buf.tell() > 32768:          # kirim per potongan, bukan sekaligus
            yield buf.getvalue()
            buf.seek(0), buf.truncate(0)
    if buf.tell():
        yield buf.getvalue()


def _json_stream(rows):
    yield "[\n"
    first = True
    for row in rows:
        yield ("" if first else ",\n") + json.dumps(row, ensure_ascii=False)
        first = False
    yield "\n]\n"


def _stamp(prefix: str, ext: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{ext}"


@app.get("/api/v1/export/indicators", tags=["export"])
async def export_indicators(
    request: Request,
    actor: str = Depends(security.require_session),
    format: str = Query("csv", pattern="^(csv|json)$"),
    q: str = "", severity: str = "", tlp: str = "", type: str = "",
    source: str = "", status_: str = Query("", alias="status"),
    ioc_type: str = "",
    sort: str = "updated_at", order: str = "desc",
):
    """Ekspor indikator sesuai filter yang sedang aktif di dashboard."""
    ip, ua = _req_meta(request)
    total = await asyncio.to_thread(crud.count_indicators, q, severity, tlp, type,
                                    source, status_, ioc_type)
    await asyncio.to_thread(
        crud.log_event, "export", actor, ip, ua, entries_ok=total,
        detail=f"format={format} q={q or '*'} severity={severity or '*'} "
               f"type={type or '*'} ioc_type={ioc_type or '*'} status={status_ or '*'}")

    rows = crud.iter_indicators(q, severity, tlp, type, source, status_, ioc_type, sort, order)
    if format == "json":
        return StreamingResponse(
            _json_stream(rows), media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{_stamp("ioc-watch", "json")}"',
                     "X-Export-Rows": str(total)})
    return StreamingResponse(
        _csv_stream(rows, crud.EXPORT_COLUMNS), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_stamp("ioc-watch", "csv")}"',
                 "X-Export-Rows": str(total)})


@app.get("/api/v1/export/audit", tags=["export"])
async def export_audit(request: Request, actor: str = Depends(security.require_session),
                       format: str = Query("csv", pattern="^(csv|json)$"),
                       limit: int = Query(5000, ge=1, le=100000), action: str = ""):
    ip, ua = _req_meta(request)
    await asyncio.to_thread(crud.log_event, "export", actor, ip, ua,
                            detail=f"audit format={format} limit={limit}")
    rows = crud.iter_audit(limit, action)
    cols = ("id", "ts", "action", "actor", "client_ip", "user_agent",
            "entries_ok", "entries_fail", "status_code", "duration_ms", "detail")
    if format == "json":
        return StreamingResponse(
            _json_stream(rows), media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{_stamp("ioc-watch-audit", "json")}"'})
    return StreamingResponse(
        _csv_stream(rows, cols), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_stamp("ioc-watch-audit", "csv")}"'})


@app.get("/api/v1/export/backup", tags=["export"])
async def export_backup(request: Request, actor: str = Depends(security.require_session),
                        background: BackgroundTasks = None):
    """Unduh snapshot database yang konsisten.

    Berkas ini memuat SELURUH isi database — indikator, jejak audit lengkap
    dengan alamat IP klien, dan override pengaturan. Perlakukan seperti backup
    produksi: simpan terenkripsi, jangan kirim lewat kanal yang tidak aman.
    """
    ip, ua = _req_meta(request)
    tmp = Path(tempfile.mkdtemp(prefix="tf-backup-")) / _stamp("threatfeed", "db")
    try:
        size = await asyncio.to_thread(crud.snapshot, str(tmp))
    except Exception as exc:
        log.exception("snapshot gagal")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"Snapshot database gagal: {exc}")

    await asyncio.to_thread(crud.log_event, "backup_download", actor, ip, ua,
                            entries_ok=size, detail=f"bytes={size}")

    # Berkas sementara dihapus setelah respons terkirim, bukan sebelumnya:
    # FileResponse masih membacanya saat handler ini sudah selesai.
    if background is not None:
        background.add_task(shutil.rmtree, tmp.parent, ignore_errors=True)
    return FileResponse(str(tmp), media_type="application/octet-stream",
                        filename=tmp.name, background=background)


# =============================================== TARIK DARI FORTISOAR (TAXII)
class SoarTestBody(BaseModel):
    url: str = ""
    key_name: str = ""
    api_key: str = ""
    verify_tls: bool = True


class SoarPullBody(BaseModel):
    url: str = ""
    key_name: str = ""
    api_key: str = ""
    collection_id: str = ""          # kompatibilitas mundur: satu ID
    collection_ids: list[str] = []   # dipilih via checkbox — bisa lebih dari satu
    feed_name: str = ""
    verify_tls: bool = True
    full_history: bool = False   # abaikan cursor added_after; tarik ulang semua

    def resolved_ids(self, fallback: list[str]) -> list[str]:
        if self.collection_ids:
            return [c.strip() for c in self.collection_ids if c.strip()]
        if self.collection_id.strip():
            return [self.collection_id.strip()]
        return fallback


def _soar_field(body_val: str, config_val: str) -> str:
    """Body request menang bila diisi — dipakai untuk uji koneksi sebelum disimpan."""
    return body_val.strip() if body_val.strip() else config_val


def _pull_detail_for(collection_id: str, limit: int = 30) -> dict | None:
    """Hasil tarikan terakhir untuk SATU koleksi, dari jejak audit."""
    for row in crud.audit_tail(limit, "soar_pull"):
        try:
            detail = json.loads(row["detail"]) if row["detail"].startswith("{") else {}
        except (ValueError, TypeError):
            detail = {}
        if detail.get("collection_id") == collection_id:
            return {"ts": row["ts"], "ok": row["status_code"] < 400,
                    "detail": detail if row["status_code"] < 400 else detail.get("error", row["detail"])}
    return None


@app.get("/api/v1/admin/soar/status", tags=["soar"])
async def soar_status(ids: str = "", actor: str = Depends(security.require_session)):
    """Ringkasan konfigurasi + hasil tarikan terakhir PER KOLEKSI, untuk panel dashboard.

    `ids` (opsional, dipisah koma): koleksi tambahan yang ingin dicek statusnya di
    luar yang tersimpan di .env — dipakai panel untuk menampilkan ✓/✗ pada koleksi
    yang baru ditemukan lewat Uji Koneksi atau ditarik on-demand, sebelum apa pun
    disimpan ke konfigurasi permanen.
    """
    last = await asyncio.to_thread(crud.audit_tail, 1, "soar_pull")
    last_pull = None
    if last:
        row = last[0]
        try:
            detail = json.loads(row["detail"]) if row["detail"].startswith("{") else {}
        except (ValueError, TypeError):
            detail = {}
        last_pull = {
            "ts": row["ts"], "ok": row["status_code"] < 400,
            "detail": detail if row["status_code"] < 400 else row["detail"],
        }

    extra = [c.strip() for c in ids.split(",") if c.strip()]
    configured = config.SOAR_TAXII_COLLECTION_IDS
    all_ids = list(dict.fromkeys(configured + extra))   # gabung, buang duplikat, jaga urutan
    per_collection = await asyncio.to_thread(
        lambda: [{"id": cid, "last_pull": _pull_detail_for(cid)} for cid in all_ids])

    return {
        "enabled": config.SOAR_TAXII_ENABLED,
        "url": config.SOAR_TAXII_URL,
        "key_name": config.SOAR_TAXII_KEY_NAME,
        "api_key_set": bool(config.SOAR_TAXII_API_KEY),
        "collection_id": config.SOAR_TAXII_COLLECTION_ID,     # baris .env mentah, apa adanya
        "collection_ids": configured,                          # sudah dipecah & dibersihkan
        "collection_name": config.SOAR_TAXII_COLLECTION_NAME,
        "collections": per_collection,
        "feed_name": config.SOAR_TAXII_FEED_NAME,
        "poll_minutes": config.SOAR_TAXII_POLL_MINUTES,
        "verify_tls": config.SOAR_TAXII_VERIFY_TLS,
        "last_pull": last_pull,
    }


@app.post("/api/v1/admin/soar/test-connection", tags=["soar"])
async def soar_test_connection(body: SoarTestBody, request: Request,
                               actor: str = Depends(security.require_session)):
    """Discovery + daftar collections. Dipakai sebelum menyimpan .env, jadi menerima
    nilai dari form langsung tanpa menulis apa pun ke konfigurasi."""
    url = _soar_field(body.url, config.SOAR_TAXII_URL)
    key_name = _soar_field(body.key_name, config.SOAR_TAXII_KEY_NAME)
    api_key = _soar_field(body.api_key, config.SOAR_TAXII_API_KEY)
    if not url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Server Address belum diisi")

    ip, ua = _req_meta(request)
    try:
        result = await asyncio.to_thread(
            taxii_client.test_connection, url, key_name, api_key, body.verify_tls)
    except taxii_client.TaxiiError as exc:
        await asyncio.to_thread(crud.log_event, "soar_test", actor, ip, ua,
                                status_code=502, detail=str(exc)[:500])
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))

    await asyncio.to_thread(crud.log_event, "soar_test", actor, ip, ua,
                            entries_ok=len(result["collections"]),
                            detail=f"koleksi ditemukan: {len(result['collections'])}")
    return result


@app.post("/api/v1/admin/soar/pull-now", tags=["soar"])
async def soar_pull_now(body: SoarPullBody, request: Request,
                        actor: str = Depends(security.require_session)):
    """Tarik satu atau lebih koleksi segera, di luar jadwal. Nilai dari body (bila
    diisi) menang atas konfigurasi tersimpan — berguna untuk menguji sebelum disimpan.
    Setiap koleksi diproses dan dicatat terpisah; satu koleksi gagal tidak
    menghentikan sisanya — kegagalan dikumpulkan lalu dilaporkan bersama hasil
    yang berhasil, supaya satu URL yang salah tidak menyembunyikan hasil yang lain.
    """
    url = _soar_field(body.url, config.SOAR_TAXII_URL)
    key_name = _soar_field(body.key_name, config.SOAR_TAXII_KEY_NAME)
    api_key = _soar_field(body.api_key, config.SOAR_TAXII_API_KEY)
    feed_name = _soar_field(body.feed_name, config.SOAR_TAXII_FEED_NAME) or "FortiSOAR-TAXII"
    ids = body.resolved_ids(config.SOAR_TAXII_COLLECTION_IDS)
    if not url or not ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Server Address dan minimal satu Koleksi wajib diisi")

    ip, ua = _req_meta(request)
    results, errors = [], []
    totals = {"inserted": 0, "updated": 0, "deduplicated": 0, "raw_objects": 0}

    for cid in ids:
        added_after = None
        if not body.full_history:
            added_after = await asyncio.to_thread(_last_pull_ts_for, cid)
        try:
            result = await asyncio.to_thread(
                taxii_client.pull_collection, url, key_name, api_key, cid,
                feed_name, added_after, body.verify_tls)
        except taxii_client.TaxiiError as exc:
            await asyncio.to_thread(crud.log_event, "soar_pull", actor, ip, ua,
                                    status_code=502,
                                    detail=json.dumps({"collection_id": cid, "error": str(exc)[:400]}))
            errors.append({"collection_id": cid, "error": str(exc)})
            continue

        stats = await asyncio.to_thread(crud.upsert_many, result["records"]) if result["records"] \
            else {"inserted": 0, "updated": 0, "deduplicated": 0}
        summary = {"collection_id": cid, "raw_objects": result["raw_objects"],
                  "pages": result["pages"], **stats}
        await asyncio.to_thread(crud.log_event, "soar_pull", actor, ip, ua,
                                entries_ok=stats["inserted"] + stats["updated"],
                                detail=json.dumps(summary))
        results.append(summary)
        totals["inserted"] += stats["inserted"]
        totals["updated"] += stats["updated"]
        totals["deduplicated"] += stats["deduplicated"]
        totals["raw_objects"] += result["raw_objects"]

    if not results and errors:
        # Semua koleksi gagal — tidak ada yang perlu dilaporkan sebagai sukses parsial.
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            "; ".join(f"{e['collection_id']}: {e['error']}" for e in errors))

    return {**totals, "collections": results, "errors": errors}


# ===================================================== BACKUP & RESTORE (GUI)
class RestoreBody(BaseModel):
    name: str = ""
    confirm_password: str = ""


@app.get("/api/v1/backups", tags=["backup"])
async def backups_list(actor: str = Depends(security.require_session)):
    return {"backups": await asyncio.to_thread(backup_mod.listing),
            "stats": await asyncio.to_thread(backup_mod.stats)}


@app.post("/api/v1/backups", tags=["backup"])
async def backups_create(request: Request, actor: str = Depends(security.require_session)):
    ip, ua = _req_meta(request)
    try:
        info = await asyncio.to_thread(backup_mod.create)
    except backup_mod.BackupError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))
    removed = await asyncio.to_thread(backup_mod.rotate, config.BACKUP_KEEP)
    await asyncio.to_thread(crud.log_event, "backup_manual", actor, ip, ua, entries_ok=1,
                            detail=f"{info['name']} bytes={info['size']} dibuang={len(removed)}")
    return {**info, "removed": removed}


@app.get("/api/v1/backups/{name}", tags=["backup"])
async def backups_download(name: str, request: Request,
                           actor: str = Depends(security.require_session)):
    try:
        path = await asyncio.to_thread(backup_mod.resolve, name)
    except backup_mod.BackupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    ip, ua = _req_meta(request)
    await asyncio.to_thread(crud.log_event, "backup_download", actor, ip, ua,
                            detail=f"file={name}")
    return FileResponse(str(path), media_type="application/octet-stream", filename=name)


@app.delete("/api/v1/backups/{name}", tags=["backup"])
async def backups_delete(name: str, request: Request,
                         actor: str = Depends(security.require_session)):
    try:
        await asyncio.to_thread(backup_mod.delete, name)
    except backup_mod.BackupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    ip, ua = _req_meta(request)
    await asyncio.to_thread(crud.log_event, "backup_delete", actor, ip, ua, detail=f"file={name}")
    return {"status": "ok", "deleted": name}


@app.post("/api/v1/backups/inspect", tags=["backup"])
async def backups_inspect(file: UploadFile = File(...),
                          actor: str = Depends(security.require_session)):
    """Periksa berkas unggahan tanpa mengubah apa pun."""
    tmpdir = Path(tempfile.mkdtemp(prefix="tf-inspect-"))
    try:
        dest = tmpdir / "candidate.db"
        with dest.open("wb") as out:
            shutil.copyfileobj(file.file, out, length=1024 * 1024)
        try:
            return {"valid": True, **await asyncio.to_thread(backup_mod.validate, dest)}
        except backup_mod.BackupError as exc:
            return {"valid": False, "error": str(exc)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def _do_restore(source: Path, actor: str, ip: str, ua: str, origin: str) -> dict:
    if not backup_mod.restore_available():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Helper {backup_mod.RESTORE_HELPER} tidak terpasang. Jalankan di server: "
            f"sudo bash deploy/setup.sh --upgrade --enable-env-editor")
    try:
        info = await asyncio.to_thread(backup_mod.stage_restore, source)
    except backup_mod.BackupError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    await asyncio.to_thread(crud.log_event, "restore_started", actor, ip, ua,
                            entries_ok=info["indicators"], detail=f"dari={origin}")
    ok_done, message = await asyncio.to_thread(backup_mod.wait_restore)
    if not ok_done:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"Pemulihan tidak selesai: {message}")
    return {"status": "ok", "restored": info, "helper_output": message,
            "message": "Database dipulihkan dan service dijalankan ulang. "
                       "Sesi Anda mungkin perlu login ulang."}


@app.post("/api/v1/backups/restore", tags=["backup"])
async def backups_restore(request: Request, body: RestoreBody,
                          actor: str = Depends(security.require_session)):
    """Pulihkan dari salah satu backup yang sudah ada di server."""
    ip, ua = _req_meta(request)
    if not security.verify_password(body.confirm_password):
        await asyncio.to_thread(crud.log_event, "restore_denied", actor, ip, ua,
                                status_code=401, detail="password konfirmasi salah")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Password dashboard salah. Pemulihan menimpa seluruh database, "
                            "jadi konfirmasi diperlukan.")
    try:
        path = await asyncio.to_thread(backup_mod.resolve, body.name)
    except backup_mod.BackupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return await _do_restore(path, actor, ip, ua, body.name)


@app.post("/api/v1/backups/restore-upload", tags=["backup"])
async def backups_restore_upload(request: Request, file: UploadFile = File(...),
                                 confirm_password: str = Form(""),
                                 actor: str = Depends(security.require_session)):
    """Pulihkan dari berkas .db yang diunggah operator."""
    ip, ua = _req_meta(request)
    if not security.verify_password(confirm_password):
        await asyncio.to_thread(crud.log_event, "restore_denied", actor, ip, ua,
                                status_code=401, detail="password konfirmasi salah")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Password dashboard salah.")

    tmpdir = Path(tempfile.mkdtemp(prefix="tf-restore-"))
    try:
        dest = tmpdir / "uploaded.db"
        with dest.open("wb") as out:
            shutil.copyfileobj(file.file, out, length=1024 * 1024)
        return await _do_restore(dest, actor, ip, ua, file.filename or "unggahan")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.get("/api/v1/audit", tags=["dashboard"])
async def audit(actor: str = Depends(security.require_session),
                limit: int = Query(100, ge=1, le=1000), action: str = ""):
    return {"items": await asyncio.to_thread(crud.audit_tail, limit, action)}


@app.post("/api/v1/maintenance/prune", tags=["dashboard"])
async def manual_prune(request: Request, actor: str = Depends(security.require_session)):
    result = await asyncio.to_thread(crud.prune)
    ip, ua = _req_meta(request)
    await asyncio.to_thread(crud.log_event, "prune", actor, ip, ua, detail=json.dumps(result))
    return result


# ======================================================================== UI
@app.get("/healthz", response_class=PlainTextResponse, tags=["ops"])
async def healthz():
    return "ok"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return HTMLResponse("<h1>static/index.html tidak ditemukan</h1>", status_code=500)
    return HTMLResponse(index.read_text(encoding="utf-8"))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp
