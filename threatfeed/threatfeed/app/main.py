"""IoC-WATCH Threat Feed Server — FastAPI, native systemd, tanpa container."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import config, crud, security
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
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("prune gagal")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if not config.INGEST_TOKENS:
        log.warning("TF_INGEST_TOKENS kosong — endpoint /api/v1/ingest akan menolak semua request.")
    if not config.ADMIN_PASSWORD:
        log.warning("TF_ADMIN_PASSWORD kosong — login dashboard tidak dapat dilakukan.")
    task = asyncio.create_task(_pruner())
    log.info("%s siap. db=%s ttl=%sd", config.APP_NAME, config.DB_PATH, config.TTL_DAYS)
    yield
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
    tlp: str = Query("", description="Filter TLP, pisahkan koma"),
    feed_name: str = Query("", description="Batasi ke satu feed FortiSOAR"),
    min_confidence: int | None = Query(None, ge=0, le=100),
    ttl_days: int | None = Query(None, ge=0, le=3650),
    limit: int | None = Query(None, ge=1),
    actor: str = Depends(security.require_feed),
):
    """Plain text, 1 entri per baris — format External Resource FortiOS."""
    started = time.perf_counter()
    ip, ua = _req_meta(request)

    rows = await asyncio.to_thread(
        crud.feed_rows, ttl_days, severity, tlp, feed_name, min_confidence, limit)

    # Urutan penentuan, dari yang paling spesifik:
    #   1. path /clean dan .txt selalu bersih; /annotated selalu berkomentar
    #   2. ?comments= atau ?clean= bila diberikan
    #   3. TF_FEED_INLINE_COMMENTS sebagai default instalasi
    # Path khusus disediakan karena CLI FortiGate kadang memakan karakter "?",
    # sehingga URL berparameter berubah jadi 404.
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
        detail=f"clean={clean} inline={inline} sev={severity or '*'} tlp={tlp or '*'}",
    )

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache, must-revalidate"
    response.headers["X-Feed-Entries"] = str(len(rows))
    response.headers["X-Feed-Generated"] = utcnow()
    return PlainTextResponse(body, headers=dict(response.headers),
                             media_type="text/plain; charset=utf-8")


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
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
    sort: str = "updated_at", order: str = "desc",
):
    return await asyncio.to_thread(crud.search_indicators, q, severity, tlp, type,
                                   source, status_, page, size, sort, order)


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
