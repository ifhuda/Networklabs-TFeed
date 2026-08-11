"""Autentikasi & kontrol akses. Tanpa dependency eksternal."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
import time

from fastapi import HTTPException, Request, status

from . import config

COOKIE_NAME = "tf_session"


# ------------------------------------------------------------------ client IP
def client_ip(request: Request) -> str:
    if config.TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    return request.client.host if request.client else "-"


def ip_allowed(ip: str, cidrs: list[str]) -> bool:
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------- token compare
def _match(candidate: str, allowed: list[str]) -> bool:
    """Bandingkan seluruh kandidat agar waktu eksekusi tidak membocorkan token."""
    ok = False
    for token in allowed:
        if hmac.compare_digest(candidate, token):
            ok = True
    return ok


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return None


def _basic(request: Request) -> str | None:
    """FortiGate 'set username/password' pada external-resource mengirim Basic auth."""
    auth = request.headers.get("authorization", "")
    if auth[:6].lower() != "basic ":
        return None
    try:
        decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
    return decoded.split(":", 1)[1] if ":" in decoded else decoded


def require_ingest(request: Request) -> str:
    ip = client_ip(request)
    if not ip_allowed(ip, config.INGEST_ALLOWED_CIDRS):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Alamat sumber tidak diizinkan.")
    if not config.INGEST_TOKENS:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "TF_INGEST_TOKENS belum diset. Ingestion dinonaktifkan.")
    token = _bearer(request)
    if not token or not _match(token, config.INGEST_TOKENS):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token tidak valid.",
                            headers={"WWW-Authenticate": "Bearer"})
    return "fortisoar:" + hashlib.sha256(token.encode()).hexdigest()[:8]


def require_feed(request: Request) -> str:
    ip = client_ip(request)
    if not ip_allowed(ip, config.FEED_ALLOWED_CIDRS):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Alamat sumber tidak diizinkan.")
    if not config.FEED_TOKENS:
        return "fortigate:anonymous"
    token = _bearer(request) or _basic(request) or request.query_params.get("token")
    if not token or not _match(token, config.FEED_TOKENS):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token feed tidak valid.",
                            headers={"WWW-Authenticate": 'Basic realm="threatfeed"'})
    return "fortigate:" + hashlib.sha256(token.encode()).hexdigest()[:8]


# --------------------------------------------------------------- session cookie
def _sign(raw: bytes) -> str:
    sig = hmac.new(config.SECRET_KEY.encode(), raw, hashlib.sha256).digest()
    return (base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." +
            base64.urlsafe_b64encode(sig).decode().rstrip("="))


def _unsign(value: str) -> dict | None:
    try:
        body_b64, sig_b64 = value.split(".", 1)
        raw = base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    except (ValueError, binascii.Error):
        return None
    expected = hmac.new(config.SECRET_KEY.encode(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def issue_session(user: str = "admin") -> str:
    payload = {"u": user, "exp": int(time.time()) + config.SESSION_TTL_HOURS * 3600,
               "jti": secrets.token_hex(8)}
    return _sign(json.dumps(payload, separators=(",", ":")).encode())


def verify_password(password: str) -> bool:
    if not config.ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(password, config.ADMIN_PASSWORD)


def require_session(request: Request) -> str:
    cookie = request.cookies.get(COOKIE_NAME)
    data = _unsign(cookie) if cookie else None
    if not data or data.get("exp", 0) < time.time():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesi tidak valid atau kedaluwarsa.")
    return f"dashboard:{data.get('u', 'admin')}"
