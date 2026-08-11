"""Normalisasi indikator + parser payload FortiSOAR yang toleran terhadap bentuk input."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from . import config

# ---------------------------------------------------------------- kamus nilai
SEVERITY_MAP = {
    "malicious": "Malicious", "critical": "Critical", "crit": "Critical",
    "high": "High", "medium": "Medium", "med": "Medium", "moderate": "Medium",
    "low": "Low", "informational": "Info", "info": "Info",
    "suspicious": "High", "minimal": "Low", "none": "Info",
}
SEVERITY_ORDER = ["Malicious", "Critical", "High", "Medium", "Low", "Info"]

TLP_MAP = {
    "red": "TLP:RED", "amber": "TLP:AMBER", "amber+strict": "TLP:AMBER+STRICT",
    "green": "TLP:GREEN", "white": "TLP:WHITE", "clear": "TLP:WHITE",
}
TLP_VALID = {"TLP:RED", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:GREEN", "TLP:WHITE"}

_IP_KEYS = ("ip", "ip_address", "ipaddress", "value", "indicator", "address", "src_ip", "dst_ip")
_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*-\s*([0-9a-fA-F:.]+)\s*$")


class NormalizeError(ValueError):
    pass


# ---------------------------------------------------------------- IP handling
def normalize_ip(raw: Any) -> str:
    """Terima IPv4/IPv6 tunggal, CIDR, atau range. Kembalikan bentuk kanonik FortiGate."""
    if raw is None:
        raise NormalizeError("nilai IP kosong")
    s = str(raw).strip().strip('"').strip("'")
    if not s:
        raise NormalizeError("nilai IP kosong")

    m = _RANGE_RE.match(s)
    if m:
        lo, hi = ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
        if lo.version != hi.version:
            raise NormalizeError(f"range campur IPv4/IPv6: {s}")
        if int(hi) < int(lo):
            raise NormalizeError(f"range terbalik: {s}")
        return f"{lo.compressed}-{hi.compressed}"

    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        if net.prefixlen == net.max_prefixlen:
            return net.network_address.compressed
        return net.with_prefixlen

    return ipaddress.ip_address(s).compressed


def is_routable(ip_str: str) -> bool:
    """False untuk loopback/multicast/unspecified — hindari indikator sampah."""
    head = ip_str.split("-")[0].split("/")[0]
    try:
        addr = ipaddress.ip_address(head)
    except ValueError:
        return True
    return not (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


# ------------------------------------------------------------ field normalize
def normalize_severity(v: Any) -> str:
    if v is None or str(v).strip() == "":
        return config.DEFAULT_SEVERITY
    s = str(v).strip()
    return SEVERITY_MAP.get(s.lower(), s[:32].title())


def normalize_tlp(v: Any) -> str:
    if v is None or str(v).strip() == "":
        return config.DEFAULT_TLP
    s = str(v).strip().upper().replace("TLP-", "TLP:").replace("TLP ", "TLP:")
    if not s.startswith("TLP:"):
        s = TLP_MAP.get(s.lower(), f"TLP:{s}")
    else:
        s = TLP_MAP.get(s[4:].lower(), s)
    return s if s in TLP_VALID else config.DEFAULT_TLP


def normalize_confidence(v: Any) -> int:
    if v is None or str(v).strip() == "":
        return config.DEFAULT_CONFIDENCE
    try:
        n = int(round(float(str(v).strip().rstrip("%"))))
    except (TypeError, ValueError):
        return config.DEFAULT_CONFIDENCE
    return max(0, min(100, n))


def clean_text(v: Any, limit: int = 512) -> str:
    """Buang CR/LF supaya tidak bisa menyuntik baris palsu ke output feed."""
    if v is None:
        return ""
    s = re.sub(r"[\r\n\t]+", " ", str(v)).strip()
    s = re.sub(r"\s{2,}", " ", s)
    return s[:limit]


# --------------------------------------------------------------- entry parser
def parse_entry(item: Any, feed_name: str = "") -> dict:
    """Ubah satu entri (string ATAU object) menjadi record ternormalisasi."""
    if isinstance(item, str):
        item = {"ip": item}
    if not isinstance(item, dict):
        raise NormalizeError(f"tipe entri tidak didukung: {type(item).__name__}")

    lower = {str(k).lower(): v for k, v in item.items()}

    raw_ip = next((lower[k] for k in _IP_KEYS if lower.get(k) not in (None, "")), None)
    if raw_ip is None:
        raise NormalizeError(f"tidak ada field IP pada entri: {list(item)[:6]}")

    ip = normalize_ip(raw_ip)
    if not is_routable(ip):
        raise NormalizeError(f"IP tidak routable / dilarang: {ip}")

    return {
        "ip_address": ip,
        "type": clean_text(lower.get("type") or lower.get("indicator_type"), 64) or config.DEFAULT_TYPE,
        "severity": normalize_severity(lower.get("severity") or lower.get("reputation")),
        "confidence": normalize_confidence(lower.get("confidence")),
        "tlp": normalize_tlp(lower.get("tlp") or lower.get("tlp_level")),
        "source": clean_text(lower.get("source") or lower.get("feed_source"), 128) or config.DEFAULT_SOURCE,
        "comment": clean_text(lower.get("comment") or lower.get("description") or lower.get("note")),
        "feed_name": clean_text(feed_name, 128),
    }


# ------------------------------------------------------------- payload parser
def parse_payload(payload: Any) -> list[dict]:
    """
    Kembalikan list command: [{"name": str, "command": "add|delete|replace", "entries": [raw...]}]

    Bentuk yang diterima:
      1. {"commands":[{"name":..,"command":"add","entries":[{...}|"1.2.3.4"]}]}
      2. {"name":..,"command":"add","entries":[...]}      (single command)
      3. {"entries":[...]}  /  {"indicators":[...]}  /  {"ips":[...]}  /  {"data":[...]}
      4. ["1.2.3.4","5.6.7.8"]        (bare array of strings)
      5. [{"ip":"1.2.3.4",...}]       (bare array of objects)
      6. {"ip":"1.2.3.4", ...}        (single object)
    """
    if isinstance(payload, list):
        return [{"name": "", "command": "add", "entries": payload}]

    if not isinstance(payload, dict):
        raise NormalizeError("payload harus berupa JSON object atau array")

    if isinstance(payload.get("commands"), list):
        out = []
        for c in payload["commands"]:
            if not isinstance(c, dict):
                raise NormalizeError("elemen 'commands' harus object")
            out.append({
                "name": clean_text(c.get("name"), 128),
                "command": str(c.get("command") or "add").strip().lower(),
                "entries": _as_entry_list(c),
            })
        return out

    if "command" in payload or "entries" in payload:
        return [{
            "name": clean_text(payload.get("name"), 128),
            "command": str(payload.get("command") or "add").strip().lower(),
            "entries": _as_entry_list(payload),
        }]

    for key in ("indicators", "ips", "ip_addresses", "data", "items"):
        if isinstance(payload.get(key), list):
            return [{
                "name": clean_text(payload.get("name"), 128),
                "command": str(payload.get("command") or "add").strip().lower(),
                "entries": payload[key],
            }]

    if any(k in payload for k in _IP_KEYS):
        return [{"name": "", "command": "add", "entries": [payload]}]

    raise NormalizeError("tidak menemukan 'commands', 'entries', atau field IP pada payload")


def _as_entry_list(block: dict) -> list:
    for key in ("entries", "indicators", "ips", "ip_addresses", "data", "items", "values"):
        val = block.get(key)
        if isinstance(val, list):
            return val
        if isinstance(val, (str, dict)):
            return [val]
    return []


def flatten(commands: Iterable[dict]) -> tuple[list[dict], list[dict], list[str], list[dict]]:
    """Pisahkan menjadi (upserts, deletes, replace_feeds, errors)."""
    upserts: list[dict] = []
    deletes: list[dict] = []
    replace_feeds: list[str] = []
    errors: list[dict] = []

    for cmd in commands:
        action = cmd.get("command", "add")
        name = cmd.get("name", "")
        if action in {"replace", "set", "sync"} and name:
            replace_feeds.append(name)
        target = deletes if action in {"delete", "remove", "revoke", "clear"} else upserts

        for raw in cmd.get("entries", []):
            try:
                target.append(parse_entry(raw, name))
            except (NormalizeError, ValueError) as exc:
                errors.append({"entry": str(raw)[:120], "error": str(exc)})

    return upserts, deletes, replace_feeds, errors
