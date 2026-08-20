"""Client TAXII 2.1 untuk menarik indikator dari Outgoing TAXII Feed FortiSOAR.

FortiSOAR menyajikan koleksinya di:
    Discovery : {base}/taxii            -> daftar api-root
    Collections: {base}/collections
    Objects   : {base}/collections/{id}/objects  (bundle STIX, paginasi via `next`/`more`)

Dua kuirk yang membuat modul ini tidak bisa memakai parser STIX generik begitu saja:

1. **Autentikasi bergaya API Key, bukan Bearer.** FortiSOAR memakai HTTP Basic dengan
   nama key sebagai username dan key itu sendiri sebagai password — bukan header
   Authorization biasa. Client lain yang mengasumsikan Bearer akan mendapat 401 tanpa
   penjelasan.
2. **Field indikator IP kadang bukan `pattern` STIX baku.** Beberapa konektor FortiSOAR
   mengekspor objek dengan field `value` langsung berisi alamat IP, alih-alih pola
   `[ipv4-addr:value = '1.2.3.4']` yang dipersyaratkan STIX 2.1. Parser di sini mencoba
   pattern dulu, lalu jatuh ke `value` — tanpa itu, feed yang formatnya sedikit
   menyimpang akan terlihat "kosong" tanpa satu pun baris tertarik, dan tidak ada
   pesan error yang menjelaskan kenapa.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import httpx

from . import config
from .normalize import (NormalizeError, hash_algo, normalize_confidence,
                        normalize_domain, normalize_hash, normalize_ip,
                        normalize_severity, normalize_tlp, normalize_url)

TIMEOUT = httpx.Timeout(20.0, connect=10.0)

# Skala severity standar (Critical/High/Medium/Low/Info) — bukan skala internal
# "Malicious/Critical/High/Medium/Low/Info" yang dipakai jalur ingest push. Nilai
# `reputation` FortiSOAR dipetakan ke sini, bukan disalin mentah sebagai severity,
# supaya kolom Severity di dashboard konsisten dengan taksonomi standar yang dipakai
# tim (Critical = butuh perhatian segera, ... Info = sekadar informasi).
REPUTATION_SEVERITY = {
    "malicious": "Critical",
    "suspicious": "High",
    "unknown": "Medium",
    "known good": "Info", "good": "Info", "benign": "Info",
    "clean": "Info", "trusted": "Info", "safe": "Info", "whitelisted": "Info",
}

# Pola STIX 2.1 baku untuk alamat/domain/url: [ipv4-addr:value = '1.2.3.4'] dst.
# FortiSOAR terkadang menggabungkan beberapa observable dengan OR di satu pattern;
# semua kecocokan diambil, bukan hanya yang pertama.
_ADDR_PATTERN_RE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'", re.IGNORECASE)
# Pola STIX 2.1 baku untuk hash file: [file:hashes.'SHA-256' = '...'] — kutip di
# sekitar nama algoritma tidak selalu ada, dan penulisan SHA-1/SHA1 bervariasi.
_HASH_PATTERN_RE = re.compile(
    r"file:hashes\.'?(?:MD5|SHA-?1|SHA-?256)'?\s*=\s*'([^']+)'", re.IGNORECASE)

_STIX_TYPE_TO_IOC = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain",
                     "url": "url"}
_NORMALIZERS = {"ip": normalize_ip, "domain": normalize_domain, "hash": normalize_hash,
                "url": normalize_url}


class TaxiiError(RuntimeError):
    """Kegagalan yang harus ditampilkan apa adanya ke operator, bukan disamarkan."""


def _client(base_url: str, key_name: str, api_key: str, verify_tls: bool) -> httpx.Client:
    return httpx.Client(
        base_url=base_url.rstrip("/") + "/",
        auth=(key_name, api_key) if key_name else None,
        headers=({"Authorization": f"API-KEY {api_key}"} if not key_name and api_key else {})
               | {"Accept": "application/taxii+json;version=2.1, application/json"},
        timeout=TIMEOUT, verify=verify_tls,
    )


def _raise_for(resp: httpx.Response, action: str) -> None:
    if resp.status_code == 401:
        raise TaxiiError(f"{action}: 401 — API key atau nama key salah")
    if resp.status_code == 403:
        raise TaxiiError(f"{action}: 403 — key valid tapi tidak berizin ke koleksi ini")
    if resp.status_code == 404:
        raise TaxiiError(f"{action}: 404 — path TAXII tidak ditemukan; cek Server Address")
    if resp.status_code >= 400:
        raise TaxiiError(f"{action}: HTTP {resp.status_code} — {resp.text[:200]}")


def test_connection(base_url: str, key_name: str, api_key: str, verify_tls: bool = True) -> dict:
    """Discovery + daftar collections. Dipakai tombol 'Uji Koneksi' di GUI.

    `base_url` adalah Server Address (api-root), mis. https://host/api/taxii/1/ —
    endpoint discovery FortiSOAR ada persis satu segmen di bawahnya: .../taxii.
    """
    try:
        with _client(base_url, key_name, api_key, verify_tls) as c:
            title = None
            disc = c.get("taxii")
            if disc.status_code < 400:
                try:
                    title = disc.json().get("title")
                except ValueError:
                    pass

            coll_resp = c.get("collections")
            _raise_for(coll_resp, "Ambil daftar collections")
            data = coll_resp.json()
            collections = data.get("collections", data if isinstance(data, list) else [])
            out = [{"id": item.get("id"), "title": item.get("title") or item.get("id"),
                    "description": item.get("description", "")} for item in collections]
    except httpx.ConnectError as exc:
        raise TaxiiError(f"Tidak dapat terhubung ke {base_url}: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise TaxiiError(f"Timeout menghubungi {base_url} (20 detik): {exc}") from exc
    except httpx.HTTPError as exc:
        raise TaxiiError(f"Kesalahan HTTP: {exc}") from exc
    return {"server_title": title, "collections": out}


def _detect_fortisoar_ioc_type(obj: dict) -> str:
    """Simpulkan jenis indikator untuk bentuk non-standar FortiSOAR (field `value`
    langsung, bukan `pattern` STIX). `indicatorTypes` dan `typeOfFeed` dicek dulu
    karena eksplisit dari FortiSOAR sendiri; bentuk nilai literal hanya dipakai
    sebagai upaya terakhir bila kedua field itu tidak ada atau tidak jelas.
    """
    types = obj.get("indicatorTypes") or []
    feed_type = str(obj.get("typeOfFeed") or "").lower()
    hay = " ".join([str(t).lower() for t in types] + [feed_type])
    if "hash" in hay or "file" in hay or "md5" in hay or "sha" in hay:
        return "hash"
    if "url" in hay:
        return "url"
    if "domain" in hay:
        return "domain"
    if "ip" in hay:
        return "ip"

    raw = obj.get("value")
    v = str(raw[0] if isinstance(raw, list) and raw else raw or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", v):
        return "hash"
    if "://" in v:
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    return "domain"


def _extract_iocs(obj: dict) -> list[tuple[str, str]]:
    """Ambil semua indikator (ip/domain/hash) dari satu objek TAXII.

    Mencoba `pattern` STIX baku dulu (bisa memuat lebih dari satu jenis, mis. IP
    dan hash sekaligus lewat OR), lalu jatuh ke field `value` mentah dengan jenis
    disimpulkan dari `indicatorTypes`/`typeOfFeed` — bentuk yang justru dipakai
    FortiSOAR untuk mayoritas objeknya.
    """
    found: list[tuple[str, str]] = []
    pattern = obj.get("pattern")
    if isinstance(pattern, str):
        for stix_type, val in _ADDR_PATTERN_RE.findall(pattern):
            found.append((_STIX_TYPE_TO_IOC[stix_type.lower()], val))
        for val in _HASH_PATTERN_RE.findall(pattern):
            found.append(("hash", val))

    if not found:
        raw = obj.get("value")
        vals = [str(v).strip() for v in (raw if isinstance(raw, list) else [raw])
                if v and str(v).strip()]
        if vals:
            ioc_type = _detect_fortisoar_ioc_type(obj)
            found.extend((ioc_type, v) for v in vals)
    return found


def _object_to_records(obj: dict, default_source: str, default_feed: str) -> list[dict]:
    """Ubah satu objek TAXII menjadi satu atau lebih record siap-upsert.

    FortiSOAR TIDAK mengirim STIX 2.1 standar untuk feed ini — objeknya adalah
    `ThreatIntel` FortiSOAR sendiri: `reputation`, `source`, dan `tLP` (huruf L
    kapital di tengah, bukan `tlp`) ada langsung sebagai field objek, `pattern`
    dan `labels` selalu kosong. Memperlakukannya sebagai STIX baku membuat type
    jatuh ke "Indicator" generik, comment jatuh ke nilai `name` (yang kebetulan
    berisi nilai indikator itu sendiri), dan source selalu memakai nama feed
    lokal — bukan sumber intel sesungguhnya seperti "IPsum Threat Intelligence
    Feed" atau "FortiGuard Outbreak".

    Satu koleksi FortiGuard Outbreak lazim mencampur alamat IP dan hash file
    (`typeOfFeed: "FileHash-SHA256"`) dalam koleksi yang sama — setiap indikator
    diproses menurut jenisnya sendiri (`ioc_type`), bukan diasumsikan semuanya IP.
    """
    if obj.get("type") not in ("indicator", "ipv4-addr", "ipv6-addr",
                               "domain-name", "file", "url"):
        return []

    iocs_raw = _extract_iocs(obj)
    if not iocs_raw:
        return []

    reputation = obj.get("reputation")                        # "Malicious", "Suspicious", ...
    source_name = obj.get("source") or default_source          # nama feed intel FortiSOAR
    tlp_raw = obj.get("tLP") or obj.get("x_tlp") or obj.get("tlp")
    confidence_raw = obj.get("confidence", 70)

    # Fallback untuk server yang benar-benar mengirim STIX 2.1 baku (bukan
    # bentuk FortiSOAR di atas): reputation kosong, pakai labels/severity biasa.
    labels = obj.get("labels") or obj.get("indicator_types") or []
    # Severity mengikuti skala standar (Critical/High/Medium/Low/Info), bukan
    # nilai reputation mentah — "Malicious" sebagai teks severity tidak ada di
    # taksonomi itu, dan tanpa pemetaan ini kolom Severity akan berisi nilai
    # yang tidak dikenal alih-alih tingkat keparahan yang bisa dibandingkan.
    if reputation:
        severity_raw = REPUTATION_SEVERITY.get(reputation.strip().lower(), "Medium")
    else:
        severity_raw = obj.get("x_severity") or obj.get("severity") or "Medium"
    type_value = reputation or (labels[0].title() if labels else "Indicator")
    # Pemisah ASCII biasa, BUKAN em-dash "—": FortiOS memotong field
    # description pada external-resource malware-hash begitu ketemu byte
    # non-ASCII pertama. Em-dash adalah UTF-8 tiga-byte (\xe2\x80\x94) —
    # "FortiGuard Outbreak — Malicious" terpotong jadi "FortiGuard Outbreak "
    # tepat di titik itu, membuang seluruh info reputasi dari deskripsi yang
    # dilihat scanunit daemon. Dikonfirmasi lewat `diagnose sys scanunit
    # file-hash list malware` di server produksi.
    comment = " - ".join(p for p in (source_name, reputation) if p)[:500] \
        or (obj.get("description") or "")[:500]

    out = []
    for ioc_type, raw_val in iocs_raw:
        normalizer = _NORMALIZERS.get(ioc_type)
        if normalizer is None:
            continue
        try:
            value = normalizer(raw_val)
        except (NormalizeError, ValueError):
            # NormalizeError untuk input yang jelas kosong/rusak; ValueError
            # mentah tetap dijaga sebagai jaring pengaman meski normalize_ip
            # sudah tidak membocorkannya lagi — satu objek yang bentuknya
            # tidak terduga tidak boleh men-crash SELURUH siklus tarikan (500),
            # hanya dilewati sendiri.
            continue
        out.append({
            "ip_address": value,
            "ioc_type": ioc_type,
            "type": type_value,
            "severity": normalize_severity(severity_raw),
            "confidence": normalize_confidence(confidence_raw),
            "tlp": normalize_tlp(tlp_raw or "TLP:AMBER"),
            "source": source_name,
            "comment": comment,
            "feed_name": default_feed,
        })
    return out


def pull_collection(base_url: str, key_name: str, api_key: str, collection_id: str,
                    feed_name: str, added_after: str | None = None,
                    verify_tls: bool = True, page_limit: int = 20) -> dict:
    """Tarik seluruh objek koleksi (dengan paginasi TAXII `next`), lalu ubah ke record.

    `added_after` membatasi ke objek yang ditambahkan setelah timestamp ISO-8601 —
    tanpa ini, setiap siklus polling menarik ulang seluruh riwayat koleksi.
    """
    records: list[dict] = []
    raw_object_count = 0
    next_cursor = None
    pages = 0

    with _client(base_url, key_name, api_key, verify_tls) as c:
        while pages < page_limit:
            params: dict[str, Any] = {"limit": 1000}
            if added_after:
                params["added_after"] = added_after
            if next_cursor:
                params["next"] = next_cursor

            resp = c.get(f"collections/{collection_id}/objects", params=params)
            _raise_for(resp, f"Tarik objek dari koleksi {collection_id}")
            body = resp.json()
            objects = body.get("objects", [])
            raw_object_count += len(objects)

            for obj in objects:
                records.extend(_object_to_records(obj, f"FortiSOAR TAXII:{feed_name}", feed_name))

            pages += 1
            prev_cursor = next_cursor
            next_cursor = body.get("next")
            has_more = body.get("more", False)
            if not next_cursor or not has_more:
                break
            if next_cursor == prev_cursor:
                # Server mengembalikan cursor `next` yang sama dengan siklus
                # sebelumnya sambil tetap bilang more=true — melanjutkan hanya
                # akan mengulang permintaan halaman yang sama sampai page_limit
                # habis (terlihat di log sebagai deretan `next=N` identik
                # berkali-kali). Ini kerusakan sisi server, bukan sesuatu yang
                # bisa diperbaiki dengan meminta lebih banyak — berhenti sekarang
                # sambil tetap melaporkan apa yang berhasil ditarik.
                break

    return {"raw_objects": raw_object_count, "records": records, "pages": pages}
