"""Turn a GreyNoise GNQL payload into graph vertices. HTTP bodies are dropped."""

from __future__ import annotations

import re

from ingest.bundle import GraphBundle

CRAWLER = "Citrix ADC Gateway Login Panel Crawler"
SCANNER = "Citrix ADC / NetScaler Scanner"
BLEED = "CitrixBleed 2 CVE-2025-5777 Attempt"
FOCUS_CVE = "CVE-2026-88771"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)

# Payload-shaped tokens. Values that contain these are not stored.
PAYLOAD_MARKERS = ("${", "IFS", "/bin/sh", "cmd.exe", "eval(", "union select")


def _text(value) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", " ").strip()
    return text[:500]


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe(value: str) -> str | None:
    text = _text(value)
    if not text:
        return None
    lowered = text.lower()
    if any(marker.lower() in lowered for marker in PAYLOAD_MARKERS):
        return None
    return text


def records_from_payload(payload) -> tuple[list[dict], dict]:
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return payload["data"], payload.get("request_metadata") or {}
    if isinstance(payload, list):
        return payload, {}
    raise ValueError("GreyNoise payload must be a GNQL object with data[] or a list of records")


def normalize_greynoise(payload, origin: str = "greynoise") -> GraphBundle:
    records, meta = records_from_payload(payload)
    bundle = GraphBundle()
    bundle.meta = {
        "source": origin,
        "query": _text(meta.get("query") or meta.get("adjusted_query")),
        "count": meta.get("count", len(records)),
    }
    for record in records:
        _one_ip(bundle, record, origin)
    return bundle


def _one_ip(bundle: GraphBundle, record: dict, origin: str) -> None:
    address = _safe(record.get("ip"))
    if not address:
        return
    isi = record.get("internet_scanner_intelligence") or {}
    # raw_data.http, paths, headers, cookies, and scan bodies are intentionally ignored.
    raw = isi.get("raw_data") if isinstance(isi.get("raw_data"), dict) else {}
    meta = isi.get("metadata") if isinstance(isi.get("metadata"), dict) else {}
    bsi = record.get("business_service_intelligence") if isinstance(record.get("business_service_intelligence"), dict) else {}

    tags = [tag for tag in (isi.get("tags") or []) if isinstance(tag, dict)]
    names = {_text(tag.get("name")) for tag in tags}
    has_crawler = CRAWLER in names
    has_scanner = SCANNER in names
    has_bleed = BLEED in names
    volumes = {}
    for item in isi.get("tag_volumes") or []:
        if isinstance(item, dict) and item.get("tag_id"):
            volumes[str(item["tag_id"])] = _int(item.get("session_count"))

    cve_sessions: dict[str, int] = {}
    cves = []
    for cve in isi.get("cves") or []:
        cve_id = _text(cve).upper()
        if CVE_RE.match(cve_id):
            cves.append(cve_id)
            cve_sessions.setdefault(cve_id, 0)
    for tag in tags:
        volume = volumes.get(str(tag.get("id")), 0)
        for cve in tag.get("cves") or []:
            cve_id = _text(cve).upper()
            if CVE_RE.match(cve_id):
                cve_sessions[cve_id] = max(cve_sessions.get(cve_id, 0), volume)

    org_name = _safe(meta.get("organization")) or _safe(bsi.get("name"))
    asn = _safe(meta.get("asn"))
    country_name = _safe(meta.get("source_country"))
    country_code = _safe(meta.get("source_country_code")) or ""
    ip_key = f"ip:{address}"
    cve_keys = "|" + "|".join(f"cve:{cve}" for cve in sorted(set(cves))) + "|" if cves else ""

    bundle.vertex(
        "Ip",
        ip_key,
        label=address,
        address=address,
        classification=_safe(isi.get("classification")) or "",
        spoofable=_flag(isi.get("spoofable")),
        first_seen=_text(isi.get("first_seen"))[:10],
        last_seen=_text(isi.get("last_seen"))[:10],
        actor=_safe(isi.get("actor")) or "",
        sensor_count=_int(meta.get("sensor_count")),
        sensor_hits=_int(meta.get("sensor_hits")),
        has_crawler=has_crawler,
        has_scanner=has_scanner,
        has_bleed=has_bleed,
        precursor_trio=has_crawler and has_scanner and has_bleed,
        organization=org_name or "",
        source_country=country_name or "",
        source_country_code=country_code,
        cve_keys=cve_keys,
        origin=origin,
    )
    if country_name or country_code:
        country_key = f"country:{(country_code or country_name).lower()}"
        bundle.vertex("Country", country_key, label=country_name or country_code, code=country_code, name=country_name or "")
        bundle.edge("LocatedIn", ip_key, country_key)
        bundle.expose("source", country_code, country_name or country_code, origin)

    dest_names = meta.get("destination_countries") or []
    dest_codes = meta.get("destination_country_codes") or []
    if not isinstance(dest_names, list):
        dest_names = []
    if not isinstance(dest_codes, list):
        dest_codes = []
    for index, code in enumerate(dest_codes):
        code_text = _safe(code) or ""
        name = ""
        if index < len(dest_names):
            name = _safe(dest_names[index]) or ""
        bundle.expose("destination", code_text, name or code_text, origin)

    if org_name:
        org_key = "org:" + org_name.lower()
        bundle.vertex(
            "Organization",
            org_key,
            label=org_name,
            name=org_name,
            category=_safe(bsi.get("category")) or _safe(meta.get("category")) or "",
        )
        bundle.edge("HostedBy", ip_key, org_key)
    if asn:
        asn_key = "asn:" + asn.lower()
        bundle.vertex("Asn", asn_key, label=asn, asn=asn)
        bundle.edge("MemberOf", ip_key, asn_key)

    for tag in tags:
        slug = _safe(tag.get("slug")) or _safe(tag.get("id"))
        name = _safe(tag.get("name"))
        if not slug or not name:
            continue
        tag_key = f"tag:{slug}"
        bundle.vertex(
            "Tag",
            tag_key,
            label=name,
            name=name,
            slug=slug,
            intention=_safe(tag.get("intention")) or "",
            category=_safe(tag.get("category")) or "",
        )
        bundle.edge("ObservedWith", ip_key, tag_key, session_count=volumes.get(str(tag.get("id")), 0))
        for cve in tag.get("cves") or []:
            cve_id = _text(cve).upper()
            if CVE_RE.match(cve_id):
                cve_key = f"cve:{cve_id}"
                bundle.vertex("Cve", cve_key, label=cve_id, cve=cve_id)
                bundle.edge("Related", tag_key, cve_key)

    for cve_id, sessions in cve_sessions.items():
        cve_key = f"cve:{cve_id}"
        bundle.vertex("Cve", cve_key, label=cve_id, cve=cve_id)
        bundle.edge("Exploits", ip_key, cve_key, session_count=sessions)

    for item in raw.get("ja3") or []:
        if not isinstance(item, dict):
            continue
        fingerprint = _safe(item.get("fingerprint"))
        if not fingerprint or not re.fullmatch(r"[a-fA-F0-9]{32}", fingerprint):
            continue
        ja_key = f"ja3:{fingerprint.lower()}"
        bundle.vertex("Ja3", ja_key, label=fingerprint.lower(), fingerprint=fingerprint.lower())
        bundle.edge("SameFingerprint", ip_key, ja_key, port=_safe(item.get("port")) or "")
