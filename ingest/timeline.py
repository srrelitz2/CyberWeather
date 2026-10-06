"""Curated Citrix timeline and the CISA KEV join."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import yaml

from ingest.bundle import GraphBundle
from ingest.normalize import CVE_RE, _safe

ROOT = Path(__file__).resolve().parents[1]
TIMELINE_PATH = ROOT / "data" / "timeline.yaml"
KEV_CACHE = ROOT / "data" / "kev.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def read_timeline(path: Path = TIMELINE_PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def timeline_bundle(doc: dict | None = None) -> GraphBundle:
    doc = doc or read_timeline()
    bundle = GraphBundle()
    cve = doc["cve"].upper()
    if not CVE_RE.match(cve):
        raise ValueError("timeline cve is invalid")
    cve_key = bundle.vertex("Cve", f"cve:{cve}", label=cve, cve=cve)
    for event in doc.get("events") or []:
        event_key = bundle.vertex(
            "Event",
            f"event:{event['id']}",
            label=_safe(event.get("title")) or event["id"],
            title=_safe(event.get("title")) or event["id"],
            at=_safe(event.get("at")) or "",
            cve=cve,
        )
        bundle.edge("CitedBy", event_key, cve_key)
    published = "event:malicious"
    for indicator in doc.get("indicators") or []:
        kind = indicator.get("kind")
        value = _safe(indicator.get("value"))
        label = _safe(indicator.get("label")) or value
        if not value or not label:
            continue
        ind_key = bundle.vertex(
            "Indicator",
            f"indicator:{kind}:{value}",
            label=label,
            name=label,
            indicator_kind=kind,
            observable=value if kind in {"ip", "sha256"} else "",
            origin="timeline",
        )
        bundle.edge("CitedBy", ind_key, cve_key)
        if published in bundle.vertices:
            bundle.edge("CitedBy", published, ind_key)
        if kind == "ip":
            ip_key = bundle.vertex("Ip", f"ip:{value}", label=value, address=value, origin="timeline")
            bundle.edge("Indicates", ind_key, ip_key)
    return bundle


def fetch_kev(cache: Path = KEV_CACHE) -> dict:
    cache.parent.mkdir(parents=True, exist_ok=True)
    try:
        response = httpx.get(KEV_URL, timeout=90, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()
        cache.write_text(json.dumps(payload), encoding="utf-8")
        return payload
    except (httpx.HTTPError, json.JSONDecodeError, OSError):
        if cache.exists():
            return json.loads(cache.read_text(encoding="utf-8"))
        raise


def kev_bundle(catalog: dict, doc: dict | None = None) -> GraphBundle:
    doc = doc or read_timeline()
    wanted = [doc["cve"].upper(), doc.get("paired_cve", "").upper()]
    found = {}
    for row in catalog.get("vulnerabilities") or []:
        cve = str(row.get("cveID") or "").upper()
        if cve in wanted:
            found[cve] = row
    bundle = GraphBundle()
    for cve in wanted:
        if not CVE_RE.match(cve):
            continue
        row = found.get(cve)
        if row:
            props = {
                "catalog_match": True,
                "source": "cisa-kev",
                "date_added": _safe(row.get("dateAdded")) or "",
                "name": _safe(row.get("vulnerabilityName")) or cve,
                "vendor": _safe(row.get("vendorProject")) or "",
                "product": _safe(row.get("product")) or "",
                "required_action": _safe(row.get("requiredAction")) or "",
            }
        else:
            props = {
                "catalog_match": False,
                "source": "cisa-alert",
                "date_added": _safe(doc.get("kev_added")) or "",
                "name": cve,
                "required_action": "Apply the vendor update and preserve forensic evidence before patching.",
            }
        kev_key = bundle.vertex("Kev", f"kev:{cve}", label=f"KEV {cve}", cve=cve, **props)
        cve_key = bundle.vertex("Cve", f"cve:{cve}", label=cve, cve=cve)
        bundle.edge("ListedInKev", cve_key, kev_key)
    primary = doc["cve"].upper()
    paired = doc.get("paired_cve", "").upper()
    if CVE_RE.match(primary) and CVE_RE.match(paired):
        bundle.edge("Related", f"cve:{primary}", f"cve:{paired}", rel="paired-kev")
    return bundle
