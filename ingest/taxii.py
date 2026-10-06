"""TAXII 2.1 client and STIX 2.1 mapping. Patterns that look like payloads are not stored."""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from ingest.bundle import GraphBundle
from ingest.normalize import CVE_RE, PAYLOAD_MARKERS, _safe

TAXII_ACCEPT = "application/taxii+json;version=2.1"
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
STIX_TYPES = {
    "infrastructure": "Infrastructure",
    "malware": "Malware",
    "tool": "Tool",
    "identity": "Identity",
    "attack-pattern": "AttackPattern",
}


def _withheld(text: str) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in PAYLOAD_MARKERS)


def _edge_type(relationship: str) -> str:
    parts = re.sub(r"[^A-Za-z0-9]+", " ", relationship or "related-to").title().replace(" ", "")
    if not parts or not parts[0].isalpha():
        parts = "Rel" + parts
    return parts[:64]


def discover_collections(base_url: str, token: str = "", collection_id: str = "") -> list[tuple[str, str]]:
    """Return (collection_url, collection_id) pairs from a TAXII 2.1 discovery root."""
    root = base_url.rstrip("/") + "/"
    headers = {"Accept": TAXII_ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=60, headers=headers) as client:
        try:
            discovery_response = client.get(urljoin(root, "taxii2/"))
            discovery_response.raise_for_status()
            discovery = discovery_response.json()
        except httpx.HTTPError as exc:
            raise RuntimeError(f"TAXII server is not reachable at {base_url}") from exc
        api_roots = discovery.get("api_roots") or [root]
        found: list[tuple[str, str]] = []
        for api_root in api_roots:
            api = api_root if api_root.endswith("/") else api_root + "/"
            listing = client.get(urljoin(api, "collections/")).json()
            for collection in listing.get("collections") or []:
                cid = collection.get("id")
                if not cid:
                    continue
                if collection_id and cid != collection_id:
                    continue
                if collection.get("can_read") is False:
                    continue
                found.append((urljoin(api, f"collections/{cid}/objects/"), cid))
        return found


def iter_objects(collection_url: str, token: str = "", added_after: str = "") -> list[dict]:
    headers = {"Accept": TAXII_ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    objects: list[dict] = []
    params: dict[str, str] = {"limit": "200"}
    if added_after:
        params["added_after"] = added_after
    with httpx.Client(timeout=90, headers=headers) as client:
        url = collection_url
        while url:
            response = client.get(url, params=params)
            response.raise_for_status()
            page = response.json()
            objects.extend(page.get("objects") or [])
            if page.get("more") and page.get("next"):
                params = {"limit": "200", "next": page["next"]}
            else:
                break
    return objects


def map_stix(objects: list[dict]) -> GraphBundle:
    bundle = GraphBundle()
    stix_to_key: dict[str, str] = {}
    relationships = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        stix_id = _safe(obj.get("id"))
        if kind == "relationship" or kind == "sighting":
            relationships.append(obj)
            continue
        key = _map_object(bundle, obj)
        if stix_id and key:
            stix_to_key[stix_id] = key
    for obj in relationships:
        _map_relationship(bundle, obj, stix_to_key)
    bundle.meta = {"source": "taxii", "objects": len(objects)}
    return bundle


def _map_object(bundle: GraphBundle, obj: dict) -> str | None:
    kind = obj.get("type")
    stix_id = _safe(obj.get("id")) or ""
    name = _safe(obj.get("name")) or stix_id or kind
    if kind == "vulnerability":
        cve = _cve_from_object(obj)
        if not cve:
            return None
        return bundle.vertex("Cve", f"cve:{cve}", label=cve, cve=cve, stix_id=stix_id, origin="taxii")
    if kind == "indicator":
        return _map_indicator(bundle, obj, name, stix_id)
    if kind == "ipv4-addr":
        address = _safe(obj.get("value"))
        if not address or not IPV4_RE.fullmatch(address):
            return None
        return bundle.vertex("Ip", f"ip:{address}", label=address, address=address, origin="taxii", stix_id=stix_id)
    vtype = STIX_TYPES.get(kind or "")
    if vtype:
        prefix = {
            "Infrastructure": "infrastructure",
            "Malware": "malware",
            "Tool": "tool",
            "Identity": "identity",
            "AttackPattern": "attack",
        }[vtype]
        return bundle.vertex(vtype, f"{prefix}:{stix_id or name}", label=name, name=name, stix_id=stix_id, origin="taxii")
    if stix_id and kind and kind not in {"marking-definition", "extension-definition", "language-content"}:
        return bundle.vertex("StixObject", f"stix:{stix_id}", label=name, name=name, stix_type=kind, stix_id=stix_id, origin="taxii")
    return None


def _cve_from_object(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        external_id = _safe(ref.get("external_id")) or ""
        if CVE_RE.match(external_id.upper()):
            return external_id.upper()
    name = _safe(obj.get("name")) or ""
    match = re.search(r"CVE-\d{4}-\d{4,7}", name, re.I)
    return match.group(0).upper() if match else None


def _map_indicator(bundle: GraphBundle, obj: dict, name: str, stix_id: str) -> str | None:
    pattern = str(obj.get("pattern") or "")
    withheld = _withheld(pattern)
    observable = ""
    if not withheld:
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", pattern, re.I)
        ip_match = IPV4_RE.search(pattern)
        hash_match = SHA256_RE.search(pattern)
        if cve_match:
            observable = cve_match.group(0).upper()
        elif ip_match:
            observable = ip_match.group(0)
        elif hash_match:
            observable = hash_match.group(0).lower()
    key = bundle.vertex(
        "Indicator",
        f"indicator:{stix_id or observable or name}",
        label=name,
        name=name,
        stix_id=stix_id,
        observable=observable,
        pattern_withheld=withheld or not observable,
        origin="taxii",
    )
    if observable and CVE_RE.match(observable):
        cve_key = bundle.vertex("Cve", f"cve:{observable}", label=observable, cve=observable, origin="taxii")
        bundle.edge("Indicates", key, cve_key)
    elif observable and IPV4_RE.fullmatch(observable):
        ip_key = bundle.vertex("Ip", f"ip:{observable}", label=observable, address=observable, origin="taxii")
        bundle.edge("Indicates", key, ip_key)
    return key


def _map_relationship(bundle: GraphBundle, obj: dict, stix_to_key: dict[str, str]) -> None:
    if obj.get("type") == "sighting":
        source = _safe(obj.get("sighting_of_ref"))
        targets = obj.get("where_sighted_refs") or []
        rel_name = "sighting"
    else:
        source = _safe(obj.get("source_ref"))
        targets = [obj.get("target_ref")] if obj.get("target_ref") else []
        rel_name = _safe(obj.get("relationship_type")) or "related-to"
    if not source:
        return
    source_key = _resolve(bundle, source, stix_to_key)
    etype = _edge_type(rel_name)
    for target in targets:
        target_id = _safe(target)
        if not target_id:
            continue
        target_key = _resolve(bundle, target_id, stix_to_key)
        bundle.edge(etype, source_key, target_key, rel=rel_name)


def _resolve(bundle: GraphBundle, stix_id: str, stix_to_key: dict[str, str]) -> str:
    if stix_id in stix_to_key:
        return stix_to_key[stix_id]
    key = f"stix:{stix_id}"
    bundle.vertex("StixObject", key, label=stix_id, stix_id=stix_id, origin="taxii")
    stix_to_key[stix_id] = key
    return key
