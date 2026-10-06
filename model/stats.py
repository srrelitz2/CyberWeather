"""SQL aggregates used by the forecast and the heat map."""

from __future__ import annotations

from ingest.arcadedb import Arcade
from ingest.normalize import CVE_RE

MAP_NAMES = {
    "United States": "United States of America",
    "United States of America": "United States of America",
    "USA": "United States of America",
    "Czechia": "Czech Republic",
    "Czech Republic": "Czech Republic",
    "Russian Federation": "Russia",
    "Russia": "Russia",
    "Republic of Korea": "South Korea",
    "Korea, Republic of": "South Korea",
    "South Korea": "South Korea",
    "Viet Nam": "Vietnam",
    "Vietnam": "Vietnam",
    "Iran, Islamic Republic of": "Iran",
    "Syrian Arab Republic": "Syria",
    "Lao People's Democratic Republic": "Laos",
    "Republic of Moldova": "Moldova",
    "Tanzania": "United Republic of Tanzania",
    "United Republic of Tanzania": "United Republic of Tanzania",
    "Côte d'Ivoire": "Ivory Coast",
    "Cote d'Ivoire": "Ivory Coast",
    "Ivory Coast": "Ivory Coast",
    "North Macedonia": "Macedonia",
    "Macedonia": "Macedonia",
    "The Netherlands": "Netherlands",
    "Netherlands": "Netherlands",
    "Hong Kong": "Hong Kong",
    "Taiwan": "Taiwan",
}


def map_name(name: str) -> str:
    return MAP_NAMES.get(name, name)


def _pattern(cve: str) -> str:
    cve = cve.upper()
    if not CVE_RE.match(cve):
        raise ValueError("invalid CVE")
    return f"%|cve:{cve}|%"


def _count(db: Arcade, where: str, pattern: str) -> int:
    rows = db.command(
        f"SELECT count(*) AS n FROM Ip WHERE cve_keys LIKE :pat AND ({where})",
        {"pat": pattern},
    )
    return int(rows[0]["n"]) if rows else 0


def collect_stats(db: Arcade, cve: str) -> dict:
    cve = cve.upper()
    pattern = _pattern(cve)
    cve_key = f"cve:{cve}"
    session_rows = db.command(
        "SELECT session_count FROM Exploits WHERE to_key = :key",
        {"key": cve_key},
        limit=100000,
    )
    totals = db.command(
        "SELECT sum(session_count) AS total, max(session_count) AS peak FROM Exploits WHERE to_key = :key",
        {"key": cve_key},
    )
    orgs = db.command(
        "SELECT organization, count(*) AS n FROM Ip WHERE cve_keys LIKE :pat AND organization <> '' GROUP BY organization ORDER BY n DESC LIMIT 8",
        {"pat": pattern},
    )
    sensors = db.command(
        "SELECT sensor_count FROM Ip WHERE cve_keys LIKE :pat",
        {"pat": pattern},
        limit=100000,
    )
    hits = db.command(
        "SELECT max(sensor_hits) AS peak FROM Ip WHERE cve_keys LIKE :pat",
        {"pat": pattern},
    )
    kev_rows = db.command("SELECT FROM Kev WHERE cve = :cve", {"cve": cve})
    events = db.command("SELECT label, at FROM Event ORDER BY at", limit=50)
    meta_rows = db.command("SELECT FROM Meta WHERE key = 'meta:import'", limit=5)
    destinations = heatmap(db)["destination"]
    kev = kev_rows[0] if kev_rows else {}
    meta = meta_rows[0] if meta_rows else {}
    query = str(meta.get("query") or "")
    total = totals[0] if totals else {}
    return {
        "cve": cve,
        "malicious_ips": _count(db, "classification = 'malicious' AND spoofable = false", pattern),
        "ip_count": _count(db, "label <> ''", pattern),
        "crawler": _count(db, "has_crawler = true", pattern),
        "scanner": _count(db, "has_scanner = true", pattern),
        "sibling": _count(db, "has_bleed = true", pattern),
        "trio": _count(db, "precursor_trio = true", pattern),
        "reused": _count(db, "first_seen < '2026-09-24'", pattern),
        "between": _count(db, "first_seen >= '2026-09-24' AND first_seen < '2026-09-27'", pattern),
        "post": _count(db, "first_seen >= '2026-09-27'", pattern),
        "session_values": [int(row.get("session_count") or 0) for row in session_rows],
        "session_sum": int(total.get("total") or 0),
        "session_max": int(total.get("peak") or 0),
        "sensor_values": [int(row.get("sensor_count") or 0) for row in sensors],
        "max_hits": int((hits[0].get("peak") if hits else 0) or 0),
        "kev_listed": bool(kev),
        "catalog_match": bool(kev.get("catalog_match")),
        "kev_source": kev.get("source") or "",
        "kev_date": kev.get("date_added") or "",
        "required_action": kev.get("required_action") or "",
        "top_organizations": [
            {"name": row.get("organization") or "", "count": int(row.get("n") or 0)} for row in orgs
        ],
        "top_destinations": destinations[:8],
        "timeline": [
            {"title": row.get("label") or "", "at": row.get("at") or ""}
            for row in events
            if row.get("label")
        ],
        "after_landfall": cve.lower() in query.lower(),
        "vertex_delta": int(meta.get("vertex_delta") or 0),
        "previous_condition": meta.get("condition") or "",
    }


def heatmap(db: Arcade) -> dict:
    layers = {}
    for layer in ("source", "destination"):
        rows = db.command(
            "SELECT country_code, country_name, count(*) AS n FROM Exposure WHERE layer = :layer GROUP BY country_code, country_name",
            {"layer": layer},
            limit=100000,
        )
        merged: dict[str, dict] = {}
        for row in rows:
            name = row.get("country_name") or row.get("country_code") or ""
            if not name:
                continue
            target = map_name(name)
            slot = merged.setdefault(
                target,
                {"code": row.get("country_code") or "", "name": name, "map_name": target, "count": 0},
            )
            slot["count"] += int(row.get("n") or 0)
            if row.get("country_code") and not slot["code"]:
                slot["code"] = row.get("country_code")
        layers[layer] = sorted(merged.values(), key=lambda item: item["count"], reverse=True)
    return {
        "source": layers["source"],
        "destination": layers["destination"],
        "note": "Destination counts are GreyNoise sensor coverage, not a map of confirmed vulnerable assets.",
        "citation": "Unit 42 reported about 50,277 exposed NetScaler instances on 27 Sep 2026.",
    }


EDGE_KIND = {
    "Exploits": "exploits",
    "HostedBy": "hosted-by",
    "SameFingerprint": "same-fingerprint",
    "ListedInKev": "listed-in-kev",
    "CitedBy": "cited-by",
    "ObservedWith": "observed-with",
    "LocatedIn": "located-in",
    "MemberOf": "member-of",
    "Related": "related",
    "Indicates": "indicates",
}


def neighborhood(db: Arcade, focus: str, hops: int) -> dict:
    if hops not in {1, 2, 3}:
        raise ValueError("hops must be 1, 2, or 3")
    prefix = focus.split(":", 1)[0]
    from ingest.bundle import PREFIX_TYPE

    vtype = PREFIX_TYPE.get(prefix)
    if not vtype:
        raise ValueError("unknown focus")
    vertices = db.command(
        f"TRAVERSE out(), in() FROM (SELECT FROM {vtype} WHERE key = :focus) WHILE $depth <= :hops",
        {"focus": focus, "hops": hops},
        limit=100000,
    )
    edges = db.command(
        f"SELECT expand(bothE()) FROM (TRAVERSE out(), in() FROM (SELECT FROM {vtype} WHERE key = :focus) WHILE $depth <= :hops)",
        {"focus": focus, "hops": hops},
        limit=100000,
    )
    rid_to_key = {}
    nodes = []
    seen = set()
    for row in vertices:
        key = row.get("key")
        rid = row.get("@rid")
        if not key or key in seen:
            continue
        seen.add(key)
        if rid:
            rid_to_key[rid] = key
        nodes.append(
            {
                "id": key,
                "label": row.get("label") or row.get("name") or key,
                "kind": row.get("@type") or "Entity",
                "trio": bool(row.get("precursor_trio")),
            }
        )
    links = []
    seen_edges = set()
    for row in edges:
        rid = row.get("@rid")
        if rid in seen_edges:
            continue
        source = rid_to_key.get(row.get("@out"))
        target = rid_to_key.get(row.get("@in"))
        if not source or not target:
            continue
        seen_edges.add(rid)
        kind = row.get("rel") or EDGE_KIND.get(row.get("@type"), row.get("@type") or "related")
        links.append({"source": source, "target": target, "kind": kind})
    return {"focus": focus, "hops": hops, "nodes": nodes, "links": links}
