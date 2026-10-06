"""Forecast states from ArcadeDB aggregate numbers."""

from __future__ import annotations

CONDITIONS = ("Clear", "Watch", "Advisory", "Storm", "Named storm")

LIMITS = [
    "This GreyNoise export keeps malicious, non-spoofable sources only. Actor is unknown on these rows, and ASN subnet is restricted.",
    "first_seen is the IP’s GreyNoise lifetime, not the first CVE-2026-88771 packet.",
    "Destination countries measure where GreyNoise sensors saw the traffic aimed, not confirmed vulnerable assets.",
    "Hundreds of other CVEs sit on these IPs. Hop depth stops at 3. Depth 3 from a noisy IP can still pull sibling CVEs into view.",
]

ACTIONS = [
    "Patch NetScaler ADC and Gateway to the fixed builds in the Citrix security bulletin.",
    "Preserve forensic evidence before applying updates. Patching can remove the traces needed to confirm compromise.",
    "Hunt the published indicators linked from this CVE.",
]


def median(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def classify(stats: dict) -> str:
    malicious = int(stats.get("malicious_ips") or 0)
    if malicious > 0 and stats.get("kev_listed"):
        return "Named storm"
    if malicious > 0:
        return "Storm"
    crawler = int(stats.get("crawler") or 0)
    scanner = int(stats.get("scanner") or 0)
    sibling = int(stats.get("sibling") or 0)
    if (crawler or scanner) and sibling:
        return "Advisory"
    if crawler or scanner:
        return "Watch"
    return "Clear"


def _confidence(condition: str, ip_count: int) -> float:
    base = {"Clear": 0.34, "Watch": 0.48, "Advisory": 0.62, "Storm": 0.74, "Named storm": 0.82}[condition]
    if condition in {"Storm", "Named storm"}:
        base = min(0.95, base + min(ip_count, 150) / 900)
    return round(base, 2)


def _nature(condition: str, cve: str) -> str:
    if condition == "Named storm" and cve == "CVE-2026-88771":
        return (
            "Unauthenticated edge-gateway command injection is being attempted, mostly from reused "
            "hosting infrastructure that already probed CitrixBleed 2, with a second wave of addresses after disclosure."
        )
    return {
        "Clear": "No product crawler, scanner, or sibling exploitation is in the imported set.",
        "Watch": "Product crawlers or scanners are active, and this set has no CVE-specific malicious tag yet.",
        "Advisory": "Crawlers or scanners overlap a sibling exploited CVE on the same product. That is the precursor pattern from the Citrix case.",
        "Storm": "A CVE-specific malicious tag is present on non-spoofable infrastructure.",
        "Named storm": "CISA KEV lists this CVE and non-spoofable malicious sources are already tagged against it.",
    }[condition]


def forecast(stats: dict) -> dict:
    cve = stats.get("cve") or "CVE-2026-88771"
    condition = classify(stats)
    ip_count = int(stats.get("ip_count") or 0)
    sessions = [int(value) for value in stats.get("session_values") or []]
    actions = list(ACTIONS)
    required = stats.get("required_action") or ""
    if required and required not in actions:
        actions.insert(0, required)
    brief = {
        "cve": cve,
        "condition": condition,
        "confidence": _confidence(condition, ip_count),
        "after_landfall": bool(stats.get("after_landfall")),
        "after_landfall_note": (
            "This snapshot is after landfall. The leading signal is reconstructed from co-occurring tags and the article timeline, not observed live on 24 Sep."
            if stats.get("after_landfall")
            else ""
        ),
        "nature": _nature(condition, cve),
        "precursors": {
            "crawler": int(stats.get("crawler") or 0),
            "scanner": int(stats.get("scanner") or 0),
            "citrixbleed2": int(stats.get("sibling") or 0),
            "trio": int(stats.get("trio") or 0),
        },
        "first_seen": {
            "reused_before_sep24": int(stats.get("reused") or 0),
            "sep24_to_disclosure": int(stats.get("between") or 0),
            "on_or_after_disclosure": int(stats.get("post") or 0),
        },
        "sessions": {
            "ip_count": ip_count,
            "sum": int(stats.get("session_sum") or 0),
            "max": int(stats.get("session_max") or 0),
            "median": median(sessions),
        },
        "sensor_spread": {
            "median_sensors": median([int(value) for value in stats.get("sensor_values") or []]),
            "max_hits": int(stats.get("max_hits") or 0),
        },
        "kev": {
            "listed": bool(stats.get("kev_listed")),
            "catalog_match": bool(stats.get("catalog_match")),
            "source": stats.get("kev_source") or "",
            "date_added": stats.get("kev_date") or "",
            "paired_cve": "CVE-2026-88772",
        },
        "top_organizations": stats.get("top_organizations") or [],
        "top_destinations": stats.get("top_destinations") or [],
        "timeline": stats.get("timeline") or [],
        "exposure_citation": "Unit 42 reported about 50,277 exposed NetScaler instances on 27 Sep 2026. That figure is a citation, not a plotted layer.",
        "actions": actions,
        "limits": LIMITS,
        "deltas": {
            "vertex_delta": int(stats.get("vertex_delta") or 0),
            "previous_condition": stats.get("previous_condition") or "",
        },
    }
    return brief
