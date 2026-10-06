"""GreyNoise file and GNQL API import."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from ingest.normalize import normalize_greynoise

GNQL_URL = "https://api.greynoise.io/v3/gnql"
PRECURSOR_QUERY = (
    "last_seen:30d AND spoofable:false AND classification:malicious "
    'AND (tag:"Citrix ADC Gateway Login Panel Crawler" OR cve:CVE-2025-5777)'
)
STORM_QUERY = "cve:CVE-2026-88771 last_seen:30d AND spoofable:false AND classification:malicious"


def load_file(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fetch_gnql(query: str, api_key: str) -> dict:
    if not api_key:
        raise RuntimeError("GREYNOISE_API_KEY is not set")
    headers = {"key": api_key, "Accept": "application/json"}
    records: list[dict] = []
    scroll = None
    metadata: dict = {}
    with httpx.Client(timeout=90) as client:
        while True:
            params = {"query": query, "size": "1000"}
            if scroll:
                params["scroll"] = scroll
            response = client.get(GNQL_URL, headers=headers, params=params)
            response.raise_for_status()
            body = response.json()
            page = body.get("data") or []
            records.extend(page)
            metadata = body.get("request_metadata") or metadata
            scroll = metadata.get("scroll") or body.get("scroll")
            if not scroll or not page:
                break
    metadata = dict(metadata)
    metadata.setdefault("query", query)
    metadata["count"] = len(records)
    return {"data": records, "request_metadata": metadata}


def bundle_from_file(path: Path):
    return normalize_greynoise(load_file(path))


def bundle_from_api(query: str, api_key: str):
    return normalize_greynoise(fetch_gnql(query, api_key))
