"""One import entry point for GreyNoise and TAXII."""

from __future__ import annotations

import os
from pathlib import Path

from ingest.arcadedb import Arcade, lit
from ingest.bundle import GraphBundle
from ingest.greynoise import PRECURSOR_QUERY, STORM_QUERY, bundle_from_api, bundle_from_file
from ingest.taxii import discover_collections, iter_objects, map_stix
from ingest.timeline import fetch_kev, kev_bundle, read_timeline, timeline_bundle

ROOT = Path(__file__).resolve().parents[1]


def default_gnql_path() -> Path:
    matches = sorted(ROOT.glob("gnql_*.json"))
    if not matches:
        raise FileNotFoundError("no GNQL export in the project folder")
    return matches[-1]


def run_import(
    source: str,
    mode: str = "file",
    path: str | None = None,
    query: str | None = None,
    added_after: str | None = None,
    precursor: bool = False,
    include_context: bool = True,
) -> dict:
    if source not in {"greynoise", "taxii"}:
        raise ValueError("source must be greynoise or taxii")
    bundle = GraphBundle()
    if source == "greynoise":
        if mode == "api" or precursor:
            chosen = PRECURSOR_QUERY if precursor else (query or STORM_QUERY)
            bundle = bundle_from_api(chosen, os.environ.get("GREYNOISE_API_KEY", ""))
        else:
            bundle = bundle_from_file(Path(path) if path else default_gnql_path())
    else:
        base = os.environ.get("TAXII_BASE_URL") or "http://127.0.0.1:4200"
        token = os.environ.get("TAXII_TOKEN") or ""
        collection_id = os.environ.get("TAXII_COLLECTION_ID") or ""
        collections = discover_collections(base, token, collection_id)
        if not collections:
            raise RuntimeError(f"no readable TAXII 2.1 collections at {base}")
        objects = []
        for url, _cid in collections:
            objects.extend(iter_objects(url, token, added_after or ""))
        bundle = map_stix(objects)
    if include_context and source == "greynoise":
        doc = read_timeline()
        bundle.merge(timeline_bundle(doc))
        bundle.merge(kev_bundle(fetch_kev(), doc))
    previous = _previous_meta()
    db = Arcade()
    db.ensure_schema()
    counts = db.upsert_bundle(bundle)
    meta = GraphBundle()
    meta.vertex(
        "Meta",
        "meta:import",
        label="last import",
        source=source,
        query=bundle.meta.get("query", ""),
        mode=mode if source == "greynoise" else "taxii",
        precursor=precursor,
        added_after=added_after or "",
        vertices=counts["vertices"],
        edges=counts["edges"],
        previous_vertices=previous.get("vertices") or 0,
        vertex_delta=counts["vertices"] - int(previous.get("vertices") or 0),
    )
    db.upsert_vertices(meta)
    counts.update(bundle.meta)
    counts["vertex_delta"] = counts["vertices"] - int(previous.get("vertices") or 0)
    if include_context and source == "greynoise":
        from model.stats import collect_stats
        from model.weather import forecast

        condition = forecast(collect_stats(db, "CVE-2026-88771"))["condition"]
        db.command(f"UPDATE Meta SET condition = {lit(condition)} WHERE key = 'meta:import'")
        counts["condition"] = condition
    return counts


def _previous_meta() -> dict:
    try:
        rows = Arcade().command("SELECT FROM Meta WHERE key = 'meta:import'")
    except Exception:
        return {}
    return rows[0] if rows else {}
