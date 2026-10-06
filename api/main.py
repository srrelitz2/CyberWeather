"""Cyber Weather HTTP API."""

from __future__ import annotations

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ingest.arcadedb import Arcade, ArcadeError
from ingest.load import run_import
from model.stats import collect_stats, heatmap, neighborhood
from model.weather import forecast

app = FastAPI(title="Cyber Weather")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ImportBody(BaseModel):
    source: str = Field(pattern="^(greynoise|taxii)$")
    mode: str = "file"
    path: str | None = None
    query: str | None = None
    added_after: str | None = None
    precursor: bool = False


def _db() -> Arcade:
    return Arcade()


@app.get("/health")
def health():
    db = _db()
    try:
        response = httpx.get(f"{db.url}/api/v1/ready", timeout=5)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"ArcadeDB is not reachable at {db.url}") from exc
    return {"ok": response.status_code < 500, "arcadedb": db.url, "database": db.database}


@app.post("/import")
def import_source(body: ImportBody):
    try:
        return run_import(
            source=body.source,
            mode=body.mode,
            path=body.path,
            query=body.query,
            added_after=body.added_after,
            precursor=body.precursor,
        )
    except (ArcadeError, ValueError, RuntimeError, OSError, httpx.HTTPError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/forecast")
def forecast_cve(cve: str = "CVE-2026-88771"):
    try:
        return forecast(collect_stats(_db(), cve))
    except (ArcadeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/graph")
def graph(focus: str = "cve:CVE-2026-88771", hops: int = 2):
    try:
        return neighborhood(_db(), focus, hops)
    except (ArcadeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/heatmap")
def heat():
    try:
        return heatmap(_db())
    except ArcadeError as exc:
        raise HTTPException(400, str(exc)) from exc
