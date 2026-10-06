"""ArcadeDB HTTP client, schema, and batch upserts."""

from __future__ import annotations

import os
import re

import httpx

from ingest.bundle import TYPE_PREFIX, GraphBundle

IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
VERTEX_TYPES = ["Entity", *TYPE_PREFIX.keys()]
EDGE_TYPES = [
    "Exploits",
    "HostedBy",
    "SameFingerprint",
    "ListedInKev",
    "CitedBy",
    "ObservedWith",
    "LocatedIn",
    "MemberOf",
    "Related",
    "Indicates",
]


def lit(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    text = str(value).replace("\n", " ").replace("\r", " ").replace("\\", "\\\\").replace("'", "\\'")
    return "'" + text + "'"


class ArcadeError(RuntimeError):
    pass


class Arcade:
    def __init__(self, url: str | None = None, database: str | None = None) -> None:
        self.url = (url or os.environ.get("ARCADEDB_URL") or "http://127.0.0.1:2481").rstrip("/")
        self.user = os.environ.get("ARCADEDB_USER") or "root"
        self.password = os.environ.get("ARCADEDB_PASSWORD") or "playwithdata"
        self.database = database or os.environ.get("ARCADEDB_DATABASE") or "cyberweather"
        self._edges: set[str] = set()

    def server(self, command: str):
        response = httpx.post(
            f"{self.url}/api/v1/server",
            json={"command": command},
            auth=(self.user, self.password),
            timeout=60,
        )
        return self._body(response)

    def command(self, sql: str, params: dict | None = None, limit: int = 20000, language: str = "sql"):
        payload: dict = {"language": language, "command": sql, "limit": limit}
        if params:
            payload["params"] = params
        response = httpx.post(
            f"{self.url}/api/v1/command/{self.database}",
            json=payload,
            auth=(self.user, self.password),
            timeout=180,
        )
        body = self._body(response)
        return body.get("result") or []

    def _body(self, response: httpx.Response) -> dict:
        try:
            body = response.json()
        except Exception as exc:
            raise ArcadeError(response.text[:500]) from exc
        if response.status_code >= 400 or "error" in body:
            detail = body.get("detail") or body.get("error") or response.text[:500]
            raise ArcadeError(str(detail))
        return body

    def script(self, statements: list[str], size: int = 25) -> None:
        for start in range(0, len(statements), size):
            chunk = statements[start : start + size]
            try:
                self.command(";\n".join(chunk), language="sqlscript", limit=5)
            except ArcadeError:
                for statement in chunk:
                    try:
                        self.command(statement)
                    except ArcadeError as exc:
                        if "Duplicated key" in str(exc):
                            continue
                        raise

    def ensure_schema(self) -> None:
        try:
            self.server(f"create database {self.database}")
        except ArcadeError as exc:
            if "already exists" not in str(exc).lower():
                raise
        for vtype in VERTEX_TYPES:
            self._ident(vtype)
            self.command(f"CREATE VERTEX TYPE {vtype} IF NOT EXISTS")
            if vtype != "Entity":
                self.command(f"ALTER TYPE {vtype} SUPERTYPE Entity")
            self.command(f"CREATE PROPERTY {vtype}.key IF NOT EXISTS STRING")
            self.command(f"CREATE INDEX IF NOT EXISTS ON {vtype} (key) UNIQUE")
        for etype in EDGE_TYPES:
            self.ensure_edge(etype)
        self.command("CREATE DOCUMENT TYPE Exposure IF NOT EXISTS")

    def ensure_edge(self, etype: str) -> None:
        self._ident(etype)
        if etype in self._edges:
            return
        self.command(f"CREATE EDGE TYPE {etype} IF NOT EXISTS")
        self.command(f"CREATE PROPERTY {etype}.ekey IF NOT EXISTS STRING")
        self.command(f"CREATE PROPERTY {etype}.from_key IF NOT EXISTS STRING")
        self.command(f"CREATE PROPERTY {etype}.to_key IF NOT EXISTS STRING")
        self.command(f"CREATE INDEX IF NOT EXISTS ON {etype} (ekey) UNIQUE")
        self._edges.add(etype)

    def upsert_bundle(self, bundle: GraphBundle) -> dict:
        self.upsert_vertices(bundle)
        self.upsert_edges(bundle)
        origins = {row["origin"] for row in bundle.exposure}
        for origin in origins:
            self.command(f"DELETE FROM Exposure WHERE origin = {lit(origin)}")
            rows = [row for row in bundle.exposure if row["origin"] == origin]
            self.script(
                [
                    "INSERT INTO Exposure SET " + ", ".join(f"{key} = {lit(value)}" for key, value in row.items())
                    for row in rows
                ]
            )
        return {"vertices": len(bundle.vertices), "edges": len(bundle.edges), "exposure": len(bundle.exposure)}

    def upsert_vertices(self, bundle: GraphBundle) -> None:
        statements = []
        for key, vertex in bundle.vertices.items():
            self._ident(vertex["type"])
            assignments = []
            for name, value in vertex["props"].items():
                if name == "key" or not IDENTIFIER.match(name):
                    continue
                assignments.append(f"{name} = {lit(value)}")
            if not assignments:
                assignments.append(f"label = {lit(key)}")
            statements.append(
                f"UPDATE {vertex['type']} SET {', '.join(assignments)} UPSERT WHERE key = {lit(key)}"
            )
        self.script(statements)

    def upsert_edges(self, bundle: GraphBundle) -> None:
        grouped: dict[str, list[dict]] = {}
        for edge in bundle.edges.values():
            grouped.setdefault(edge["type"], []).append(edge)
        creates: list[str] = []
        updates: list[str] = []
        for etype, edges in grouped.items():
            self.ensure_edge(etype)
            existing = {
                row.get("ekey")
                for row in self.command(f"SELECT ekey FROM {etype}", limit=100000)
                if row.get("ekey")
            }
            for edge in edges:
                ekey = f"{etype}|{edge['from_key']}|{edge['to_key']}"
                props = {name: value for name, value in edge["props"].items() if IDENTIFIER.match(name)}
                props["from_key"] = edge["from_key"]
                props["to_key"] = edge["to_key"]
                if ekey in existing:
                    assignments = ", ".join(f"{name} = {lit(value)}" for name, value in props.items())
                    updates.append(f"UPDATE {etype} SET {assignments} WHERE ekey = {lit(ekey)}")
                else:
                    props["ekey"] = ekey
                    sets = ", ".join(f"{name} = {lit(value)}" for name, value in props.items())
                    creates.append(
                        f"CREATE EDGE {etype} FROM (SELECT FROM {edge['from_type']} WHERE key = {lit(edge['from_key'])}) "
                        f"TO (SELECT FROM {edge['to_type']} WHERE key = {lit(edge['to_key'])}) SET {sets}"
                    )
        self.script(creates)
        self.script(updates)

    @staticmethod
    def _ident(name: str) -> None:
        if not IDENTIFIER.match(name):
            raise ArcadeError(f"unsafe identifier {name}")
