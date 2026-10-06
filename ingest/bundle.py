"""In-memory vertices and edges shared by every importer."""

from __future__ import annotations

TYPE_PREFIX = {
    "Ip": "ip",
    "Tag": "tag",
    "Cve": "cve",
    "Asn": "asn",
    "Organization": "org",
    "Country": "country",
    "Ja3": "ja3",
    "Kev": "kev",
    "Indicator": "indicator",
    "Event": "event",
    "Infrastructure": "infrastructure",
    "Malware": "malware",
    "Tool": "tool",
    "Identity": "identity",
    "AttackPattern": "attack",
    "StixObject": "stix",
    "Meta": "meta",
}

PREFIX_TYPE = {prefix: vtype for vtype, prefix in TYPE_PREFIX.items()}


class GraphBundle:
    def __init__(self) -> None:
        self.vertices: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}
        self.exposure: list[dict] = []
        self.meta: dict = {}

    def vertex(self, vtype: str, key: str, **props) -> str:
        if vtype not in TYPE_PREFIX:
            raise ValueError(f"unknown vertex type {vtype}")
        clean = {k: v for k, v in props.items() if v is not None and v != ""}
        current = self.vertices.get(key)
        if current is None:
            self.vertices[key] = {"type": vtype, "key": key, "props": clean}
        else:
            current["props"].update(clean)
        return key

    def edge(self, etype: str, from_key: str, to_key: str, **props) -> None:
        if from_key not in self.vertices or to_key not in self.vertices:
            return
        ekey = f"{etype}|{from_key}|{to_key}"
        clean = {k: v for k, v in props.items() if v is not None and v != ""}
        current = self.edges.get(ekey)
        if current is None:
            self.edges[ekey] = {
                "type": etype,
                "from_key": from_key,
                "to_key": to_key,
                "from_type": self.vertices[from_key]["type"],
                "to_type": self.vertices[to_key]["type"],
                "props": clean,
            }
        else:
            current["props"].update(clean)

    def expose(self, layer: str, country_code: str, country_name: str, origin: str) -> None:
        if not country_name and not country_code:
            return
        self.exposure.append(
            {
                "layer": layer,
                "country_code": country_code or "",
                "country_name": country_name or country_code,
                "origin": origin,
            }
        )

    def merge(self, other: "GraphBundle") -> None:
        for key, vertex in other.vertices.items():
            self.vertex(vertex["type"], key, **vertex["props"])
        for edge in other.edges.values():
            self.edge(edge["type"], edge["from_key"], edge["to_key"], **edge["props"])
        self.exposure.extend(other.exposure)
        self.meta.update(other.meta)
