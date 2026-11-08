#!/usr/bin/env python3
"""Convert a Natural Earth-derived TopoJSON file into a compact local SVG path asset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, List, Sequence, Tuple


WIDTH = 1200
HEIGHT = 520
ANTIMERIDIAN_GAP = WIDTH / 2


def decode_arcs(document: dict[str, Any]) -> list[list[tuple[float, float]]]:
    scale_x, scale_y = document["transform"]["scale"]
    translate_x, translate_y = document["transform"]["translate"]
    decoded: list[list[tuple[float, float]]] = []
    for arc in document["arcs"]:
        x = y = 0
        points = []
        for delta_x, delta_y in arc:
            x += delta_x
            y += delta_y
            longitude = x * scale_x + translate_x
            latitude = y * scale_y + translate_y
            projected_x = (longitude + 180) / 360 * WIDTH
            projected_y = (90 - latitude) / 180 * HEIGHT
            points.append((round(projected_x, 1), round(projected_y, 1)))
        decoded.append(points)
    return decoded


def join_ring(indices: Sequence[int], arcs: list[list[tuple[float, float]]]) -> str:
    points: list[tuple[float, float]] = []
    for index in indices:
        part = arcs[index] if index >= 0 else list(reversed(arcs[-index - 1]))
        if points and part and points[-1] == part[0]:
            points.extend(part[1:])
        else:
            points.extend(part)
    if not points:
        return ""

    # Split rings at the left/right map edge. Without this break, Russia,
    # Alaska and islands near 180 degrees are drawn as long diagonals across
    # the entire map.
    parts: list[list[tuple[float, float]]] = [[]]
    for point in points:
        if parts[-1] and abs(point[0] - parts[-1][-1][0]) > ANTIMERIDIAN_GAP:
            parts.append([])
        parts[-1].append(point)
    return "".join(
        "M" + " ".join(f"{x:g},{y:g}" for x, y in part) + "Z"
        for part in parts
        if part
    )


def geometry_path(geometry: dict[str, Any], arcs: list[list[tuple[float, float]]]) -> str:
    geometry_type = geometry.get("type")
    if geometry_type == "Polygon":
        return "".join(join_ring(ring, arcs) for ring in geometry.get("arcs", []))
    if geometry_type == "MultiPolygon":
        return "".join(join_ring(ring, arcs) for polygon in geometry.get("arcs", []) for ring in polygon)
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the local country map asset.")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    document = json.loads(args.source.read_text(encoding="utf-8"))
    arcs = decode_arcs(document)
    geometries = document["objects"]["countries"]["geometries"]
    countries_by_id: dict[str, dict[str, str]] = {}
    for geometry in geometries:
        path = geometry_path(geometry, arcs)
        if not path:
            continue
        country_id = str(geometry.get("id", ""))
        country = {
            "id": country_id,
            "name": geometry.get("properties", {}).get("name", ""),
            "path": path,
        }
        countries_by_id[country_id] = country

    # Keep the public map aligned with the site's country-level China
    # aggregation instead of rendering a separate Taiwan data layer.
    if "158" in countries_by_id and "156" in countries_by_id:
        countries_by_id["156"]["path"] += countries_by_id["158"]["path"]
        del countries_by_id["158"]

    countries = list(countries_by_id.values())

    land_path = "".join(country["path"] for country in countries)
    payload = {
        "schema_version": 1,
        "width": WIDTH,
        "height": HEIGHT,
        "land_path": land_path,
        "countries": countries,
        "source": "world-atlas countries-110m / Natural Earth",
    }
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("window.MCPSCOPE_WORLD_MAP = " + serialized + ";\n", encoding="utf-8")
    print(f"wrote {len(countries)} country paths to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
