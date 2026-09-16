from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit


RISK_ORDER = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4}


def selected_records(document: Dict[str, Any], minimum: str = "信息") -> List[Dict[str, Any]]:
    threshold = RISK_ORDER.get(minimum, 4)
    records = [
        record for record in document.get("records", [])
        if record.get("confirmed_mcp") and RISK_ORDER.get(str(record.get("risk_level")), 4) <= threshold
    ]
    return sorted(records, key=lambda record: (RISK_ORDER.get(str(record.get("risk_level")), 4), -int(record.get("priority_score", 0))))


def corvus_yaml(document: Dict[str, Any], minimum: str = "信息", include_waf: bool = False, source: str = "") -> str:
    lines = ["targets:"]
    for record in selected_records(document, minimum):
        if source and source not in record.get("sources", []):
            continue
        if record.get("behind_cloudflare") and not include_waf:
            continue
        if record.get("transport") not in {"streamable-http", "websocket"}:
            continue
        lines.extend([
            f"  - name: {json.dumps(urlsplit(record['url']).netloc.replace('.', '-'))}",
            f"    transport: {json.dumps('websocket' if record.get('transport') == 'websocket' else 'http')}",
            f"    url: {json.dumps(record.get('endpoint') or record['url'])}",
            f"    risk_level: {json.dumps(record.get('risk_level', '信息'), ensure_ascii=False)}",
            f"    priority_score: {int(record.get('priority_score', 0))}",
        ])
    return "\n".join(lines) + "\n"


def condor_targets(document: Dict[str, Any], minimum_score: int = 50) -> str:
    markers = ("flowise", "langflow", "dify", "n8n", "autogen", "langchain", "llamaflow")
    lines = []
    for record in document.get("records", []):
        identity = f"{record.get('url', '')} {(record.get('server_info') or {}).get('name', '')}".lower()
        platform = next((marker for marker in markers if marker in identity), None)
        if platform and int(record.get("priority_score", 0)) >= minimum_score:
            lines.append(f"{record['url']} {platform if platform in {'flowise', 'langflow', 'dify', 'autogen'} else 'generic'}")
    return "\n".join(lines) + ("\n" if lines else "")


def shrike_yaml(document: Dict[str, Any], minimum_score: int = 50, source: str = "") -> str:
    lines = ["targets:"]
    for record in document.get("records", []):
        if not record.get("confirmed_mcp"):
            continue
        if source and source not in record.get("sources", []):
            continue
        priority = int(record.get("priority_score", 0))
        if priority < minimum_score and not (record.get("auth_state") == "none" and record.get("risk_level") in {"严重", "高"}):
            continue
        lines.extend([
            f"  - url: {json.dumps(record['url'])}",
            "    source: mcp-one",
            f"    priority_score: {priority}",
            f"    auth: {json.dumps(record.get('auth_state', 'unknown'))}",
            f"    tools_count: {int(record.get('tool_count', 0))}",
        ])
    return "\n".join(lines) + "\n"


def ibis_candidates(document: Dict[str, Any], database: Path | None = None) -> List[Dict[str, Any]]:
    known = set()
    if database and database.exists():
        try:
            with sqlite3.connect(database) as connection:
                known.update(str(row[0]).lower() for row in connection.execute("SELECT package FROM advisories") if row[0])
        except sqlite3.Error:
            pass
    values = []
    for record in selected_records(document, "高"):
        categories = {category for candidate in record.get("high_risk_candidates", []) for category in candidate.get("risk_categories", [])}
        if record.get("auth_state") != "none" and "命令或代码执行" not in categories:
            continue
        package = (urlsplit(record["url"]).hostname or record["url"]).lower()
        if package in known:
            continue
        values.append({"url": record["url"], "package": package, "severity": "critical" if record.get("risk_level") == "严重" else "high"})
        known.add(package)
    return values


def submit_ibis(candidates: List[Dict[str, Any]], executable: str) -> List[Dict[str, Any]]:
    results = []
    for candidate in candidates:
        completed = subprocess.run(
            [executable, "add", "--package", candidate["package"], "--severity", candidate["severity"], "--source", "manual", "--no-npm"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        identifier = re.search(r"MANUAL-[a-fA-F0-9]+", completed.stdout)
        results.append({**candidate, "returncode": completed.returncode, "advisory": identifier.group(0) if identifier else None, "stderr": completed.stderr[:500]})
    return results


def emit_events(document: Dict[str, Any], output_file: str) -> int:
    try:
        from cobalt_hub_client import emit  # type: ignore[import-not-found]
    except ImportError:
        return 0
    emitted = 0
    for record in selected_records(document, "高"):
        try:
            emit("mcp_audit.server.high_risk", {"url": record["url"], "risk_level": record.get("risk_level"), "priority_score": record.get("priority_score"), "output_file": output_file}, "mcp-audit-one-click")
            emitted += 1
        except Exception:
            continue
    return emitted
