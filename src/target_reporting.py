#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


RISK_ORDER = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4, "未发现高风险工具": 4}


def load_scan(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"JSONL records must be objects: {path}:{line_number}")
            records.append(record)
        return {"records": records}
    if isinstance(document, list):
        return {"records": document}
    if not isinstance(document, dict) or not isinstance(document.get("records"), list):
        raise ValueError(f"scan document must contain a records array: {path}")
    return document


def summarize_scan(document: Dict[str, Any]) -> Dict[str, Any]:
    records = document.get("records", [])
    confirmed = [record for record in records if record.get("confirmed_mcp")]
    tool_counts: Counter[str] = Counter()
    for record in confirmed:
        for tool in record.get("tools", []):
            if isinstance(tool, dict) and tool.get("name"):
                tool_counts[str(tool["name"])] += 1
    return {
        "scanned_target_count": len(records),
        "confirmed_mcp_count": len(confirmed),
        "high_risk_target_count": sum(bool(record.get("high_risk_candidates")) for record in confirmed),
        "risk_distribution": dict(Counter(str(record.get("risk_level", "unknown")) for record in confirmed)),
        "auth_distribution": dict(Counter(str(record.get("auth_state", "unknown")) for record in confirmed)),
        "transport_distribution": dict(Counter(str(record.get("transport", "unknown")) for record in confirmed)),
        "platform_distribution": dict(Counter(str(record.get("platform", "unknown")) for record in confirmed)),
        "source_distribution": dict(Counter(source for record in confirmed for source in record.get("sources", []))),
        "cloudflare_count": sum(bool(record.get("behind_cloudflare")) for record in confirmed),
        "schema_complete_count": sum(
            bool(record.get("tools")) and any(
                isinstance(tool, dict) and bool(tool.get("inputSchema") or tool.get("input_schema"))
                for tool in record.get("tools", [])
            )
            for record in confirmed
        ),
        "tool_count_distribution": dict(Counter(
            "0" if int(record.get("tool_count", 0)) == 0 else
            "1-5" if int(record.get("tool_count", 0)) <= 5 else
            "6-20" if int(record.get("tool_count", 0)) <= 20 else
            "21-50" if int(record.get("tool_count", 0)) <= 50 else "50+"
            for record in confirmed
        )),
        "top_tools": [{"name": name, "count": count} for name, count in tool_counts.most_common(20)],
    }


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def markdown_report(document: Dict[str, Any]) -> str:
    summary = summarize_scan(document)
    confirmed = [record for record in document.get("records", []) if record.get("confirmed_mcp")]
    confirmed.sort(key=lambda record: (RISK_ORDER.get(str(record.get("risk_level")), 99), -int(record.get("priority_score", 0))))
    lines = [
        "# MCP Target Fingerprint Report",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Scanned targets | {summary['scanned_target_count']} |",
        f"| Confirmed MCP | {summary['confirmed_mcp_count']} |",
        f"| High-risk targets | {summary['high_risk_target_count']} |",
        "",
        "## Confirmed Servers",
        "",
        "| URL | Risk | Score | Auth | Transport | Platform | Tools |",
        "| --- | --- | ---: | --- | --- | --- | ---: |",
    ]
    for record in confirmed:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(record.get("url")),
                    _cell(record.get("risk_level")),
                    _cell(record.get("priority_score", 0)),
                    _cell(record.get("auth_state")),
                    _cell(record.get("transport")),
                    _cell(record.get("platform") or "unknown"),
                    _cell(record.get("tool_count", 0)),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Top Tools", "", "| Tool | Servers |", "| --- | ---: |"])
    for item in summary["top_tools"]:
        lines.append(f"| {_cell(item['name'])} | {item['count']} |")
    return "\n".join(lines) + "\n"


def compare_scans(old_document: Dict[str, Any], new_document: Dict[str, Any]) -> Dict[str, Any]:
    old_map = {record["url"]: record for record in old_document.get("records", []) if record.get("confirmed_mcp")}
    new_map = {record["url"]: record for record in new_document.get("records", []) if record.get("confirmed_mcp")}
    new_targets = sorted(set(new_map) - set(old_map))
    disappeared = sorted(set(old_map) - set(new_map))
    risk_changes = []
    tool_changes = []
    for url in sorted(set(old_map) & set(new_map)):
        old_record = old_map[url]
        new_record = new_map[url]
        old_risk = old_record.get("risk_level")
        new_risk = new_record.get("risk_level")
        if old_risk != new_risk:
            risk_changes.append({"url": url, "old": old_risk, "new": new_risk})
        old_tools = {tool.get("name") for tool in old_record.get("tools", []) if isinstance(tool, dict) and tool.get("name")}
        new_tools = {tool.get("name") for tool in new_record.get("tools", []) if isinstance(tool, dict) and tool.get("name")}
        added = sorted(new_tools - old_tools)
        removed = sorted(old_tools - new_tools)
        if added or removed:
            tool_changes.append({"url": url, "added": added, "removed": removed})
    return {
        "old_confirmed_count": len(old_map),
        "new_confirmed_count": len(new_map),
        "new_targets": new_targets,
        "disappeared_targets": disappeared,
        "risk_changes": risk_changes,
        "tool_changes": tool_changes,
    }
