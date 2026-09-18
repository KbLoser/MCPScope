from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


SARIF_LEVEL = {"严重": "error", "高": "error", "中": "warning", "低": "note", "信息": "none"}
SARIF_RANK = {"严重": 100.0, "高": 75.0, "中": 50.0, "低": 25.0, "信息": 0.0}


def to_sarif(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules = []
    seen = set()
    results = []
    for record in records:
        tier = str(record.get("risk_level", "信息"))
        rule_id = f"MCPSCOPE-{tier}"
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({"id": rule_id, "name": f"MCP{tier}Risk", "shortDescription": {"text": f"{tier}风险 MCP 服务"}, "defaultConfiguration": {"level": SARIF_LEVEL.get(tier, "none")}})
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(tier, "none"),
            "rank": SARIF_RANK.get(tier, 0.0),
            "message": {"text": "; ".join(record.get("risk_reasons", [])) or f"MCP 服务风险等级：{tier}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": record.get("url", "")}}}],
            "properties": {"auth": record.get("auth_state"), "transport": record.get("transport"), "priority_score": record.get("priority_score", 0)},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "MCPScope", "rules": rules}}, "results": results}]}


def to_csv(records: Iterable[Dict[str, Any]]) -> str:
    buffer = io.StringIO()
    fields = ("url", "risk_level", "priority_score", "auth_state", "transport", "platform", "tool_count", "tool_name_hash")
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    for record in records:
        writer.writerow({field: record.get(field, "") for field in fields})
    return buffer.getvalue()


def to_html(records: List[Dict[str, Any]], title: str = "MCPScope Report") -> str:
    rows = []
    for record in records:
        reasons = "<br>".join(html.escape(str(item)) for item in record.get("risk_reasons", []))
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (record.get("risk_level", ""), record.get("priority_score", 0), record.get("url", ""), record.get("auth_state", ""), record.get("transport", ""), record.get("tool_count", 0))) + f"<td>{reasons}</td></tr>")
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>body{{font:14px system-ui;margin:32px;color:#202124}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #dadce0;padding:8px;text-align:left;vertical-align:top}}th{{background:#f1f3f4}}</style></head><body><h1>{html.escape(title)}</h1><p>确认 MCP 服务：{len(records)}</p><table><thead><tr><th>风险</th><th>分数</th><th>URL</th><th>认证</th><th>传输</th><th>工具</th><th>原因</th></tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"""


def write_reports(document: Dict[str, Any], output_dir: Path, stem: str, formats: Iterable[str], markdown: str) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    records = [record for record in document.get("records", []) if record.get("confirmed_mcp")]
    written: Dict[str, str] = {}
    for kind in formats:
        if kind == "json":
            content, suffix = json.dumps(document, ensure_ascii=False, indent=2) + "\n", ".json"
        elif kind == "jsonl":
            content, suffix = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), ".jsonl"
        elif kind == "sarif":
            content, suffix = json.dumps(to_sarif(records), ensure_ascii=False, indent=2) + "\n", ".sarif"
        elif kind == "html":
            content, suffix = to_html(records), ".html"
        elif kind == "csv":
            content, suffix = to_csv(records), ".csv"
        elif kind == "markdown":
            content, suffix = markdown, ".md"
        else:
            raise ValueError(f"unsupported report format: {kind}")
        path = output_dir / f"{stem}{suffix}"
        path.write_text(content, encoding="utf-8")
        written[kind] = str(path)
    return written
