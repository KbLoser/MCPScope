#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VULNERABILITIES = (
    ROOT.parent.parent
    / "获取工具列表"
    / "18_手动测试结果合并_2026-07-23"
    / "mcp619.csv"
)
DEFAULT_OUTPUT = ROOT / "site" / "data" / "public-summary.json"
DEFAULT_FALLBACK = ROOT / "site" / "data" / "public-summary.js"

SOURCE_LABELS = {
    "无认证扫描累计": "无认证扫描累计",
    "IP地址工具数据": "IP 地址工具数据",
    "未获取工具; Curl协议复测": "Curl 协议复测",
}

CASE_TEMPLATES = [
    (
        "CASE-STORAGE-01",
        "文件与内容存储",
        "文件与内容存储是最大类别",
        "最新记录中有 {count} 条工具被归入文件与内容存储。公开结果只保留能力分类，不公开目标、请求和响应。",
    ),
    (
        "CASE-COMMS-01",
        "通信与公开发布",
        "通信与公开发布是第二大类别",
        "有 {count} 条记录涉及消息、邮件或公开发布能力。该类别表示工具可以改变外部通信状态，不等于已经证明业务影响。",
    ),
    (
        "CASE-EXEC-01",
        "主机与代码执行",
        "主机与代码执行需要优先复核",
        "有 {count} 条记录被归入主机与代码执行。这是能力层面的高风险信号，实际可达性和影响仍需授权测试。",
    ),
    (
        "CASE-DATABASE-01",
        "数据库访问与操作",
        "数据库访问是稳定出现的高风险类别",
        "有 {count} 条记录涉及数据库访问与操作。结果仅展示统计与分类，不包含查询、连接信息或可复现载荷。",
    ),
]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def count_items(values: Iterable[str], label_map: Dict[str, str] | None = None) -> List[Dict[str, Any]]:
    counts = Counter(value.strip() for value in values if value and value.strip())
    return [
        {"label": (label_map or {}).get(label, label), "value": value}
        for label, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def build_cases(categories: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    counts = {item["label"]: item["value"] for item in categories}
    cases = []
    for case_id, category, title, summary in CASE_TEMPLATES:
        if category not in counts:
            continue
        cases.append(
            {
                "id": case_id,
                "category": category,
                "title": title,
                "summary": summary.format(count=counts[category]),
                "evidence": "能力分类记录",
            }
        )
    return cases


def build_summary(vulnerabilities: List[Dict[str, str]]) -> Dict[str, Any]:
    services = {row["mcp_id"].strip() for row in vulnerabilities if row.get("mcp_id", "").strip()}
    tool_names = {
        row["工具名称 (Tool Name)"].strip()
        for row in vulnerabilities
        if row.get("工具名称 (Tool Name)", "").strip()
    }
    categories = count_items(row.get("工具功能分类", "") for row in vulnerabilities)
    sources = count_items((row.get("数据来源", "") for row in vulnerabilities), SOURCE_LABELS)
    records = len(vulnerabilities)

    return {
        "schema_version": 2,
        "publication": {
            "label": "619 条漏洞记录的脱敏汇总",
            "raw_targets_published": False,
            "record_definition": "按最新 CSV 中的工具记录统计，不代表每条记录都已完成影响级别验证。",
        },
        "headline": {
            "services": len(services),
            "records": records,
            "unique_tools": len(tool_names),
            "findings": records,
            "categories": len(categories),
        },
        "candidate_risk_types": categories,
        "record_sources": sources,
        "finding_categories": categories,
        "case_studies": build_cases(categories),
        "limitations": [
            "619 条记录来自工具能力筛选与复测汇总，不等同于 619 条都已完成影响验证。",
            "筛选方式以工具名称或描述关键词为主，命名、描述和 Schema 覆盖不足会造成漏报。",
            "匿名获取工具列表不代表工具调用不需要认证，认证状态仍需在授权范围内单独核验。",
            "公开页面只展示聚合类别和来源，不发布目标地址、凭据、原始响应或可复现参数。",
        ],
    }


def validate_public_summary(document: Dict[str, Any]) -> None:
    serialized = json.dumps(document, ensure_ascii=False)
    forbidden_keys = {"url", "ip", "hostname", "target", "evidence_path", "raw_response"}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in forbidden_keys:
                    raise ValueError(f"public data contains forbidden field: {key}")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    checks = {
        "network address": r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "credential material": r"(?i)(?:password|passwd|api[_ -]?key|bearer)\s*[:=]",
        "private evidence path": r"测试/\d+_|SDK原始结果|测试证据\.json",
    }
    for label, pattern in checks.items():
        if re.search(pattern, serialized):
            raise ValueError(f"public data contains {label}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the redacted MCPScope website data file.")
    parser.add_argument("--vulnerabilities", type=Path, default=DEFAULT_VULNERABILITIES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = build_summary(read_csv(args.vulnerabilities))
    validate_public_summary(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(document, ensure_ascii=False, indent=2)
    args.output.write_text(serialized + "\n", encoding="utf-8")
    DEFAULT_FALLBACK.write_text(
        "window.MCPSCOPE_PUBLIC_SUMMARY = " + serialized + ";\n",
        encoding="utf-8",
    )
    print(f"wrote redacted public summary: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
