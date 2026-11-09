#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VULNERABILITIES = (
    ROOT.parent.parent
    / "获取工具列表"
    / "18_手动测试结果合并_2026-07-23"
    / "mcp619.csv"
)
DEFAULT_OUTPUT = ROOT / "site" / "data" / "public-summary.json"
DEFAULT_FALLBACK = ROOT / "site" / "data" / "public-summary.js"
DEFAULT_RECORDS = ROOT / "site" / "data" / "public-records.json"
DEFAULT_RECORDS_FALLBACK = ROOT / "site" / "data" / "public-records.js"
DEFAULT_GEOGRAPHY = (
    ROOT.parent.parent
    / "获取工具列表"
    / "18_手动测试结果合并_2026-07-23"
    / "619漏洞情况.csv"
)
DEFAULT_GEOGRAPHY_OUTPUT = ROOT / "site" / "data" / "public-geography.json"
DEFAULT_GEOGRAPHY_FALLBACK = ROOT / "site" / "data" / "public-geography.js"

SOURCE_LABELS = {
    "无认证扫描累计": "无认证扫描累计",
    "IP地址工具数据": "IP 地址工具数据",
    "未获取工具; Curl协议复测": "Curl 协议复测",
}

COUNTRY_ALIASES = {
    "The Netherlands": "Netherlands",
    "Hong Kong": "China",
    "Taiwan": "China",
}

COUNTRY_LABELS = {
    "United States": "美国",
    "Canada": "加拿大",
    "Germany": "德国",
    "China": "中国",
    "France": "法国",
    "India": "印度",
    "Japan": "日本",
    "Russia": "俄罗斯",
    "United Kingdom": "英国",
    "Netherlands": "荷兰",
    "Singapore": "新加坡",
    "South Korea": "韩国",
    "Ireland": "爱尔兰",
    "Finland": "芬兰",
    "Sweden": "瑞典",
    "Latvia": "拉脱维亚",
    "Brazil": "巴西",
    "Hungary": "匈牙利",
    "Switzerland": "瑞士",
    "Thailand": "泰国",
    "United Arab Emirates": "阿联酋",
    "Luxembourg": "卢森堡",
    "Belarus": "白俄罗斯",
    "Indonesia": "印度尼西亚",
    "Turkey": "土耳其",
    "Poland": "波兰",
    "Qatar": "卡塔尔",
    "Guinea": "几内亚",
    "New Zealand": "新西兰",
    "Belgium": "比利时",
    "Mexico": "墨西哥",
    "Czechia": "捷克",
    "Italy": "意大利",
    "Austria": "奥地利",
    "Bulgaria": "保加利亚",
    "Chile": "智利",
}

COUNTRY_IDS = {
    "United States": "840",
    "Canada": "124",
    "Germany": "276",
    "China": "156",
    "France": "250",
    "India": "356",
    "Japan": "392",
    "Russia": "643",
    "United Kingdom": "826",
    "Netherlands": "528",
    "Singapore": "702",
    "South Korea": "410",
    "Ireland": "372",
    "Finland": "246",
    "Sweden": "752",
    "Latvia": "428",
    "Brazil": "076",
    "Hungary": "348",
    "Switzerland": "756",
    "Thailand": "764",
    "United Arab Emirates": "784",
    "Luxembourg": "442",
    "Belarus": "112",
    "Indonesia": "360",
    "Turkey": "792",
    "Poland": "616",
    "Qatar": "634",
    "Guinea": "324",
    "New Zealand": "554",
    "Belgium": "056",
    "Mexico": "484",
    "Czechia": "203",
    "Italy": "380",
    "Austria": "040",
    "Bulgaria": "100",
    "Chile": "152",
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


def redact_tool_name(name: str) -> str:
    value = name.strip()
    if len(value) <= 2:
        return "*" * max(1, len(value))
    return f"{value[0]}***{value[-1]}"


def redact_target(row: Dict[str, str]) -> str:
    hostname = row.get("标准主机名", "").strip().strip("[]")
    if not hostname:
        raw_target = row.get("目标地址 (IP/URL)", "").strip()
        try:
            hostname = (urlsplit(raw_target if "://" in raw_target else f"//{raw_target}").hostname or "").strip()
        except ValueError:
            hostname = ""
    if not hostname:
        return "未提供"

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        labels = [label for label in hostname.rstrip(".").split(".") if label]
        if not labels:
            return "未提供"
        if len(labels) == 1:
            return redact_tool_name(labels[0])
        masked = [redact_tool_name(label) for label in labels[:-1]]
        suffix = labels[-1] if labels[-1].isalpha() and len(labels[-1]) <= 6 else redact_tool_name(labels[-1])
        return ".".join([*masked, suffix])

    if address.version == 4:
        return f"{str(address).split('.')[0]}.*.*.*"
    first_group = address.exploded.split(":", 1)[0]
    return f"{first_group}:****:****:****:****:****:****:****"


def build_public_records(vulnerabilities: List[Dict[str, str]]) -> Dict[str, Any]:
    records = []
    for index, row in enumerate(vulnerabilities, start=1):
        records.append(
            {
                "record_id": f"V-{index:04d}",
                "masked_tool_name": redact_tool_name(row.get("工具名称 (Tool Name)", "")),
                "masked_target": redact_target(row),
                "category": row.get("工具功能分类", "").strip(),
                "source": SOURCE_LABELS.get(row.get("数据来源", "").strip(), "其他来源"),
            }
        )
    return {
        "schema_version": 1,
        "publication": {
            "label": "619 条脱敏漏洞记录",
            "raw_targets_published": False,
            "raw_tool_names_published": False,
        },
        "records": records,
    }


def normalize_country(value: str) -> str:
    country = value.strip().split("/", 1)[0].strip() if value else ""
    if not country or country == "UN":
        return "未解析"
    return COUNTRY_ALIASES.get(country, country)


def build_public_geography(vulnerabilities: List[Dict[str, str]]) -> Dict[str, Any]:
    country_counts: Counter[str] = Counter()
    source_counts: Dict[str, Counter[str]] = {}
    for row in vulnerabilities:
        country = normalize_country(row.get("地区", ""))
        country_counts[country] += 1
        source = SOURCE_LABELS.get(row.get("数据来源", "").strip(), "其他来源")
        source_counts.setdefault(country, Counter())[source] += 1

    published = []
    for country, count in sorted(country_counts.items(), key=lambda item: (-item[1], item[0])):
        if country == "未解析":
            country_id = "unresolved"
            label = "未解析地区"
        else:
            country_id = COUNTRY_IDS.get(country, "")
            label = COUNTRY_LABELS.get(country, country)
        published.append(
            {
                "id": country_id,
                "label": label,
                "count": count,
                "source_counts": [
                    {"label": source, "value": value}
                    for source, value in sorted(source_counts[country].items(), key=lambda item: (-item[1], item[0]))
                ],
            }
        )

    return {
        "schema_version": 1,
        "publication": {
            "label": "国家级脱敏地理统计",
            "granularity": "国家或地区级",
            "exact_locations_published": False,
            "raw_addresses_published": False,
            "notes": "地区值按国家级聚合；中国香港、中国台湾归入中国，未解析值单列。",
        },
        "totals": {
            "records": sum(country_counts.values()),
            "countries": sum(1 for country in country_counts if country != "未解析"),
            "unresolved": country_counts.get("未解析", 0),
        },
        "countries": published,
    }


def validate_public_geography(document: Dict[str, Any]) -> None:
    serialized = json.dumps(document, ensure_ascii=False)
    if re.search(r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b|::", serialized):
        raise ValueError("public geography contains a network address")
    if document.get("publication", {}).get("exact_locations_published"):
        raise ValueError("public geography publishes exact locations")
    if any("city" in json.dumps(item, ensure_ascii=False).lower() for item in document.get("countries", [])):
        raise ValueError("public geography contains city-level data")


def validate_public_records(
    document: Dict[str, Any],
    raw_tool_names: Iterable[str] = (),
    raw_hostnames: Iterable[str] = (),
) -> None:
    serialized = json.dumps(document, ensure_ascii=False)
    if re.search(r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b", serialized):
        raise ValueError("public records contain a network address")
    if any(record.get("masked_tool_name", "").count("*") < 3 for record in document["records"]):
        raise ValueError("public records contain an insufficiently redacted tool name")
    forbidden_keys = {"mcp_id", "tool_id", "target", "hostname", "url", "raw_tool_name"}
    for record in document["records"]:
        if forbidden_keys.intersection(record):
            raise ValueError("public records contain an identifying field")
    masked_names = {record.get("masked_tool_name", "") for record in document["records"]}
    for raw_name in raw_tool_names:
        if raw_name and raw_name in masked_names:
            raise ValueError("public records contain a raw tool name")
    masked_targets = {record.get("masked_target", "") for record in document["records"]}
    for raw_hostname in raw_hostnames:
        if raw_hostname and raw_hostname in masked_targets:
            raise ValueError("public records contain a raw hostname")


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
    parser.add_argument("--geography", type=Path, default=DEFAULT_GEOGRAPHY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    vulnerabilities = read_csv(args.vulnerabilities)
    document = build_summary(vulnerabilities)
    records = build_public_records(vulnerabilities)
    geography_rows = read_csv(args.geography) if args.geography.exists() else vulnerabilities
    geography = build_public_geography(geography_rows)
    validate_public_summary(document)
    validate_public_records(
        records,
        (row.get("工具名称 (Tool Name)", "") for row in vulnerabilities),
        (row.get("标准主机名", "") for row in vulnerabilities),
    )
    validate_public_geography(geography)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(document, ensure_ascii=False, indent=2)
    args.output.write_text(serialized + "\n", encoding="utf-8")
    DEFAULT_FALLBACK.write_text(
        "window.MCPSCOPE_PUBLIC_SUMMARY = " + serialized + ";\n",
        encoding="utf-8",
    )
    records_serialized = json.dumps(records, ensure_ascii=False, indent=2)
    DEFAULT_RECORDS.write_text(records_serialized + "\n", encoding="utf-8")
    DEFAULT_RECORDS_FALLBACK.write_text(
        "window.MCPSCOPE_PUBLIC_RECORDS = " + records_serialized + ";\n",
        encoding="utf-8",
    )
    geography_serialized = json.dumps(geography, ensure_ascii=False, indent=2)
    DEFAULT_GEOGRAPHY_OUTPUT.write_text(geography_serialized + "\n", encoding="utf-8")
    DEFAULT_GEOGRAPHY_FALLBACK.write_text(
        "window.MCPSCOPE_PUBLIC_GEOGRAPHY = " + geography_serialized + ";\n",
        encoding="utf-8",
    )
    print(f"wrote redacted public summary: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
