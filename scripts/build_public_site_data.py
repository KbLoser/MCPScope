#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = ROOT.parent / "高危MCP工具候选清单.csv"
DEFAULT_CLASSIFIED = ROOT.parent / "高危MCP工具候选清单_142个MCP分类.csv"
DEFAULT_OUTPUT = ROOT / "site" / "data" / "public-summary.json"

SCOPE_LABELS = {
    "operation or impact evidence": "操作或影响证据",
    "invocation reachability only": "匿名调用可达",
    "authentication conflict in manual result": "认证结论待复核",
}

PRIMARY_LABELS = {
    "server-management capabilities": "服务管理与外部操作",
    "data leakage": "数据泄露",
    "remote code execution": "远程代码执行",
    "SQL/database access": "SQL 与数据库访问",
}

CASE_STUDIES = [
    {
        "id": "CASE-RCE-01",
        "category": "远程代码执行",
        "title": "匿名命令调用返回固定标记",
        "summary": "受控测试使用无害输出指令，服务返回成功状态与预期标记，证明远程命令能力可以在未建立业务身份的情况下触达。",
        "evidence": "操作结果",
    },
    {
        "id": "CASE-SQL-01",
        "category": "SQL 与数据库访问",
        "title": "常量查询获得预期结果",
        "summary": "测试仅使用不访问业务表的常量查询，响应与查询语义一致，表明数据库执行路径缺少必要的访问控制。",
        "evidence": "操作结果",
    },
    {
        "id": "CASE-LEAK-01",
        "category": "数据泄露",
        "title": "错误响应暴露内部连接信息",
        "summary": "工具后端在处理受控请求时返回内部数据库连接信息。公开案例仅保留证据类型，不包含地址、账号或连接字符串。",
        "evidence": "影响证据",
    },
    {
        "id": "CASE-OPS-01",
        "category": "服务管理与外部操作",
        "title": "匿名请求到达外部管理接口",
        "summary": "受控调用获得来自管理平面的真实响应，证明操作已经越过工具参数层并触达后端服务。测试未执行破坏性变更。",
        "evidence": "调用链证据",
    },
]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def split_risks(value: str) -> Iterable[str]:
    for item in value.replace("；", ";").split(";"):
        item = item.strip()
        if item:
            yield item


def count_items(values: Iterable[str], label_map: Dict[str, str] | None = None) -> List[Dict[str, Any]]:
    counts = Counter(values)
    return [
        {"label": (label_map or {}).get(label, label), "value": value}
        for label, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def service_outcomes(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["mcp_id"]].append(row)

    outcomes = Counter()
    for service_rows in grouped.values():
        statuses = {row["手动测试状态"] for row in service_rows}
        if any(row["是否已确认漏洞"] == "是" for row in service_rows):
            outcomes["证据支持的安全发现"] += 1
        elif statuses & {"已测试（未确认）", "已测试（功能禁用）", "已测试（参数格式）"}:
            outcomes["测试后未确认"] += 1
        elif "已测试（鉴权拦截）" in statuses:
            outcomes["鉴权拦截"] += 1
        elif "连接失败" in statuses:
            outcomes["目标不可达"] += 1
        else:
            outcomes["未完成测试"] += 1

    order = ["证据支持的安全发现", "鉴权拦截", "测试后未确认", "目标不可达", "未完成测试"]
    return [{"label": label, "value": outcomes[label]} for label in order if outcomes[label]]


def build_summary(candidates: List[Dict[str, str]], classified: List[Dict[str, str]]) -> Dict[str, Any]:
    services = {row["mcp_id"] for row in candidates}
    tool_names = {row["工具名称 (Tool Name)"] for row in candidates}
    operation_evidence = sum(
        row["evidence_scope"] == "operation or impact evidence" for row in classified
    )

    return {
        "schema_version": 1,
        "publication": {
            "label": "内部研究快照的脱敏汇总",
            "raw_targets_published": False,
        },
        "headline": {
            "services": len(services),
            "candidates": len(candidates),
            "unique_tools": len(tool_names),
            "findings": len(classified),
            "operation_evidence": operation_evidence,
        },
        "candidate_severity": count_items(row["候选风险等级"] for row in candidates),
        "candidate_risk_types": count_items(
            risk for row in candidates for risk in split_risks(row["高危风险类型"])
        ),
        "service_outcomes": service_outcomes(candidates),
        "finding_categories": count_items(
            (row["primary_category"] for row in classified), PRIMARY_LABELS
        ),
        "evidence_scopes": count_items(
            (row["evidence_scope"] for row in classified), SCOPE_LABELS
        ),
        "case_studies": CASE_STUDIES,
        "limitations": [
            "规则命中表示需要审查，不等同于漏洞成立。",
            "匿名获取工具列表不代表工具调用不需要认证。",
            "目标不可达不能被解释为目标安全。",
            "规则不命中仍可能来自命名、描述或覆盖不足。",
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
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--classified", type=Path, default=DEFAULT_CLASSIFIED)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = build_summary(read_csv(args.candidates), read_csv(args.classified))
    validate_public_summary(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote redacted public summary: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
