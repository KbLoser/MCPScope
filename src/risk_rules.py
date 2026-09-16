from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit


RISK_TIERS = ("严重", "高", "中", "低", "信息")
RISK_ORDER = {name: index for index, name in enumerate(RISK_TIERS)}
RISK_BASE = {"严重": 80, "高": 60, "中": 40, "低": 20, "信息": 0}
SEVERITY_ORDER = {"中": 0, "高": 1, "严重": 2}

RULES = [
    ("命令或代码执行", "严重", r"\b(?:run|execute|exec|eval|evaluate|spawn)\b.{0,40}\b(?:shell|bash|powershell|terminal|command|code|script|python|process)\b|\b(?:os\.system|subprocess|popen)\b"),
    ("文件系统写入或破坏", "高", r"\b(?:write|edit|modify|delete|remove|upload|move|rename|overwrite)\b.{0,40}\b(?:file|folder|directory|path|filesystem|blob)\b"),
    ("文件系统读取", "中", r"\b(?:read|get|list|search|download|grep)\b.{0,40}\b(?:file|folder|directory|path|filesystem|blob)\b"),
    ("任意SQL或数据库操作", "严重", r"\b(?:execute|exec|run|raw|mysql|postgres|postgresql|database|db)\b.{0,40}\b(?:sql|query)\b|\braw\s+sql\b"),
    ("任意网络请求/SSRF", "高", r"\b(?:fetch|request|visit|navigate|crawl|scrape|proxy|download|curl)\b.{0,80}\b(?:url|uri|webpage|website|endpoint|http)\b"),
    ("凭证或敏感配置访问", "严重", r"\b(?:get|read|list|export|retrieve|fetch|reveal|rotate)\b.{0,40}\b(?:secret|credential|password|private\s+key|api\s+key|access\s+token|environment\s+variable)\b"),
    ("账号、权限或安全策略变更", "高", r"\b(?:create|delete|remove|disable|enable|assign|grant|revoke|invite|promote|reset)\b.{0,40}\b(?:user|account|member|admin|role|permission|policy|access)\b"),
    ("基础设施或运行环境变更", "严重", r"\b(?:deploy|restart|reboot|shutdown|stop|terminate|destroy|provision|scale|rollback|kubectl)\b.{0,50}\b(?:server|instance|container|cluster|deployment|service|vm|pod|function|infrastructure)?\b"),
    ("资金、支付或交易操作", "严重", r"\b(?:capture|charge|create|execute|make|send|refund|withdraw|transfer|swap|trade|pay|place)\b.{0,40}\b(?:payment|charge|refund|withdrawal|transfer|transaction|money|funds|crypto|checkout|trade|swap|order)\b"),
    ("外部消息、邮件或公开发布", "高", r"\b(?:send|reply|publish|schedule|broadcast|post)\b.{0,30}\b(?:email|mail|message|sms|tweet|post|notification|slack)\b"),
    ("删除、撤销或不可逆操作", "高", r"\b(?:delete|remove|destroy|drop|purge|terminate|revoke|wipe|erase)\b.{0,40}\b(?:resource|account|project|database|table|workflow|repository|customer|data|site)\b"),
    ("工作流执行或软件安装", "高", r"\b(?:trigger|run|execute|install|uninstall)\b.{0,40}\b(?:workflow|automation|job|pipeline|package|plugin|extension|dependency|software)\b"),
]

PARAM_RISK = {
    "command": "严重", "cmd": "严重", "shell": "严重", "exec": "严重",
    "code": "高", "script": "高", "payload": "高", "expression": "高", "sql": "高",
    "path": "中", "filename": "中", "filepath": "中", "file_path": "中", "url": "中", "uri": "中",
}

CLUSTER_RULES = [
    ({"命令或代码执行", "任意网络请求/SSRF"}, "严重", "代码执行与网络访问组合", "exec+network"),
    ({"命令或代码执行", "外部消息、邮件或公开发布"}, "严重", "代码执行与外部消息组合", "exec+messaging"),
    ({"文件系统读取", "任意网络请求/SSRF"}, "严重", "文件读取与网络访问组合", "read+network"),
    ({"文件系统读取", "外部消息、邮件或公开发布"}, "严重", "文件读取与外部消息组合", "read+messaging"),
    ({"文件系统读取", "文件系统写入或破坏"}, "高", "完整文件系统能力组合", "full-filesystem"),
]

SENSITIVE_RESOURCE_SCHEMES = {"file", "postgres", "postgresql", "mysql", "redis", "mongodb", "sqlite", "s3", "gcs"}
INSTRUCTION_INJECTION = ("ignore previous", "disregard instructions", "system prompt", "you are now", "forget your", "jailbreak")


def normalize(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", " ", text).strip().lower()


def _walk_schema(value: Any, path: str = "") -> Iterable[tuple[str, Dict[str, Any]]]:
    if not isinstance(value, dict):
        return
    properties = value.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            child_path = f"{path}.{name}" if path else name
            yield child_path, child if isinstance(child, dict) else {}
            if isinstance(child, dict) and "$ref" not in child:
                yield from _walk_schema(child, child_path)
    for key in ("items", "allOf", "anyOf", "oneOf"):
        child = value.get(key)
        for item in child if isinstance(child, list) else [child]:
            if isinstance(item, dict) and "$ref" not in item:
                yield from _walk_schema(item, path)


def schema_text(schema: Any) -> str:
    parts = []
    for path, value in _walk_schema(schema):
        parts.extend((path, str(value.get("title", "")), str(value.get("description", ""))))
    return normalize(" ".join(parts))


def _worse(first: str, second: str) -> str:
    return first if RISK_ORDER.get(first, 99) <= RISK_ORDER.get(second, 99) else second


def classify_tool(tool: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw_name = str(tool.get("name", ""))
    raw_description = str(tool.get("description", ""))
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    sources = (("工具名称", normalize(raw_name), raw_name), ("工具描述", normalize(raw_description), raw_description[:240]), ("参数格式", schema_text(schema), json.dumps(schema, ensure_ascii=False)[:240]))
    matches = []
    for category, severity, pattern in RULES:
        for source, searchable, evidence in sources:
            if re.search(pattern, searchable, re.I):
                matches.append({"category": category, "severity": severity, "source": source, "evidence": evidence})
                break

    dangerous_parameters = []
    for path, definition in _walk_schema(schema):
        name = normalize(path.rsplit(".", 1)[-1]).replace(" ", "_")
        configured = PARAM_RISK.get(name)
        if not configured:
            continue
        unconstrained = definition.get("type") == "string" and not any(key in definition for key in ("enum", "pattern", "format", "maxLength"))
        tier = "严重" if configured == "高" and unconstrained else configured
        dangerous_parameters.append(path)
        matches.append({"category": "危险输入参数", "severity": tier, "source": "参数格式", "evidence": path})

    if not matches:
        return None
    severity = min((item["severity"] for item in matches), key=lambda value: RISK_ORDER[value])
    categories = list(dict.fromkeys(item["category"] for item in matches if item["category"] != "危险输入参数"))
    return {
        "risk_level": severity,
        "risk_categories": categories,
        "confidence": "高" if any(item["source"] == "工具名称" for item in matches) else "中",
        "evidence": [f'{item["source"]}: {item["evidence"]}' for item in matches],
        "dangerous_parameters": dangerous_parameters,
    }


def shortlist(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = []
    for tool in tools:
        assessment = classify_tool(tool)
        if assessment:
            candidates.append({**assessment, "tool": tool})
    candidates.sort(key=lambda item: (RISK_ORDER[item["risk_level"]], normalize(item["tool"].get("name", ""))))
    for index, candidate in enumerate(candidates, start=1):
        candidate["candidate_id"] = index
    return candidates


def assess_server(result: Dict[str, Any], auth_state: str, platform: str = "unknown", persistence_runs: int = 1) -> Dict[str, Any]:
    tools = result.get("tools", []) if isinstance(result.get("tools"), list) else []
    candidates = shortlist(tools)
    tier = "信息" if not tools else "低"
    reasons: List[str] = []
    for item in candidates:
        tier = _worse(tier, item["risk_level"])
    categories = {category for item in candidates for category in item.get("risk_categories", [])}
    clusters = []
    for required, cluster_tier, reason, key in CLUSTER_RULES:
        if required <= categories:
            tier = _worse(tier, cluster_tier)
            reasons.append(reason)
            clusters.append(key)

    capabilities = result.get("serverCapabilities") or {}
    if "sampling" in capabilities:
        tier = _worse(tier, "高")
        reasons.append("服务声明 sampling 能力")
        if "文件系统读取" in categories:
            tier = "严重"
            reasons.append("sampling 与文件读取形成自主外传能力")
    if "roots" in capabilities:
        tier = _worse(tier, "中")
        reasons.append("服务声明 roots 文件系统能力")

    for resource in result.get("resources", []) if isinstance(result.get("resources"), list) else []:
        uri = str(resource.get("uri", "")) if isinstance(resource, dict) else ""
        parsed = urlsplit(uri)
        if parsed.scheme.lower() in SENSITIVE_RESOURCE_SCHEMES:
            tier = _worse(tier, "严重" if parsed.username or parsed.password else "高")
            reasons.append(f"敏感资源 URI: {parsed.scheme}://")

    instructions = str(result.get("serverInstructions") or "")
    lowered = instructions.lower()
    if any(marker in lowered for marker in INSTRUCTION_INJECTION):
        tier = "严重"
        reasons.append("服务指令包含提示注入特征")
    if re.search(r"\b(?:password|api[_ -]?key|secret|token|credential)\s*[=:]\s*\S+", lowered):
        tier = _worse(tier, "高")
        reasons.append("服务指令可能包含凭据")

    if len(tools) >= 50:
        tier = _worse(tier, "高")
        reasons.append(f"工具面较宽，共 {len(tools)} 个工具")
    server_name = normalize((result.get("serverInfo") or {}).get("name", ""))
    if any(marker in server_name for marker in ("computer use", "code interpreter", "terminal", "sandbox", "operator")):
        tier = _worse(tier, "高")
        reasons.append("服务名称表明高权限交互能力")

    if auth_state == "none":
        reasons.insert(0, "无需认证即可读取 MCP 元数据")
        if tier == "高":
            tier = "严重"
        elif tier == "中":
            tier = "高"
        elif tier == "信息":
            tier = "低"
    if categories:
        reasons.append("高风险能力: " + "、".join(sorted(categories)))

    score = RISK_BASE[tier]
    if auth_state == "none" and tier in {"严重", "高"}:
        score += 15
    if "命令或代码执行" in categories:
        score += 5
    if platform in {"railway", "fly.io", "huggingface", "vercel"}:
        score += 3
    if persistence_runs > 1:
        score += min(20, (persistence_runs - 1) * 10)
    return {
        "risk_level": tier,
        "priority_score": min(100, score),
        "risk_reasons": list(dict.fromkeys(reasons)),
        "high_risk_candidates": candidates,
        "capability_clusters": clusters,
    }
