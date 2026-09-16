import re
from typing import Any, Dict, List


def _string_value(key: str, description: str, allowed_resources: List[str]) -> str:
    context = f"{key} {description}".lower()
    if re.search(r"(?:sql|query|statement)", context):
        return "SELECT 12345 AS audit_safe_probe;"
    if re.search(r"(?:command|cmd|script|code)", context):
        return "echo audit_safe_probe"
    if re.search(r"(?:url|uri|endpoint|webhook|callback)", context):
        return allowed_resources[0] if allowed_resources else "https://example.invalid/audit-safe-probe"
    if re.search(r"(?:email|recipient|to)", context):
        return "audit@example.invalid"
    if re.search(r"(?:phone|mobile|channel|username|handle)", context):
        return "audit-test-00000000"
    if re.search(r"(?:path|file|filename|directory|folder)", context):
        return "/tmp/mcp-audit/audit-safe-probe.txt"
    if re.search(r"(?:id|uuid|slug|resource|project|workspace|account|user|tenant)", context):
        return "audit-test-00000000"
    return "audit-safe-probe"


def value_for_schema(schema: Dict[str, Any], key: str, allowed_resources: List[str]) -> Any:
    if not isinstance(schema, dict):
        return "audit-safe-probe"
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "string")
    description = str(schema.get("description", ""))
    if schema_type == "object" or isinstance(schema.get("properties"), dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        keys = required if isinstance(required, list) else []
        return {
            child_key: value_for_schema(properties.get(child_key, {}), child_key, allowed_resources)
            for child_key in keys
            if child_key in properties
        }
    if schema_type == "array":
        return []
    if schema_type == "boolean":
        return False
    if schema_type in {"integer", "number"}:
        return 0
    if schema_type == "null":
        return None
    return _string_value(key, description, allowed_resources)


def build_plan(candidate: Dict[str, Any], allowed_resources: List[str]) -> Dict[str, Any]:
    tool = candidate["tool"]
    schema = tool.get("inputSchema") or tool.get("input_schema") or {"type": "object", "properties": {}}
    arguments = value_for_schema(schema, "arguments", allowed_resources)
    if not isinstance(arguments, dict):
        arguments = {}
    categories = "；".join(candidate.get("risk_categories", []))
    marker_categories = ("命令或代码执行", "任意SQL或数据库操作")
    markers = ["audit_safe_probe"] if any(item in categories for item in marker_categories) else []
    return {
        "arguments": arguments,
        "expected_success_markers": markers,
        "test_intent": f"使用合成参数验证 {tool.get('name', '')} 是否在未授权情况下到达高风险操作边界。",
        "success_criteria": "仅观察无害审计标记或针对明显虚假资源的业务校验结果，不访问或修改真实数据。",
        "safety_assessment": "参数由本地安全模板生成，仅包含审计标记、虚假标识符、零金额或允许的测试资源。",
        "safety_controls": [
            "single tool call",
            "synthetic identifiers only",
            "no real credentials or business data",
            "manual approval required",
        ],
        "requires_manual_approval": True,
    }
