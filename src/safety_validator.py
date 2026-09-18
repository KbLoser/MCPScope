#!/usr/bin/env python3
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from llm_payload_planner import AuditPlan, ToolMetadata


AUDIT_MARKER_PATTERN = re.compile(
    r"(?:audit|test|dummy|fake|sandbox|safe.?probe|example|00000000|9999)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[A-Z0-9]{16}\b)",
    re.IGNORECASE,
)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|credential|api.?key|access.?token|auth.?token|private.?key)",
    re.IGNORECASE,
)
IDENTIFIER_KEY_PATTERN = re.compile(
    r"(?:^|[_-])(?:id|uuid|slug|resource|project|workspace|account|user|tenant|zone|record|app)(?:$|[_-])",
    re.IGNORECASE,
)
URL_KEY_PATTERN = re.compile(r"(?:url|uri|endpoint|webhook|callback)", re.IGNORECASE)
PATH_KEY_PATTERN = re.compile(r"(?:path|file|filename|directory|folder)", re.IGNORECASE)
COMMAND_KEY_PATTERN = re.compile(r"(?:command|cmd|script|code)", re.IGNORECASE)
RECIPIENT_KEY_PATTERN = re.compile(
    r"(?:email|recipient|to|phone|mobile|channel|username|handle)", re.IGNORECASE
)


@dataclass
class ValidationReport:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not self.errors

    def require_safe(self) -> None:
        if self.errors:
            raise SafetyValidationError("\n".join(self.errors))


class SafetyValidationError(ValueError):
    pass


def json_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def resolve_local_ref(root_schema: Dict[str, Any], reference: str) -> Optional[Dict[str, Any]]:
    if not reference.startswith("#/"):
        return None
    current: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current if isinstance(current, dict) else None


def validate_json_schema(
    value: Any,
    schema: Dict[str, Any],
    path: str = "arguments",
    root_schema: Optional[Dict[str, Any]] = None,
) -> List[str]:
    if not isinstance(schema, dict) or not schema:
        return []
    if root_schema is None:
        root_schema = schema

    if "$ref" in schema:
        resolved = resolve_local_ref(root_schema, str(schema["$ref"]))
        if resolved is None:
            return [f"{path}: unresolved or non-local $ref: {schema['$ref']}"]
        return validate_json_schema(value, resolved, path, root_schema)

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        errors = []
        for branch in all_of:
            errors.extend(validate_json_schema(value, branch, path, root_schema))
        if errors:
            return errors

    for union_key in ("anyOf", "oneOf"):
        branches = schema.get(union_key)
        if isinstance(branches, list):
            branch_errors = [validate_json_schema(value, branch, path, root_schema) for branch in branches]
            if any(not errors for errors in branch_errors):
                return []
            return [f"{path}: value does not match any {union_key} branch"]

    if value is None and schema.get("nullable") is True:
        return []

    expected = schema.get("type")
    expected_types = expected if isinstance(expected, list) else [expected] if expected else []
    if expected_types and not any(json_type_matches(value, item) for item in expected_types):
        return [f"{path}: expected {expected_types}, got {type(value).__name__}"]

    errors = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: value does not match const")
    if isinstance(schema.get("enum"), list) and value not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{path}.{key}: required field is missing")
        if isinstance(properties, dict):
            for key, child in value.items():
                if key in properties:
                    errors.extend(validate_json_schema(child, properties[key], f"{path}.{key}", root_schema))
                elif schema.get("additionalProperties") is False:
                    errors.append(f"{path}.{key}: additional property is not allowed")

    if isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, child in enumerate(value):
                errors.extend(validate_json_schema(child, item_schema, f"{path}[{index}]", root_schema))

    if isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                if not re.search(pattern, value):
                    errors.append(f"{path}: does not match schema pattern")
            except re.error:
                errors.append(f"{path}: schema contains an invalid regex pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")
        if isinstance(schema.get("exclusiveMinimum"), (int, float)) and value <= schema["exclusiveMinimum"]:
            errors.append(f"{path}: not above exclusiveMinimum")
        if isinstance(schema.get("exclusiveMaximum"), (int, float)) and value >= schema["exclusiveMaximum"]:
            errors.append(f"{path}: not below exclusiveMaximum")
    return errors


def walk_values(value: Any, path: str = "arguments") -> Iterable[Tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, str(key), child
            yield from walk_values(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_values(child, f"{path}[{index}]")


def is_synthetic_identifier(value: Any) -> bool:
    if isinstance(value, int) and not isinstance(value, bool):
        return value in {0, 9999, 99999, 999999, 999999999}
    if isinstance(value, str):
        return bool(AUDIT_MARKER_PATTERN.search(value))
    return False


def is_allowed_url(value: str, allowed_resources: List[str]) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    allowed = list(allowed_resources) + ["https://example.invalid/audit-safe-probe"]
    for resource in allowed:
        resource_parsed = urlparse(resource)
        if (
            parsed.scheme == resource_parsed.scheme
            and parsed.hostname == resource_parsed.hostname
            and parsed.port == resource_parsed.port
            and parsed.path.startswith(resource_parsed.path or "/")
        ):
            return True
    return False


def validate_sql(path: str, value: str, report: ValidationReport) -> None:
    normalized = re.sub(r"\s+", " ", value).strip()
    safe_select = re.fullmatch(
        r"SELECT\s+(?:-?\d+(?:\.\d+)?|'[A-Za-z0-9 _-]{1,80}')"
        r"(?:\s+AS\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;?",
        normalized,
        re.IGNORECASE,
    )
    if not safe_select:
        report.errors.append(
            f"{path}: SQL must be a single SELECT of a literal constant and must not reference data objects"
        )


def validate_soql(path: str, value: str, report: ValidationReport) -> None:
    normalized = re.sub(r"\s+", " ", value).strip()
    safe = re.fullmatch(
        r"SELECT Id FROM (?:Account|Contact|Opportunity) WHERE Id = "
        r"'(?=[A-Za-z0-9_-]{15,40}')(?:[A-Za-z0-9_-]*)(?:000|999|audit|test)(?:[A-Za-z0-9_-]*)' LIMIT 1",
        normalized,
        re.IGNORECASE,
    )
    if not safe:
        report.errors.append(f"{path}: SOQL must target one conspicuously synthetic object ID with LIMIT 1")


def validate_command(path: str, value: str, report: ValidationReport) -> None:
    normalized = value.strip()
    safe = (
        re.fullmatch(r"(?:echo|printf)\s+['\"]?[A-Za-z0-9_-]*audit[A-Za-z0-9_-]*['\"]?", normalized, re.IGNORECASE)
        or re.fullmatch(r"print\(['\"][A-Za-z0-9_-]*audit[A-Za-z0-9_-]*['\"]\)", normalized, re.IGNORECASE)
    )
    if not safe or re.search(r"[;&|><`\n]|\$\(", normalized):
        report.errors.append(f"{path}: command/code is not a fixed audit-marker print operation")


def validate_policy(
    plan: AuditPlan,
    metadata: ToolMetadata,
    allowed_resources: Optional[List[str]] = None,
) -> ValidationReport:
    report = ValidationReport()
    report.errors.extend(validate_json_schema(plan.arguments, metadata.input_schema))
    allowed_resources = allowed_resources or []
    categories = metadata.risk_category

    if not plan.requires_manual_approval:
        report.errors.append("requires_manual_approval must be true")
    if not plan.expected_success_markers:
        report.warnings.append("No expected success marker; this plan cannot automatically confirm an effect")
    for marker in plan.expected_success_markers:
        if not AUDIT_MARKER_PATTERN.search(marker):
            report.errors.append("Expected success markers must contain an audit/test marker")

    high_impact_target = any(
        token in categories
        for token in (
            "删除",
            "资金",
            "支付",
            "交易",
            "账号",
            "权限",
            "基础设施",
            "外部消息",
            "邮件",
            "公开发布",
        )
    )
    found_synthetic_target = False

    for path, key, value in walk_values(plan.arguments):
        if isinstance(value, str) and len(value) > 10000:
            report.errors.append(f"{path}: string payload is unexpectedly large")
        if isinstance(value, str) and SENSITIVE_VALUE_PATTERN.search(value):
            report.errors.append(f"{path}: payload resembles a real credential or private key")

        if SENSITIVE_KEY_PATTERN.search(key) and value not in (None, ""):
            if not is_synthetic_identifier(value):
                report.errors.append(f"{path}: credential-like fields may only contain conspicuous dummy values")

        if IDENTIFIER_KEY_PATTERN.search(key) and is_synthetic_identifier(value):
            found_synthetic_target = True

        if URL_KEY_PATTERN.search(key) and isinstance(value, str):
            if not is_allowed_url(value, allowed_resources):
                report.errors.append(f"{path}: URL is outside the explicit callback allowlist")

        if PATH_KEY_PATTERN.search(key) and isinstance(value, str):
            if ".." in value or not (
                value.startswith("/tmp/mcpscope/") or AUDIT_MARKER_PATTERN.search(value)
            ):
                report.errors.append(f"{path}: file paths must stay under /tmp/mcpscope/ or use a test marker")

        if COMMAND_KEY_PATTERN.search(key) and isinstance(value, str) and "命令或代码执行" in categories:
            validate_command(path, value, report)

        if (key.lower() in {"sql", "sql_query", "statement", "query"} or key.lower().endswith("_sql")) and "SQL" in categories:
            if not isinstance(value, str):
                report.errors.append(f"{path}: SQL value must be a string")
            elif "SOQL" in metadata.description or "SOSL" in metadata.description:
                validate_soql(path, value, report)
            else:
                validate_sql(path, value, report)

        if re.search(r"(?:amount|price|quantity|funds|value)", key, re.IGNORECASE) and any(
            token in categories for token in ("资金", "支付", "交易")
        ):
            if isinstance(value, (int, float)) and value != 0:
                report.errors.append(f"{path}: financial numeric values must be zero in the generic template")

        if RECIPIENT_KEY_PATTERN.search(key) and isinstance(value, str) and any(
            token in categories for token in ("外部消息", "邮件", "公开发布")
        ):
            if "@" in value and not value.lower().endswith(".invalid"):
                report.errors.append(f"{path}: recipient email must use the reserved .invalid domain")
            elif "@" not in value and not AUDIT_MARKER_PATTERN.search(value):
                report.errors.append(f"{path}: recipient/channel must be an explicit audit target")

    if high_impact_target and not found_synthetic_target:
        report.errors.append("High-impact tools require at least one conspicuously synthetic target identifier")
    return report


def validate_and_require_safe(
    plan: AuditPlan,
    metadata: ToolMetadata,
    allowed_resources: Optional[List[str]] = None,
) -> ValidationReport:
    report = validate_policy(plan, metadata, allowed_resources)
    report.require_safe()
    return report
