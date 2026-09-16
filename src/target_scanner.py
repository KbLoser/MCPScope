#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List
from urllib.parse import urlsplit

from risk_rules import assess_server
from target_discovery import normalize_url


ProbeFunction = Callable[[str], Dict[str, Any]]


def detect_platform(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    for suffix, platform in (
        (".hf.space", "huggingface"),
        (".vercel.app", "vercel"),
        (".railway.app", "railway"),
        (".fly.dev", "fly.io"),
        (".fly.io", "fly.io"),
        (".onrender.com", "render"),
        (".workers.dev", "cloudflare-workers"),
        (".run.app", "google-cloud-run"),
        (".amazonaws.com", "aws"),
        (".azurewebsites.net", "azure"),
    ):
        if host.endswith(suffix):
            return platform
    return "unknown"


def _target_item(value: Any) -> Dict[str, Any] | None:
    if isinstance(value, str):
        url = normalize_url(value)
        return {"url": url, "sources": []} if url else None
    if not isinstance(value, dict):
        return None
    raw_url = value.get("url") or value.get("target_url") or value.get("final_url") or value.get("endpoint")
    url = normalize_url(str(raw_url or ""))
    if not url:
        return None
    sources = value.get("sources", [])
    if isinstance(sources, str):
        sources = [sources]
    return {"url": url, "sources": sources if isinstance(sources, list) else []}


def load_targets(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    values: Iterable[Any]
    try:
        document = json.loads(text)
        if isinstance(document, dict):
            values = document.get("candidates") or document.get("targets") or document.get("records") or []
        elif isinstance(document, list):
            values = document
        else:
            values = []
    except json.JSONDecodeError:
        parsed_lines = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parsed_lines.append(json.loads(line))
            except json.JSONDecodeError:
                parsed_lines.append(line)
        values = parsed_lines

    results = []
    by_url: Dict[str, Dict[str, Any]] = {}
    for value in values:
        item = _target_item(value)
        if not item:
            continue
        existing = by_url.get(item["url"])
        if existing:
            for source in item["sources"]:
                if source not in existing["sources"]:
                    existing["sources"].append(source)
        else:
            by_url[item["url"]] = item
            results.append(item)
    return results


def _auth_state(result: Dict[str, Any]) -> str:
    if result.get("status") in {"success", "no_tools"}:
        return "provided" if result.get("authenticationProvided") else "none"
    text = json.dumps(result.get("attempts", []), ensure_ascii=False)
    if re.search(r"oauth", text, re.I):
        return "oauth"
    if re.search(r"bearer", text, re.I):
        return "bearer"
    if re.search(r"api[-_ ]?key|x-api-key", text, re.I):
        return "api-key"
    if re.search(r"(?:\b401\b|\b403\b|unauthorized|forbidden|authentication required)", text, re.I):
        return "required"
    return "unknown"


def assess_target(target: Dict[str, Any], result: Dict[str, Any], persistence_runs: int = 1) -> Dict[str, Any]:
    tools = result.get("tools", []) if isinstance(result.get("tools"), list) else []
    auth_state = _auth_state(result)
    platform = detect_platform(target["url"])
    risk = assess_server(result, auth_state, platform, persistence_runs)
    tool_names = sorted(str(tool.get("name", "")) for tool in tools if isinstance(tool, dict) and tool.get("name"))
    tool_name_hash = hashlib.sha256(json.dumps(tool_names, ensure_ascii=False).encode("utf-8")).hexdigest()[:16]

    return {
        "url": target["url"],
        "sources": target.get("sources", []),
        "status": result.get("status", "failed"),
        "confirmed_mcp": result.get("status") in {"success", "no_tools"},
        "endpoint": result.get("endpoint"),
        "endpoint_path": result.get("endpointPath"),
        "final_url": result.get("finalUrl"),
        "redirect_count": result.get("redirectCount", 0),
        "behind_cloudflare": bool(result.get("behindCloudflare")),
        "http_server": result.get("httpServer"),
        "transport": result.get("transport"),
        "platform": platform,
        "protocol_version": result.get("protocolVersion"),
        "server_info": result.get("serverInfo"),
        "server_capabilities": result.get("serverCapabilities"),
        "server_instructions": result.get("serverInstructions"),
        "resources": result.get("resources", []),
        "prompts": result.get("prompts", []),
        "resource_pages": result.get("resourcePages", 0),
        "prompt_pages": result.get("promptPages", 0),
        "duration_ms": result.get("durationMs"),
        "auth_state": auth_state,
        "tool_count": len(tools),
        "tool_name_hash": tool_name_hash,
        "tools": tools,
        **risk,
        "persistence_runs": persistence_runs,
        "attempts": result.get("attempts", []),
        "error": result.get("error"),
        "probe_error_type": (
            "timeout" if re.search(r"timeout|超时", str(result.get("error", "")), re.I)
            else "non_mcp" if re.search(r"404|405|method not allowed|not found", str(result.get("error", "")), re.I)
            else "error" if result.get("status") == "failed" else None
        ),
    }


def scan_targets(
    targets: List[Dict[str, Any]],
    probe: ProbeFunction,
    concurrency: int,
    persistence_counts: Dict[str, int] | None = None,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any] | None] = [None] * len(targets)

    def run_one(index: int, target: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
        try:
            result = probe(target["url"])
        except Exception as exc:
            result = {"status": "failed", "tools": [], "error": f"{type(exc).__name__}: {exc}"}
        prior_runs = (persistence_counts or {}).get(target["url"], 0)
        return index, assess_target(target, result, persistence_runs=prior_runs + 1)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(run_one, index, target) for index, target in enumerate(targets)]
        for future in as_completed(futures):
            index, record = future.result()
            records[index] = record
    return [record for record in records if record is not None]
