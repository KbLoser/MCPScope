#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import time
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm_payload_planner import AuditPlan, OpenAICompatiblePlanner, ToolMetadata
from plan_builder import build_plan
from risk_rules import shortlist
from safety_validator import SafetyValidationError, validate_and_require_safe
from target_discovery import DEFAULT_SOURCES, SOURCE_NAMES, PublicIndexDiscovery
from target_reporting import compare_scans, load_scan, markdown_report, summarize_scan
from target_scanner import load_targets, scan_targets
from report_formats import write_reports
from scan_history import decay_stats, list_runs, latest_watch_targets, persistence_counts, record_scan, target_history, trend
from integration_exports import condor_targets, corvus_yaml, emit_events, ibis_candidates, shrike_yaml, submit_ibis


APP_ROOT = Path(__file__).resolve().parents[1]
NODE_ROOT = APP_ROOT / "node"
DEFAULT_DATA_ROOT = Path(os.getenv("MCPSCOPE_DATA_DIR", str(APP_ROOT / "data"))).resolve()
AUTH_ACK = "I_HAVE_AUTHORIZATION"
VERSION = "1.0.0"


def bounded_integer(value: str, minimum: int, maximum: int, option: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{option} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError(f"{option} must be between {minimum} and {maximum}")
    return parsed


def discovery_limit(value: str) -> int:
    return bounded_integer(value, 1, 500, "--limit-per-source")


def discovery_timeout(value: str) -> int:
    return bounded_integer(value, 1, 120, "--timeout")


def target_limit(value: str) -> int:
    return bounded_integer(value, 1, 1000, "--max-targets")


def target_concurrency(value: str) -> int:
    return bounded_integer(value, 1, 32, "--concurrency")


def probe_timeout(value: str) -> int:
    return bounded_integer(value, 100, 120000, "--timeout")


def page_limit(value: str) -> int:
    return bounded_integer(value, 1, 1000, "--max-pages")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def run_node(script: str, arguments: List[str]) -> Dict[str, Any]:
    command = ["node", str(NODE_ROOT / script), *arguments]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode not in {0, 2}:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or f"Node process exited {completed.returncode}")
    output = completed.stdout.strip()
    if not output:
        raise RuntimeError(completed.stderr.strip() or "Node process returned no JSON")
    return json.loads(output)


def new_run_dir(data_root: Path) -> Path:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    path = data_root / "runs" / run_id
    path.mkdir(parents=True, exist_ok=False)
    return path


def new_artifact_path(data_root: Path, prefix: str, suffix: str = ".json") -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return data_root / "targets" / f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}{suffix}"


def discover(
    url: str,
    transport: str,
    timeout: int,
    max_pages: int,
    command: str = "",
    command_args: Optional[List[str]] = None,
    cwd: str = "",
    pass_env: Optional[List[str]] = None,
    headers: Optional[List[str]] = None,
    bearer_env: str = "",
    api_key_env: str = "",
    api_key_header: str = "X-API-Key",
) -> Dict[str, Any]:
    node_args = ["--transport", transport, "--timeout", str(timeout), "--max-pages", str(max_pages)]
    if transport == "stdio":
        if not command:
            raise ValueError("stdio discovery requires --command")
        node_args.extend(["--command", command])
        for item in command_args or []:
            node_args.extend(["--arg", item])
        if cwd:
            node_args.extend(["--cwd", cwd])
        for item in pass_env or []:
            node_args.extend(["--pass-env", item])
    else:
        if not url:
            raise ValueError("remote discovery requires --url")
        node_args.extend(["--url", url])
        for item in headers or []:
            node_args.extend(["--header", item])
        if bearer_env:
            node_args.extend(["--bearer-env", bearer_env])
        if api_key_env:
            node_args.extend(["--api-key-env", api_key_env, "--api-key-header", api_key_header])
    return run_node("mcp_tools_probe.js", node_args)


def candidate_metadata(candidate: Dict[str, Any], target_url: str) -> ToolMetadata:
    tool = candidate["tool"]
    return ToolMetadata(
        tool_name=str(tool.get("name", "")),
        description=str(tool.get("description", "")),
        input_schema=tool.get("inputSchema") or tool.get("input_schema") or {},
        risk_category="；".join(candidate.get("risk_categories", [])),
        target_url=target_url,
    )


def validate_plan(plan_value: Dict[str, Any], candidate: Dict[str, Any], target_url: str, allowed: List[str]) -> Dict[str, Any]:
    plan = AuditPlan.from_dict(plan_value)
    metadata = candidate_metadata(candidate, target_url)
    try:
        report = validate_and_require_safe(plan, metadata, allowed)
        return {"safe": True, "errors": [], "warnings": report.warnings}
    except SafetyValidationError as exc:
        return {"safe": False, "errors": str(exc).splitlines(), "warnings": []}


def find_candidate(candidates: List[Dict[str, Any]], candidate_id: int) -> Dict[str, Any]:
    for candidate in candidates:
        if int(candidate.get("candidate_id", 0)) == candidate_id:
            return candidate
    raise ValueError(f"candidate_id not found: {candidate_id}")


def flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten(child) for child in value.values())
    if isinstance(value, list):
        return " ".join(flatten(child) for child in value)
    return "" if value is None else str(value)


def analyze_result(result: Dict[str, Any], markers: List[str]) -> Dict[str, Any]:
    text = flatten(result)
    if result.get("status") == "connection_failed":
        classification = "CONNECTION_FAILED"
        rationale = "所有有限候选端点均连接失败，未调用工具。"
    elif result.get("status") == "call_failed":
        classification = "CALL_FAILED_REVIEW_REQUIRED"
        rationale = "MCP 已连接，但工具调用失败，需要检查协议或参数错误。"
    elif re.search(r"\b(?:401|403|unauthorized|forbidden|authentication|required credential|api key|bearer)\b", text, re.I):
        classification = "AUTHENTICATION_BLOCKED"
        rationale = "响应包含明确的认证或授权拦截证据。"
    elif re.search(r"(?:postgres(?:ql)?|mysql|mongodb|redis)://\*\*\*:\*\*\*@", text, re.I):
        classification = "SENSITIVE_INFORMATION_DISCLOSURE_REVIEW_REQUIRED"
        rationale = "脱敏响应中仍可识别出带认证信息的内部连接串结构。"
    elif any(marker and marker in text for marker in markers):
        classification = "SAFE_EFFECT_REACHED_REVIEW_REQUIRED"
        rationale = "响应命中预期无害标记，说明调用可能到达工具执行层，需要人工确认授权边界。"
    elif re.search(r"not found|does not exist|invalid (?:id|resource)|validation", text, re.I):
        classification = "BUSINESS_REACHED_NOT_PROVEN"
        rationale = "请求到达业务校验层，但没有证明高风险操作成功。"
    else:
        classification = "RESPONSE_RECEIVED_REVIEW_REQUIRED"
        rationale = "收到响应，但确定性规则不足以确认或排除漏洞。"
    return {
        "classification": classification,
        "rationale": rationale,
        "vulnerability_confirmed": False,
        "manual_review_required": True,
        "analyzed_at": now_iso(),
    }


def command_discover(args: argparse.Namespace) -> int:
    result = discover(
        args.url,
        args.transport,
        args.timeout,
        args.max_pages,
        args.command,
        args.command_args,
        args.cwd,
        args.pass_env,
        args.header,
        args.bearer_env,
        args.api_key_env,
        args.api_key_header,
    )
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result.get("status") == "failed" else 0


def command_targets_discover(args: argparse.Namespace) -> int:
    sources = args.source or list(DEFAULT_SOURCES)
    discovery = PublicIndexDiscovery(timeout=args.timeout)
    payload = discovery.run(sources, args.limit_per_source)
    if args.since:
        known = {item["url"] for item in load_targets(args.since)}
        payload["candidates"] = [item for item in payload["candidates"] if item["url"] not in known]
        payload["candidate_count"] = len(payload["candidates"])
        payload["excluded_by_since"] = len(known)
    payload["created_at"] = now_iso()
    output = args.output or new_artifact_path(args.data_root, "passive-candidates")
    write_json(output, payload)
    print(
        json.dumps(
            {
                "mode": payload["mode"],
                "sources": payload["sources"],
                "source_counts": payload["source_counts"],
                "candidate_count": payload["candidate_count"],
                "warnings": payload["warnings"],
                "output": str(output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_targets_scan(args: argparse.Namespace) -> int:
    if args.authorization_ack != AUTH_ACK:
        raise SystemExit(
            f"Active target scanning requires --authorization-ack {AUTH_ACK}. "
            "Only scan targets covered by a written authorization scope."
        )
    if not args.input.exists():
        raise ValueError(f"target input not found: {args.input}")
    targets = load_targets(args.input)
    if not targets:
        raise ValueError(f"target input contains no valid HTTP(S) URLs: {args.input}")
    selected = targets[: args.max_targets]
    if args.resume:
        completed = {item["url"] for item in load_targets(args.resume)}
        selected = [target for target in selected if target["url"] not in completed]

    def probe_target(url: str) -> Dict[str, Any]:
        return discover(
            url, "auto", args.timeout, args.max_pages,
            headers=args.header, bearer_env=args.bearer_env,
            api_key_env=args.api_key_env, api_key_header=args.api_key_header,
        )

    database = args.data_root / "history.sqlite3"
    prior_counts = persistence_counts(database, [target["url"] for target in selected])
    records = scan_targets(selected, probe_target, args.concurrency, prior_counts)
    confirmed = [record for record in records if record["confirmed_mcp"]]
    high_risk = [record for record in confirmed if record["high_risk_candidates"]]
    payload = {
        "mode": "authorized_active_mcp_fingerprint",
        "created_at": now_iso(),
        "authorization_acknowledged": True,
        "input": str(args.input),
        "input_target_count": len(targets),
        "scanned_target_count": len(selected),
        "confirmed_mcp_count": len(confirmed),
        "high_risk_target_count": len(high_risk),
        "records": records,
    }
    output = args.output or new_artifact_path(args.data_root, "fingerprint-results")
    write_json(output, payload)
    history_run_id = record_scan(database, payload, label=args.label, source_file=str(output))
    print(
        json.dumps(
            {
                "scanned_target_count": len(selected),
                "confirmed_mcp_count": len(confirmed),
                "high_risk_target_count": len(high_risk),
                "history_run_id": history_run_id,
                "output": str(output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_targets_report(args: argparse.Namespace) -> int:
    document = load_scan(args.input)
    output = args.output or args.input.with_suffix(".md")
    write_text(output, markdown_report(document))
    summary = summarize_scan(document)
    summary["output"] = str(output)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def command_report(args: argparse.Namespace) -> int:
    document = load_scan(args.input)
    if args.min_risk:
        order = {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4, "未发现高风险工具": 4}
        threshold = order[args.min_risk]
        document = {**document, "records": [record for record in document.get("records", []) if order.get(str(record.get("risk_level")), 4) <= threshold]}
    formats = args.format or ["sarif", "html"]
    output_dir = args.output_dir or args.input.parent
    written = write_reports(document, output_dir, args.input.stem, formats, markdown_report(document))
    print(json.dumps({"formats": written, **summarize_scan(document)}, ensure_ascii=False, indent=2))
    return 0


def command_stats(args: argparse.Namespace) -> int:
    print(json.dumps(summarize_scan(load_scan(args.input)), ensure_ascii=False, indent=2))
    return 0


def command_history(args: argparse.Namespace) -> int:
    print(json.dumps(list_runs(args.data_root / "history.sqlite3", args.limit), ensure_ascii=False, indent=2))
    return 0


def command_trend(args: argparse.Namespace) -> int:
    print(json.dumps(trend(args.data_root / "history.sqlite3", args.metric), ensure_ascii=False, indent=2))
    return 0


def command_longitudinal(args: argparse.Namespace) -> int:
    print(json.dumps(target_history(args.data_root / "history.sqlite3", args.url), ensure_ascii=False, indent=2))
    return 0


def command_decay(args: argparse.Namespace) -> int:
    print(json.dumps(decay_stats(args.data_root / "history.sqlite3"), ensure_ascii=False, indent=2))
    return 0


def command_watch(args: argparse.Namespace) -> int:
    if args.authorization_ack != AUTH_ACK:
        raise SystemExit(f"Watch requires --authorization-ack {AUTH_ACK} because it actively reconnects to targets.")
    database = args.data_root / "history.sqlite3"
    targets = latest_watch_targets(database)
    if not targets:
        raise ValueError("no critical execution-capable targets are available in the latest history run")
    round_number = 0
    while args.max_rounds == 0 or round_number < args.max_rounds:
        round_number += 1
        selected = [{"url": record["url"], "sources": record.get("sources", ["watch"])} for record in targets]
        prior_counts = persistence_counts(database, [target["url"] for target in selected])
        records = scan_targets(
            selected,
            lambda url: discover(url, "auto", args.timeout, args.max_pages),
            args.concurrency,
            prior_counts,
        )
        document = {
            "mode": "authorized_watch",
            "created_at": now_iso(),
            "authorization_acknowledged": True,
            "round": round_number,
            "records": records,
        }
        output = new_artifact_path(args.data_root, f"watch-round-{round_number}")
        write_json(output, document)
        run_id = record_scan(database, document, label=f"watch-{round_number}", source_file=str(output))
        print(json.dumps({"round": round_number, "history_run_id": run_id, "output": str(output)}, ensure_ascii=False))
        if args.max_rounds and round_number >= args.max_rounds:
            break
        time.sleep(args.interval * 3600)
    return 0


def command_feed_corvus(args: argparse.Namespace) -> int:
    content = corvus_yaml(load_scan(args.input), args.min_risk, args.include_waf, args.source)
    if args.output:
        write_text(args.output, content)
    else:
        print(content, end="")
    return 0


def command_feed_condor(args: argparse.Namespace) -> int:
    content = condor_targets(load_scan(args.input), args.min_score)
    if args.output:
        write_text(args.output, content)
    else:
        print(content, end="")
    return 0


def command_feed_shrike(args: argparse.Namespace) -> int:
    content = shrike_yaml(load_scan(args.input), args.min_score, args.source)
    if args.output:
        write_text(args.output, content)
    else:
        print(content, end="")
    return 0


def command_feed_ibis(args: argparse.Namespace) -> int:
    database = args.ibis_database or Path.home() / ".ibis" / "ibis.db"
    candidates = ibis_candidates(load_scan(args.input), database)
    if not args.apply:
        print(json.dumps({"mode": "preview", "candidates": candidates}, ensure_ascii=False, indent=2))
        return 0
    if not args.approve:
        raise SystemExit("Ibis submission requires --apply and --approve.")
    results = submit_ibis(candidates, args.ibis_bin)
    print(json.dumps({"mode": "submitted", "results": results}, ensure_ascii=False, indent=2))
    return 0


def command_emit_cobalto(args: argparse.Namespace) -> int:
    if not args.approve:
        raise SystemExit("CobaltoHQ event emission requires --approve.")
    count = emit_events(load_scan(args.input), str(args.input))
    print(json.dumps({"emitted_events": count}, ensure_ascii=False, indent=2))
    return 0


def command_targets_diff(args: argparse.Namespace) -> int:
    comparison = compare_scans(load_scan(args.old), load_scan(args.new))
    comparison["created_at"] = now_iso()
    comparison["old"] = str(args.old)
    comparison["new"] = str(args.new)
    if args.classify and comparison["disappeared_targets"]:
        if args.authorization_ack != AUTH_ACK:
            raise SystemExit(f"Disappearance classification requires --authorization-ack {AUTH_ACK}.")
        classifications = []
        for url in comparison["disappeared_targets"]:
            result = discover(url, "auto", args.timeout, args.max_pages)
            attempts_text = json.dumps(result.get("attempts", []), ensure_ascii=False)
            if result.get("status") in {"success", "no_tools"}:
                reason = "still_available"
            elif re.search(r"401|403|unauthorized|forbidden", attempts_text, re.I):
                reason = "authentication_added"
            elif re.search(r"404|not found", attempts_text, re.I):
                reason = "endpoint_removed"
            elif re.search(r"timeout|refused|ENOTFOUND|ECONN", attempts_text, re.I):
                reason = "offline_or_unreachable"
            else:
                reason = "unknown"
            classifications.append({"url": url, "reason": reason, "probe": result})
        comparison["disappearance_classifications"] = classifications
    if args.output:
        write_json(args.output, comparison)
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return 0


def prepare_audit(
    url: str,
    transport: str,
    timeout: int,
    max_pages: int,
    plan_top: int,
    allowed_resource: List[str],
    use_llm: bool,
    data_root: Path,
) -> tuple[Path, Dict[str, Any], List[Dict[str, Any]]]:
    run_dir = new_run_dir(data_root)
    manifest = {
        "run_id": run_dir.name,
        "target_url": url,
        "created_at": now_iso(),
        "status": "discovering",
        "authorized_scope_acknowledged": False,
    }
    write_json(run_dir / "manifest.json", manifest)
    result = discover(url, transport, timeout, max_pages)
    write_json(run_dir / "discovery.json", result)
    if result.get("status") not in {"success", "no_tools"}:
        manifest["status"] = "discovery_failed"
        manifest["finished_at"] = now_iso()
        write_json(run_dir / "manifest.json", manifest)
        return run_dir, manifest, []

    candidates = shortlist(result.get("tools", []))
    write_json(run_dir / "candidates.json", candidates)
    plan_count = min(max(plan_top, 0), len(candidates))
    for candidate in candidates[:plan_count]:
        metadata = candidate_metadata(candidate, url)
        if use_llm:
            planner = OpenAICompatiblePlanner()
            plan = planner.generate(metadata, allowed_resource).to_dict()
            source = "llm"
        else:
            plan = build_plan(candidate, allowed_resource)
            source = "deterministic_template"
        validation = validate_plan(plan, candidate, url, allowed_resource)
        payload = {"source": source, "plan": plan, "validation": validation}
        write_json(run_dir / "plans" / f'candidate-{candidate["candidate_id"]}.json', payload)

    manifest.update(
        {
            "status": "awaiting_approval" if candidates else "completed_no_candidates",
            "tool_count": len(result.get("tools", [])),
            "candidate_count": len(candidates),
            "generated_plan_count": plan_count,
            "updated_at": now_iso(),
        }
    )
    write_json(run_dir / "manifest.json", manifest)
    return run_dir, manifest, candidates


def command_audit(args: argparse.Namespace) -> int:
    run_dir, manifest, _ = prepare_audit(
        args.url,
        args.transport,
        args.timeout,
        args.max_pages,
        args.plan_top,
        args.allowed_resource,
        args.llm,
        args.data_root,
    )
    if manifest["status"] == "discovery_failed":
        print(f"Run failed during discovery: {run_dir}")
        return 2
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"Run directory: {run_dir}")
    return 0


def command_one_click(args: argparse.Namespace) -> int:
    """Run discovery and planning, with optional explicitly approved single call."""
    run_dir, manifest, candidates = prepare_audit(
        args.url,
        args.transport,
        args.timeout,
        args.max_pages,
        args.plan_top,
        args.allowed_resource,
        args.llm,
        args.data_root,
    )
    if manifest["status"] == "discovery_failed":
        print(f"Run failed during discovery: {run_dir}")
        return 2
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"Run directory: {run_dir}")
    if not args.execute:
        print("Stopped before tools/call; use --execute with explicit approval to continue.")
        return 0
    if not candidates:
        raise SystemExit("No high-risk candidates were generated; refusing execution.")
    candidate_id = args.candidate_id or int(candidates[0]["candidate_id"])
    execute_args = argparse.Namespace(
        run_dir=run_dir,
        candidate_id=candidate_id,
        plan=None,
        transport=args.transport,
        timeout=args.timeout,
        allowed_resource=args.allowed_resource,
        approve=args.approve,
        authorization_ack=args.authorization_ack,
    )
    result = command_execute(execute_args)
    if args.review_decision:
        if not args.review_notes:
            raise SystemExit("--review-notes is required when --review-decision is provided")
        command_review(
            argparse.Namespace(
                run_dir=run_dir,
                candidate_id=candidate_id,
                decision=args.review_decision,
                notes=args.review_notes,
                reviewer=args.reviewer,
            )
        )
    return result


def command_execute(args: argparse.Namespace) -> int:
    if not args.approve or args.authorization_ack != AUTH_ACK:
        raise SystemExit(
            f"Execution requires --approve and --authorization-ack {AUTH_ACK}. "
            "Only test targets you are authorized to assess."
        )
    manifest_path = args.run_dir / "manifest.json"
    manifest = read_json(manifest_path)
    candidates = read_json(args.run_dir / "candidates.json")
    candidate = find_candidate(candidates, args.candidate_id)
    plan_path = args.plan or args.run_dir / "plans" / f"candidate-{args.candidate_id}.json"
    plan_document = read_json(plan_path)
    plan_value = plan_document.get("plan", plan_document)
    validation = validate_plan(plan_value, candidate, manifest["target_url"], args.allowed_resource)
    if not validation["safe"]:
        raise SystemExit("Plan failed deterministic safety validation:\n" + "\n".join(validation["errors"]))

    result_path = args.run_dir / "raw" / f"candidate-{args.candidate_id}.json"
    if result_path.exists():
        raise SystemExit(f"Refusing duplicate execution; result already exists: {result_path}")
    plan_bytes = json.dumps(plan_value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    approval = {
        "candidate_id": args.candidate_id,
        "approved_at": now_iso(),
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "authorization_ack": AUTH_ACK,
    }
    write_json(args.run_dir / "approvals" / f"candidate-{args.candidate_id}.json", approval)

    tool = candidate["tool"]
    temporary_plan = args.run_dir / "plans" / f"candidate-{args.candidate_id}.arguments.json"
    write_json(temporary_plan, {"arguments": plan_value["arguments"]})
    result = run_node(
        "mcp_tool_call.js",
        [
            "--url", manifest["target_url"],
            "--transport", args.transport,
            "--tool", str(tool.get("name", "")),
            "--arguments-file", str(temporary_plan),
            "--timeout", str(args.timeout),
        ],
    )
    write_json(result_path, result)
    analysis = analyze_result(result, plan_value.get("expected_success_markers", []))
    write_json(args.run_dir / "results" / f"candidate-{args.candidate_id}.json", analysis)
    manifest["status"] = "review_required"
    manifest["authorized_scope_acknowledged"] = True
    manifest["updated_at"] = now_iso()
    write_json(manifest_path, manifest)
    print(json.dumps(analysis, ensure_ascii=False, indent=2))
    print(f"Raw result: {result_path}")
    return 2 if result.get("status") == "connection_failed" else 0


def command_review(args: argparse.Namespace) -> int:
    result_path = args.run_dir / "results" / f"candidate-{args.candidate_id}.json"
    if not result_path.exists():
        raise SystemExit(f"Analysis result not found: {result_path}")
    review = {
        "candidate_id": args.candidate_id,
        "decision": args.decision,
        "notes": args.notes,
        "reviewed_at": now_iso(),
        "reviewer": args.reviewer,
    }
    write_json(args.run_dir / "reviews" / f"candidate-{args.candidate_id}.json", review)
    print(json.dumps(review, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscope",
        description="Discover, fingerprint, and safely validate authorized MCP services.",
    )
    parser.add_argument("--version", action="version", version=f"MCPScope {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover", help="Read-only MCP initialize and tools/list")
    discover_parser.add_argument("--url")
    discover_parser.add_argument("--transport", default="auto")
    discover_parser.add_argument("--command")
    discover_parser.add_argument("--arg", dest="command_args", action="append", default=[])
    discover_parser.add_argument("--cwd")
    discover_parser.add_argument("--pass-env", dest="pass_env", action="append", default=[])
    discover_parser.add_argument("--header", action="append", default=[])
    discover_parser.add_argument("--bearer-env", default="")
    discover_parser.add_argument("--api-key-env", default="")
    discover_parser.add_argument("--api-key-header", default="X-API-Key")
    discover_parser.add_argument("--timeout", type=int, default=15000)
    discover_parser.add_argument("--max-pages", type=int, default=100)
    discover_parser.add_argument("--output", type=Path)
    discover_parser.set_defaults(func=command_discover)

    target_discover_parser = subparsers.add_parser(
        "targets-discover",
        help="Passively collect candidate MCP target URLs from public indexes",
    )
    target_discover_parser.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCE_NAMES),
        help="Public index to query; repeat to select multiple sources",
    )
    target_discover_parser.add_argument("--limit-per-source", type=discovery_limit, default=100)
    target_discover_parser.add_argument("--timeout", type=discovery_timeout, default=20)
    target_discover_parser.add_argument("--since", type=Path, help="Exclude candidates already present in this target or scan file")
    target_discover_parser.add_argument("--output", type=Path)
    target_discover_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    target_discover_parser.set_defaults(func=command_targets_discover)

    target_scan_parser = subparsers.add_parser(
        "targets-scan",
        help="Actively fingerprint an explicitly authorized target list",
    )
    target_scan_parser.add_argument("--input", type=Path, required=True)
    target_scan_parser.add_argument("--output", type=Path)
    target_scan_parser.add_argument("--max-targets", type=target_limit, default=25)
    target_scan_parser.add_argument("--concurrency", type=target_concurrency, default=4)
    target_scan_parser.add_argument("--timeout", type=probe_timeout, default=15000)
    target_scan_parser.add_argument("--max-pages", type=page_limit, default=100)
    target_scan_parser.add_argument("--authorization-ack", default="")
    target_scan_parser.add_argument("--label", default="")
    target_scan_parser.add_argument("--resume", type=Path, help="Skip URLs already present in an earlier target scan")
    target_scan_parser.add_argument("--header", action="append", default=[])
    target_scan_parser.add_argument("--bearer-env", default="")
    target_scan_parser.add_argument("--api-key-env", default="")
    target_scan_parser.add_argument("--api-key-header", default="X-API-Key")
    target_scan_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    target_scan_parser.set_defaults(func=command_targets_scan)

    target_report_parser = subparsers.add_parser(
        "targets-report",
        help="Generate an offline Markdown report from fingerprint results",
    )
    target_report_parser.add_argument("--input", type=Path, required=True)
    target_report_parser.add_argument("--output", type=Path)
    target_report_parser.set_defaults(func=command_targets_report)

    target_diff_parser = subparsers.add_parser(
        "targets-diff",
        help="Compare two offline fingerprint result documents",
    )
    target_diff_parser.add_argument("--old", type=Path, required=True)
    target_diff_parser.add_argument("--new", type=Path, required=True)
    target_diff_parser.add_argument("--output", type=Path)
    target_diff_parser.add_argument("--classify", action="store_true", help="Actively re-probe disappeared targets")
    target_diff_parser.add_argument("--authorization-ack", default="")
    target_diff_parser.add_argument("--timeout", type=probe_timeout, default=15000)
    target_diff_parser.add_argument("--max-pages", type=page_limit, default=100)
    target_diff_parser.set_defaults(func=command_targets_diff)

    report_parser = subparsers.add_parser("report", help="Generate offline JSON, SARIF, HTML, Markdown, or CSV reports")
    report_parser.add_argument("--input", type=Path, required=True)
    report_parser.add_argument("--format", action="append", choices=["json", "jsonl", "sarif", "html", "markdown", "csv"])
    report_parser.add_argument("--output-dir", type=Path)
    report_parser.add_argument("--min-risk", choices=["严重", "高", "中", "低", "信息"])
    report_parser.set_defaults(func=command_report)

    stats_parser = subparsers.add_parser("stats", help="Show aggregate statistics for a fingerprint scan")
    stats_parser.add_argument("--input", type=Path, required=True)
    stats_parser.set_defaults(func=command_stats)

    history_parser = subparsers.add_parser("history", help="List stored active-scan runs")
    history_parser.add_argument("--limit", type=int, default=50)
    history_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    history_parser.set_defaults(func=command_history)

    trend_parser = subparsers.add_parser("trend", help="Show one metric across stored runs")
    trend_parser.add_argument("metric", choices=["target_count", "confirmed_count", "critical_count", "auth_none_count", "average_priority"])
    trend_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    trend_parser.set_defaults(func=command_trend)

    longitudinal_parser = subparsers.add_parser("longitudinal", help="Show stored history for one MCP URL")
    longitudinal_parser.add_argument("url")
    longitudinal_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    longitudinal_parser.set_defaults(func=command_longitudinal)

    decay_parser = subparsers.add_parser("decay", help="Show active and inactive target lifecycle statistics")
    decay_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    decay_parser.set_defaults(func=command_decay)

    watch_parser = subparsers.add_parser("watch", help="Re-scan authorized critical execution-capable targets")
    watch_parser.add_argument("--interval", type=lambda value: bounded_integer(value, 1, 720, "--interval"), default=6)
    watch_parser.add_argument("--max-rounds", type=lambda value: bounded_integer(value, 0, 10000, "--max-rounds"), default=0)
    watch_parser.add_argument("--concurrency", type=target_concurrency, default=4)
    watch_parser.add_argument("--timeout", type=probe_timeout, default=15000)
    watch_parser.add_argument("--max-pages", type=page_limit, default=100)
    watch_parser.add_argument("--authorization-ack", default="")
    watch_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    watch_parser.set_defaults(func=command_watch)

    corvus_parser = subparsers.add_parser("feed-corvus", help="Export scan results as Corvus target YAML")
    corvus_parser.add_argument("--input", type=Path, required=True)
    corvus_parser.add_argument("--output", type=Path)
    corvus_parser.add_argument("--min-risk", choices=["严重", "高", "中", "低", "信息"], default="信息")
    corvus_parser.add_argument("--include-waf", action="store_true")
    corvus_parser.add_argument("--source", default="")
    corvus_parser.set_defaults(func=command_feed_corvus)

    condor_parser = subparsers.add_parser("feed-condor", help="Export agentic-platform targets for Condor")
    condor_parser.add_argument("--input", type=Path, required=True)
    condor_parser.add_argument("--output", type=Path)
    condor_parser.add_argument("--min-score", type=int, default=50)
    condor_parser.set_defaults(func=command_feed_condor)

    shrike_parser = subparsers.add_parser("feed-shrike", help="Export prioritized targets as Shrike YAML")
    shrike_parser.add_argument("--input", type=Path, required=True)
    shrike_parser.add_argument("--output", type=Path)
    shrike_parser.add_argument("--min-score", type=int, default=50)
    shrike_parser.add_argument("--source", default="")
    shrike_parser.set_defaults(func=command_feed_shrike)

    ibis_parser = subparsers.add_parser("feed-ibis", help="Preview or submit disclosure stubs to Ibis")
    ibis_parser.add_argument("--input", type=Path, required=True)
    ibis_parser.add_argument("--ibis-database", type=Path)
    ibis_parser.add_argument("--ibis-bin", default="ibis")
    ibis_parser.add_argument("--apply", action="store_true")
    ibis_parser.add_argument("--approve", action="store_true")
    ibis_parser.set_defaults(func=command_feed_ibis)

    cobalto_parser = subparsers.add_parser("emit-cobalto", help="Emit approved high-risk scan events to CobaltoHQ")
    cobalto_parser.add_argument("--input", type=Path, required=True)
    cobalto_parser.add_argument("--approve", action="store_true")
    cobalto_parser.set_defaults(func=command_emit_cobalto)

    audit_parser = subparsers.add_parser("audit", help="Discover, shortlist, and generate non-executing plans")
    audit_parser.add_argument("--url", required=True)
    audit_parser.add_argument("--transport", default="auto")
    audit_parser.add_argument("--timeout", type=int, default=15000)
    audit_parser.add_argument("--max-pages", type=int, default=100)
    audit_parser.add_argument("--plan-top", type=int, default=5)
    audit_parser.add_argument("--allowed-resource", action="append", default=[])
    audit_parser.add_argument("--llm", action="store_true", help="Use an OpenAI-compatible planner configured by environment variables")
    audit_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    audit_parser.set_defaults(func=command_audit)

    one_click_parser = subparsers.add_parser(
        "one-click",
        help="Run discovery and planning in one command; optionally execute one approved call",
    )
    one_click_parser.add_argument("--url", required=True)
    one_click_parser.add_argument("--transport", default="auto")
    one_click_parser.add_argument("--timeout", type=int, default=15000)
    one_click_parser.add_argument("--max-pages", type=int, default=100)
    one_click_parser.add_argument("--plan-top", type=int, default=5)
    one_click_parser.add_argument("--allowed-resource", action="append", default=[])
    one_click_parser.add_argument("--llm", action="store_true")
    one_click_parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    one_click_parser.add_argument("--execute", action="store_true", help="Continue to one tools/call after approval")
    one_click_parser.add_argument("--candidate-id", type=int)
    one_click_parser.add_argument("--approve", action="store_true")
    one_click_parser.add_argument("--authorization-ack", default="")
    one_click_parser.add_argument(
        "--review-decision",
        choices=["confirmed", "not_confirmed", "needs_more_evidence"],
        help="Optionally record the final human decision after execution",
    )
    one_click_parser.add_argument("--review-notes")
    one_click_parser.add_argument("--reviewer", default=os.getenv("USER", "manual-reviewer"))
    one_click_parser.set_defaults(func=command_one_click)

    execute_parser = subparsers.add_parser("execute", help="Validate, approve, and perform exactly one tool call")
    execute_parser.add_argument("--run-dir", type=Path, required=True)
    execute_parser.add_argument("--candidate-id", type=int, required=True)
    execute_parser.add_argument("--plan", type=Path)
    execute_parser.add_argument("--transport", default="auto")
    execute_parser.add_argument("--timeout", type=int, default=15000)
    execute_parser.add_argument("--allowed-resource", action="append", default=[])
    execute_parser.add_argument("--approve", action="store_true")
    execute_parser.add_argument("--authorization-ack", default="")
    execute_parser.set_defaults(func=command_execute)

    review_parser = subparsers.add_parser("review", help="Record a human decision without modifying raw evidence")
    review_parser.add_argument("--run-dir", type=Path, required=True)
    review_parser.add_argument("--candidate-id", type=int, required=True)
    review_parser.add_argument("--decision", choices=["confirmed", "not_confirmed", "needs_more_evidence"], required=True)
    review_parser.add_argument("--notes", required=True)
    review_parser.add_argument("--reviewer", default=os.getenv("USER", "manual-reviewer"))
    review_parser.set_defaults(func=command_review)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
