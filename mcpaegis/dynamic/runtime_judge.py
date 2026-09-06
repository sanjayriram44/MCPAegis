"""Stage 4 LLM emitter: classify runtime weaknesses from tree + declared/code caps."""

from __future__ import annotations

import logging
from typing import Any, Optional

from mcpaegis.core.models import (
    DeclaredVsObservedMismatch,
    ExpectedBehaviorProfile,
    JudgeClassification,
    PostExecutionVerification,
    ProcessNode,
    StaticReport,
    ToolBehaviorTree,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness

logger = logging.getLogger(__name__)

RUNTIME_EMITTABLE = frozenset(
    {
        Weakness.W3_OVERPRIVILEGED.value,
        Weakness.W5_COMMAND_INJECTION.value,
        Weakness.W6_PATH_TRAVERSAL.value,
        Weakness.W7_SSRF.value,
        Weakness.W9_TOOL_EXEC_HIJACK.value,
        Weakness.W10_CREDENTIAL_EXPOSURE.value,
    }
)
STATIC_ONLY_IDS = frozenset(
    {
        Weakness.W1_TOOL_POISONING.value,
        Weakness.W2_TOOL_SHADOWING.value,
        Weakness.W4_SUPPLY_CHAIN.value,
        Weakness.W8_ACCESS_CONTROL.value,
    }
)
EMIT_VERDICTS = frozenset({"runtime_confirmed", "runtime_only"})


def judge_verification(
    verification: PostExecutionVerification,
    tree: ToolBehaviorTree,
    profile: ExpectedBehaviorProfile,
    *,
    session: AuditSession | None = None,
    schema: dict[str, Any] | None = None,
    execution_result: Any = None,
    static_report: StaticReport | None = None,
) -> PostExecutionVerification:
    """LLM emits runtime findings. Missing key / parse failure → code verification."""
    if session is None or not session.llm.enabled:
        return verification
    payload = _ask_llm(
        verification,
        tree,
        profile,
        session=session,
        schema=schema,
        execution_result=execution_result,
        static_report=static_report,
    )
    if payload is None:
        return verification
    return apply_classifications(verification, payload)


def apply_classifications(
    verification: PostExecutionVerification,
    payload: dict[str, Any],
) -> PostExecutionVerification:
    """Replace runtime IDs with LLM verdicts. Static-only IDs are dropped."""
    raw = payload.get("classifications")
    if not isinstance(raw, list):
        return verification

    confirmed: list[str] = []
    runtime_only: list[str] = []
    notes: list[str] = []
    classifications: list[JudgeClassification] = []
    seen: set[str] = set()

    for item in raw:
        if not isinstance(item, dict):
            continue
        wid = str(item.get("weakness_id") or "").strip()
        verdict = str(item.get("verdict") or "").strip().lower()
        why = str(item.get("reason") or "").strip()[:800]
        if not wid or wid in seen:
            continue
        seen.add(wid)
        classifications.append(
            JudgeClassification(weakness_id=wid, verdict=verdict or "absent", reason=why)
        )
        if verdict:
            notes.append(f"{wid}={verdict}" + (f" ({why})" if why else ""))
        if wid in STATIC_ONLY_IDS:
            continue
        if wid not in RUNTIME_EMITTABLE:
            continue
        if verdict == "runtime_confirmed":
            confirmed.append(wid)
        elif verdict == "runtime_only":
            runtime_only.append(wid)

    confirmed = _uniq(confirmed)
    runtime_only = _uniq(runtime_only)
    kept = set(confirmed) | set(runtime_only)
    mismatches = [
        item
        for item in verification.mismatches
        if _keep_mismatch(item, kept)
    ]
    reason = verification.reason
    if notes:
        reason = f"{reason} | judge: {'; '.join(notes)}"
        if not any(
            n.split("=", 1)[-1].split(" ", 1)[0] in EMIT_VERDICTS
            for n in notes
            if "=" in n
        ):
            if "no runtime findings" not in reason:
                reason = f"{reason}; emitter: no runtime findings"
    return verification.model_copy(
        update={
            "confirmed_weakness_ids": confirmed,
            "runtime_only_weakness_ids": runtime_only,
            "mismatches": mismatches,
            "reason": reason,
            "policy_type": "text",
            "judge_classifications": classifications,
        }
    )


def apply_judge_actions(
    verification: PostExecutionVerification,
    payload: dict[str, Any],
    *,
    candidates: list[dict[str, str]] | None = None,
) -> PostExecutionVerification:
    """Compatibility wrapper: prefer ``classifications``, else ignore old actions."""
    _ = candidates
    if isinstance(payload.get("classifications"), list):
        return apply_classifications(verification, payload)
    return verification


def candidates_from(verification: PostExecutionVerification) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for wid in verification.confirmed_weakness_ids:
        items.append({"candidate_id": f"confirmed:{wid}", "bucket": "confirmed", "weakness_id": wid})
    for wid in verification.runtime_only_weakness_ids:
        items.append({"candidate_id": f"runtime_only:{wid}", "bucket": "runtime_only", "weakness_id": wid})
    return items


def _keep_mismatch(item: DeclaredVsObservedMismatch, kept_ids: set[str]) -> bool:
    if not item.observed or not item.weakness_id:
        return True
    return item.weakness_id in kept_ids


def _uniq(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _ask_llm(
    verification: PostExecutionVerification,
    tree: ToolBehaviorTree,
    profile: ExpectedBehaviorProfile,
    *,
    session: AuditSession,
    schema: dict[str, Any] | None,
    execution_result: Any,
    static_report: StaticReport | None = None,
) -> Optional[dict[str, Any]]:
    try:
        from mcpaegis.llm.client import LLMClient
        from mcpaegis.llm.prompts import build_judge_prompt
    except Exception:
        return None
    from mcpaegis.dynamic.post_execution_verifier import observed_capabilities

    tool_meta, tool_findings, server_findings = _static_context(static_report, tree.tool_name)
    observed = sorted(cap.value for cap in observed_capabilities(tree))
    prompt = build_judge_prompt(
        tool_name=tree.tool_name,
        call_id=verification.call_id,
        schema=schema or {},
        arguments=tree.arguments,
        expected_profile=_profile_blob(profile),
        verification={
            "decision": verification.decision,
            "reason": verification.reason,
            "confirmed_weakness_ids": verification.confirmed_weakness_ids,
            "runtime_only_weakness_ids": verification.runtime_only_weakness_ids,
            "mismatches": [item.model_dump(mode="json") for item in verification.mismatches],
        },
        process_tree=_compact_tree(tree),
        dns_events=[_compact_event(evt) for evt in tree.dns_branch],
        execution_result=_truncate(execution_result),
        tool_metadata=tool_meta,
        static_findings=tool_findings,
        server_static_findings=server_findings,
        declared_capabilities=[item.value for item in profile.declared_capabilities],
        code_capabilities=[item.value for item in profile.code_capabilities],
        observed_capabilities=observed,
        known_flags=list(profile.known_flags),
        sink_refs=list(profile.sink_refs),
    )
    try:
        client = LLMClient.from_session(session)
        parsed = client.complete_json(prompt=prompt)
    except Exception as exc:  # noqa: BLE001
        logger.warning("runtime judge skipped: %s", exc)
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _static_context(
    report: StaticReport | None, tool_name: str
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    if report is None:
        return None, [], []
    tool = next((item for item in report.server.tools if item.name == tool_name), None)
    metadata = (
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "source_location": tool.source_location.model_dump(mode="json") if tool.source_location else None,
        }
        if tool is not None
        else None
    )
    tool_findings: list[dict[str, Any]] = []
    for flag in report.poisoning_flags:
        if flag.tool_name == tool_name:
            tool_findings.append(
                {
                    "weakness_id": flag.weakness_id,
                    "pattern": flag.pattern_matched,
                    "snippet": flag.snippet,
                    "severity": flag.severity,
                }
            )
    for flag in report.shadowing_flags:
        if flag.tool_name == tool_name:
            tool_findings.append(
                {
                    "weakness_id": flag.weakness_id,
                    "conflicting_tool_name": flag.conflicting_tool_name,
                    "reason": flag.reason,
                }
            )
    for item in report.cross_check_findings:
        if item.tool_name == tool_name:
            tool_findings.append(
                {
                    "weakness_id": item.weakness_id,
                    "direction": item.direction,
                    "severity": item.severity,
                    "missing_from_declared": [cap.value for cap in item.missing_from_declared],
                    "missing_from_code": [cap.value for cap in item.missing_from_code],
                }
            )
    for item in report.access_control_findings:
        if item.tool_name == tool_name:
            tool_findings.append(
                {
                    "weakness_id": item.weakness_id,
                    "sink_ref": item.sink_ref,
                    "reason": item.reason,
                    "severity": item.severity,
                }
            )
    for item in report.injection_findings:
        if item.tool_name == tool_name:
            tool_findings.append(
                {
                    "weakness_id": item.weakness_id,
                    "sink_type": item.sink_type.value,
                    "file": item.file,
                    "line": item.line,
                    "snippet": item.snippet,
                    "confidence": item.confidence,
                }
            )
    sinks = [
        {
            "id": sink.id,
            "sink_type": sink.sink_type.value,
            "file": sink.file,
            "line": sink.line,
            "function_name": sink.function_name,
            "confidence": sink.confidence,
            "snippet": sink.snippet,
        }
        for sink in report.sink_facts
        if sink.tool_name == tool_name
    ]
    if sinks:
        tool_findings.append({"sink_facts": sinks})
    server_findings = [
        {
            "weakness_id": item.weakness_id,
            "package_name": item.package_name,
            "installed_version": item.installed_version,
            "cve_id": item.cve_id,
            "severity": item.severity,
        }
        for item in report.dependency_findings
    ]
    server_findings.extend(
        {
            "weakness_id": item.weakness_id,
            "file": item.file,
            "line": item.line,
            "pattern": item.pattern,
            "snippet": item.snippet,
        }
        for item in report.static_credential_findings
    )
    return metadata, tool_findings, server_findings


def _profile_blob(profile: ExpectedBehaviorProfile) -> dict[str, Any]:
    return {
        "tool_name": profile.tool_name,
        "declared_capabilities": [item.value for item in profile.declared_capabilities],
        "code_capabilities": [item.value for item in profile.code_capabilities],
        "known_flags": list(profile.known_flags),
        "sink_refs": list(profile.sink_refs),
    }


def _compact_tree(tree: ToolBehaviorTree) -> dict[str, Any]:
    return {
        "call_id": tree.call_id,
        "tool_name": tree.tool_name,
        "arguments": tree.arguments,
        "process_branch": [_compact_node(node) for node in tree.process_branch],
    }


def _compact_node(node: ProcessNode) -> dict[str, Any]:
    return {
        "pid": node.pid,
        "comm": node.comm,
        "argv": node.argv,
        "files": [_compact_event(evt) for evt in node.file_events],
        "nets": [_compact_event(evt) for evt in node.net_events],
        "children": [_compact_node(child) for child in node.children],
    }


def _compact_event(evt: Any) -> dict[str, Any]:
    details = getattr(evt, "details", None) or {}
    if not isinstance(details, dict):
        details = {}
    return {
        "kind": getattr(getattr(evt, "kind", None), "value", getattr(evt, "kind", None)),
        "path": details.get("path"),
        "dest": details.get("dest") or details.get("ip") or details.get("host"),
        "dest_port": details.get("dest_port"),
        "comm": details.get("comm"),
    }


def _truncate(value: Any, *, limit: int = 4000) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        text = __import__("json").dumps(value, default=str)
        if len(text) <= limit:
            return value
        return text[:limit]
    text = str(value)
    return text if len(text) <= limit else text[:limit]
