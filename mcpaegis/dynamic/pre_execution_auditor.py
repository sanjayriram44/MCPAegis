"""Dangerous-dispatch gate: regex on argument values; deny skips tools/call."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from mcpaegis.core.models import PreExecutionAuditResult
from mcpaegis.core.session import AuditSession

SENSITIVE_PATH_PATTERNS = (
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/sudoers",
    r"/etc/ssh/",
    r"\.ssh/",
    r"id_rsa",
    r"id_ed25519",
    r"\.aws/credentials",
    r"\.aws/config",
    r"/proc/1/",
    r"/root/",
)

DANGEROUS_SHELL_PATTERNS = (
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=",
    r"curl\s+[^\n]*\|\s*(ba)?sh",
    r"wget\s+[^\n]*\|\s*(ba)?sh",
    r":\(\)\s*\{\s*:\|:&\s*\};:",
    r"chmod\s+-R\s+777",
    r"chown\s+-R\s+root",
)


def audit(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    call_id: str,
    schema: Mapping[str, Any] | None = None,
    task_context: str | None = None,
    session: AuditSession | None = None,
) -> PreExecutionAuditResult:
    """Code-only kill switch. Deny is not a weakness ID."""
    _ = schema, session
    now = datetime.now(timezone.utc)
    reason = _code_policy_violation(tool_name, arguments, task_context=task_context)
    if reason:
        return PreExecutionAuditResult(
            call_id=call_id,
            tool_name=tool_name,
            decision="deny",
            policy_type="code",
            reason=reason,
            evaluated_at=now,
        )
    return PreExecutionAuditResult(
        call_id=call_id,
        tool_name=tool_name,
        decision="allow",
        policy_type="code",
        reason="code policies passed",
        evaluated_at=now,
    )


def strip_schema_descriptions(schema: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a copy of JSON Schema with description fields removed."""
    return _strip_descriptions(schema or {})


def _strip_descriptions(node: Any) -> Any:
    if isinstance(node, Mapping):
        return {k: _strip_descriptions(v) for k, v in node.items() if k != "description"}
    if isinstance(node, list):
        return [_strip_descriptions(item) for item in node]
    return node


def _code_policy_violation(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    task_context: str | None,
) -> str | None:
    blob = json.dumps(dict(arguments), default=str)
    lowered = blob.lower()
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return f"code policy deny: argument matches sensitive path {pattern}"
    for pattern in DANGEROUS_SHELL_PATTERNS:
        if re.search(pattern, blob, flags=re.IGNORECASE):
            return f"code policy deny: dangerous shell pattern {pattern}"
    if task_context and task_context.strip() and task_context.strip().upper() != "N/A":
        urls = re.findall(r"https?://[^\s\"']+", blob, flags=re.IGNORECASE)
        task_l = task_context.lower()
        for url in urls:
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
            if host and host not in task_l and "http" not in task_l and "url" not in task_l:
                return f"code policy deny: off-task URL {url}"
    _ = tool_name
    return None
