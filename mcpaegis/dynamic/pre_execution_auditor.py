"""Stage 2: code-policy then optional LLM text-policy; deny skips dispatch."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

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

DEFAULT_PRE_SYSTEM = """You are a security policy engine for MCP tool calls.
Decide ALLOW or DENY. Deny if arguments request sensitive host files, shell
execution that could escape the task, exfiltration, or off-task privileged
actions. Reply with a single line: ALLOW or DENY, then a short reason."""


def audit(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    call_id: str,
    schema: Mapping[str, Any] | None = None,
    task_context: str | None = None,
    session: AuditSession | None = None,
) -> PreExecutionAuditResult:
    """Evaluate code policies first; optional LLM only if they pass."""
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

    llm_decision = _text_policy(
        tool_name,
        arguments,
        schema=schema,
        task_context=task_context,
        session=session,
    )
    if llm_decision is not None:
        decision, reason = llm_decision
        return PreExecutionAuditResult(
            call_id=call_id,
            tool_name=tool_name,
            decision=decision,
            policy_type="text",
            reason=reason,
            evaluated_at=now,
        )

    return PreExecutionAuditResult(
        call_id=call_id,
        tool_name=tool_name,
        decision="allow",
        policy_type="code",
        reason="code policies passed; LLM text policy skipped or unavailable",
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
        # Off-task: arguments mention a host/url that the task never mentioned.
        urls = re.findall(r"https?://[^\s\"']+", blob, flags=re.IGNORECASE)
        task_l = task_context.lower()
        for url in urls:
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
            if host and host not in task_l and "http" not in task_l and "url" not in task_l:
                return f"code policy deny: off-task URL {url}"
    _ = tool_name
    return None


def _text_policy(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    schema: Mapping[str, Any] | None,
    task_context: str | None,
    session: AuditSession | None,
) -> Optional[tuple[str, str]]:
    if session is None or not session.llm.enabled:
        return None
    system, user_tmpl = _prompt_templates()
    user = user_tmpl.format(
        task=task_context or "N/A",
        tool_name=tool_name,
        schema=json.dumps(strip_schema_descriptions(schema), indent=2, default=str),
        arguments=json.dumps(dict(arguments), indent=2, default=str),
    )
    text = _complete(session, system, user)
    if text is None:
        return None
    upper = text.upper()
    if "DENY" in upper.splitlines()[0] or upper.strip().startswith("DENY"):
        return "deny", text.strip()[:500]
    if "ALLOW" in upper.splitlines()[0] or upper.strip().startswith("ALLOW"):
        return "allow", text.strip()[:500]
    if "DENY" in upper:
        return "deny", text.strip()[:500]
    return "allow", text.strip()[:500]


def _prompt_templates() -> tuple[str, str]:
    try:
        from mcpaegis.llm import prompts as prompt_mod
    except Exception:
        prompt_mod = None
    system = DEFAULT_PRE_SYSTEM
    user = (
        "Task: {task}\nTool: {tool_name}\nSchema (descriptions stripped):\n{schema}\n"
        "Arguments:\n{arguments}\nDecide ALLOW or DENY."
    )
    if prompt_mod is not None:
        system = getattr(prompt_mod, "PRE_EXECUTION_SYSTEM", None) or getattr(
            prompt_mod, "pre_execution_system", system
        )
        user = getattr(prompt_mod, "PRE_EXECUTION_USER", None) or getattr(
            prompt_mod, "pre_execution_user", user
        )
    return system, user


def _complete(session: AuditSession, system: str, user: str) -> str | None:
    try:
        from mcpaegis.llm.client import LLMClient
    except Exception:
        return None
    try:
        client = LLMClient()
    except TypeError:
        try:
            client = LLMClient(session.llm)  # type: ignore[call-arg]
        except Exception:
            return None
    except Exception:
        return None
    try:
        result = client.complete(system=system, user=user)
    except TypeError:
        try:
            result = client.complete(system, user)
        except Exception:
            return None
    except NotImplementedError:
        return None
    except Exception:
        return None
    if result is None:
        return None
    return str(result)
