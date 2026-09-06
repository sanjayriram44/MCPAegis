"""Stage 4: declared-vs-observed comparison, W12 hijack shape, confirm static flags."""

from __future__ import annotations

import json
import warnings
from typing import Any, Iterable, Optional, Sequence

from mcpaegis.core.models import (
    DeclaredVsObservedMismatch,
    ExpectedBehaviorProfile,
    PostExecutionVerification,
    ProcessNode,
    ToolBehaviorTree,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Capability, RuntimeEventKind, Weakness

PRIVILEGED_CAPS = {
    Capability.SHELL_EXEC,
    Capability.CREDENTIAL_HANDLING,
    Capability.NET_OUTBOUND,
}

SENSITIVE_FILE_MARKERS = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/", "id_rsa")

DEFAULT_POST_SYSTEM = """You are verifying whether an MCP tool's runtime behavior matches
its declared/code capabilities. Reply ALLOW if consistent, DENY if the process
tree or DNS events show hijacking, unexpected shell, or data exfiltration.
Start with ALLOW or DENY, then a short reason."""


def verify(
    tree: ToolBehaviorTree,
    profile: ExpectedBehaviorProfile | None,
    *,
    call_id: str | None = None,
    simplified: ToolBehaviorTree | None = None,
    session: AuditSession | None = None,
    task_context: str | None = None,
    schema: dict[str, Any] | None = None,
) -> PostExecutionVerification:
    """Compare observed capabilities to the expected profile; optional LLM pass."""
    if profile is None:
        warnings.warn(
            "no static profile found — running without declared-vs-observed verification",
            UserWarning,
            stacklevel=2,
        )
        profile = ExpectedBehaviorProfile(
            tool_name=tree.tool_name,
            declared_capabilities=[],
            code_capabilities=[],
            sink_refs=[],
            known_flags=[],
        )

    observed = observed_capabilities(tree)
    declared = set(profile.declared_capabilities)
    code = set(profile.code_capabilities)
    known = set(profile.known_flags)

    mismatches: list[DeclaredVsObservedMismatch] = []
    confirmed: list[str] = []
    runtime_only: list[str] = []

    all_caps = set(observed) | declared | code
    for cap in sorted(all_caps, key=lambda item: item.value):
        is_obs = cap in observed
        in_code = cap in code
        in_declared = cap in declared
        if is_obs:
            weakness_id, bucket = _classify_observed_cap(
                cap, known=known, in_code=in_code, in_declared=in_declared
            )
            if bucket == "confirmed" and weakness_id:
                confirmed.append(weakness_id)
            elif bucket == "runtime_only" and weakness_id:
                runtime_only.append(weakness_id)
            if weakness_id or in_code != is_obs or in_declared != is_obs:
                mismatches.append(
                    DeclaredVsObservedMismatch(
                        capability=cap,
                        expected=in_code or in_declared,
                        observed=True,
                        weakness_id=weakness_id,
                    )
                )
        elif in_declared or in_code:
            mismatches.append(
                DeclaredVsObservedMismatch(
                    capability=cap,
                    expected=True,
                    observed=False,
                    weakness_id=None,
                )
            )

    confirmed = _uniq(confirmed)
    runtime_only = _uniq(runtime_only)

    code_reason = _raw_tree_policy(tree)
    decision = "allow"
    policy_type: str = "code"
    if confirmed:
        reason = (
            "runtime observed privileged behavior confirming static flags: "
            + ", ".join(confirmed)
        )
    else:
        reason = "observed behavior consistent with expected profile"
    if code_reason:
        decision = "deny"
        reason = code_reason
        if Weakness.W12_TOOL_EXEC_HIJACK.value not in runtime_only and Weakness.W12_TOOL_EXEC_HIJACK.value not in confirmed:
            runtime_only.append(Weakness.W12_TOOL_EXEC_HIJACK.value)

    llm = _text_policy(
        simplified or tree,
        profile,
        session=session,
        task_context=task_context,
        schema=schema,
    )
    if llm is not None and decision == "allow":
        policy_type = "text"
        llm_decision, llm_reason = llm
        decision = llm_decision
        reason = llm_reason
        if decision == "deny" and Weakness.W12_TOOL_EXEC_HIJACK.value not in runtime_only:
            runtime_only.append(Weakness.W12_TOOL_EXEC_HIJACK.value)

    return PostExecutionVerification(
        call_id=call_id or tree.call_id,
        tool_name=tree.tool_name,
        decision=decision,  # type: ignore[arg-type]
        policy_type=policy_type,  # type: ignore[arg-type]
        mismatches=mismatches,
        confirmed_weakness_ids=confirmed,
        runtime_only_weakness_ids=runtime_only,
        reason=reason,
    )


def _classify_observed_cap(
    cap: Capability,
    *,
    known: set[str],
    in_code: bool,
    in_declared: bool,
) -> tuple[str | None, str]:
    """Map an observed capability to a confirmed static flag or a runtime-only id.

    Confirmation must fire when the tree *matches* the static profile (the
    planted W6/W7/W9 case). Hijack (W12) is only for privileged behavior that
    static never attributed to the tool.
    """
    if cap == Capability.SHELL_EXEC and Weakness.W6_COMMAND_INJECTION.value in known:
        return Weakness.W6_COMMAND_INJECTION.value, "confirmed"
    if cap in {Capability.FS_READ, Capability.FS_WRITE} and Weakness.W7_PATH_TRAVERSAL.value in known:
        return Weakness.W7_PATH_TRAVERSAL.value, "confirmed"
    if cap == Capability.NET_OUTBOUND and Weakness.W9_SSRF.value in known:
        return Weakness.W9_SSRF.value, "confirmed"
    if not in_code and not in_declared and cap in PRIVILEGED_CAPS:
        return Weakness.W12_TOOL_EXEC_HIJACK.value, "runtime_only"
    if not in_code and Weakness.W4_OVERPRIVILEGED.value in known:
        return Weakness.W4_OVERPRIVILEGED.value, "confirmed"
    if not in_code:
        return Weakness.W4_OVERPRIVILEGED.value, "runtime_only"
    return None, ""


def observed_capabilities(tree: ToolBehaviorTree) -> set[Capability]:
    caps: set[Capability] = set()
    for node in _walk(tree.process_branch):
        if node.file_events:
            kinds = {evt.kind for evt in node.file_events}
            if kinds & {RuntimeEventKind.FILE_OPEN, RuntimeEventKind.FILE_READ}:
                caps.add(Capability.FS_READ)
            if kinds & {RuntimeEventKind.FILE_WRITE, RuntimeEventKind.FILE_UNLINK}:
                caps.add(Capability.FS_WRITE)
            for evt in node.file_events:
                path = str(evt.details.get("path") or "").lower()
                if any(marker in path for marker in ("password", "credential", ".env", "secret", "token", "id_rsa")):
                    caps.add(Capability.CREDENTIAL_HANDLING)
        if node.net_events:
            caps.add(Capability.NET_OUTBOUND)
            for evt in node.net_events:
                port = int(evt.details.get("dest_port") or 0)
                if port in {3306, 5432, 27017, 6379, 1521}:
                    caps.add(Capability.DB_ACCESS)
        if _looks_like_shell(node.comm, node.argv):
            caps.add(Capability.SHELL_EXEC)
        for child in node.children:
            if _looks_like_shell(child.comm, child.argv):
                caps.add(Capability.SHELL_EXEC)
    if tree.dns_branch:
        caps.add(Capability.NET_OUTBOUND)
    return caps


_INTERPRETER_COMMS = {"python", "python3", "node", "nodejs", "mcpaegis"}


def _looks_like_shell(comm: str, argv: str) -> bool:
    name = (comm or "").split("/")[-1].lower()
    blob = (argv or "").lower()
    if name in {"bash", "sh", "zsh", "dash", "cmd.exe", "powershell", "pwsh"}:
        return True
    if any(token in blob for token in ("/bin/sh", "/bin/bash", "cmd.exe", "powershell")):
        return True
    # shell=True often execs /usr/bin/echo (builtin fallback) rather than leaving
    # comm as "sh". Any non-interpreter binary path is still SHELL_EXEC.
    if name in _INTERPRETER_COMMS or not name:
        return False
    return blob.startswith("/") or name.endswith(".exe")


def _raw_tree_policy(tree: ToolBehaviorTree) -> str | None:
    for node in _walk(tree.process_branch):
        for evt in node.file_events:
            path = str(evt.details.get("path") or "")
            for marker in SENSITIVE_FILE_MARKERS:
                if marker in path:
                    return f"code policy deny: process touched sensitive path {path}"
    return None


def _walk(nodes: Sequence[ProcessNode]) -> Iterable[ProcessNode]:
    for node in nodes:
        yield node
        yield from _walk(node.children)


def _uniq(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _text_policy(
    tree: ToolBehaviorTree,
    profile: ExpectedBehaviorProfile,
    *,
    session: AuditSession | None,
    task_context: str | None,
    schema: dict[str, Any] | None,
) -> Optional[tuple[str, str]]:
    if session is None or not session.llm.enabled:
        return None
    try:
        from mcpaegis.llm import prompts as prompt_mod
    except Exception:
        prompt_mod = None
    system = DEFAULT_POST_SYSTEM
    user_tmpl = (
        "Task: {task}\nTool: {tool}\nSchema: {schema}\nArgs: {args}\n"
        "Declared caps: {declared}\nCode caps: {code}\n"
        "Process tree: {tree}\nDNS: {dns}\nDecide ALLOW or DENY."
    )
    if prompt_mod is not None:
        system = getattr(prompt_mod, "POST_EXECUTION_SYSTEM", None) or getattr(
            prompt_mod, "post_execution_system", system
        )
        user_tmpl = getattr(prompt_mod, "POST_EXECUTION_USER", None) or getattr(
            prompt_mod, "post_execution_user", user_tmpl
        )
    user = user_tmpl.format(
        task=task_context or "N/A",
        tool=tree.tool_name,
        schema=json.dumps(schema or {}, default=str)[:4000],
        args=json.dumps(tree.arguments, default=str)[:4000],
        declared=[c.value for c in profile.declared_capabilities],
        code=[c.value for c in profile.code_capabilities],
        tree=json.dumps(tree.model_dump(mode="json"), default=str)[:8000],
        dns=json.dumps([e.model_dump(mode="json") for e in tree.dns_branch], default=str)[:4000],
    )
    try:
        from mcpaegis.dynamic.pre_execution_auditor import _complete
    except Exception:
        return None
    text = _complete(session, system, user)
    if text is None:
        return None
    upper = text.upper()
    decision = "deny" if "DENY" in upper.splitlines()[0] or upper.strip().startswith("DENY") else "allow"
    if "DENY" in upper and "ALLOW" not in upper.splitlines()[0]:
        if upper.strip().startswith("DENY") or (upper.splitlines() and "DENY" in upper.splitlines()[0]):
            decision = "deny"
    return decision, text.strip()[:500]


