"""Stage 4: declared-vs-observed comparison, W9 hijack shape, confirm static flags."""

from __future__ import annotations

import warnings
from typing import Any, Iterable, Sequence

from mcpaegis.core.models import (
    DeclaredVsObservedMismatch,
    ExpectedBehaviorProfile,
    PostExecutionVerification,
    ProcessNode,
    StaticReport,
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


def verify(
    tree: ToolBehaviorTree,
    profile: ExpectedBehaviorProfile | None,
    *,
    call_id: str | None = None,
    simplified: ToolBehaviorTree | None = None,
    raw: ToolBehaviorTree | None = None,
    session: AuditSession | None = None,
    task_context: str | None = None,
    schema: dict[str, Any] | None = None,
    execution_result: Any = None,
    static_report: StaticReport | None = None,
) -> PostExecutionVerification:
    """Compare observed capabilities on the (already filtered) behavior tree.

    ``simplified`` / ``raw`` are ignored aliases from the old two-tree API.
    When ``session.llm`` is enabled, the LLM emits runtime findings. Code
    verify is the fallback if the key is missing or the model fails.
    """
    _ = raw, task_context
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

    scored = simplified or tree
    observed = observed_capabilities(scored)
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

    code_reason = _raw_tree_policy(scored)
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
        if Weakness.W9_TOOL_EXEC_HIJACK.value not in runtime_only and Weakness.W9_TOOL_EXEC_HIJACK.value not in confirmed:
            runtime_only.append(Weakness.W9_TOOL_EXEC_HIJACK.value)

    result = PostExecutionVerification(
        call_id=call_id or tree.call_id,
        tool_name=tree.tool_name,
        decision=decision,  # type: ignore[arg-type]
        policy_type=policy_type,  # type: ignore[arg-type]
        mismatches=mismatches,
        confirmed_weakness_ids=confirmed,
        runtime_only_weakness_ids=runtime_only,
        reason=reason,
    )
    from mcpaegis.dynamic.runtime_judge import judge_verification

    return judge_verification(
        result,
        scored,
        profile,
        session=session,
        schema=schema,
        execution_result=execution_result,
        static_report=static_report,
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
    planted W5/W6/W7 case). Hijack (W9) is only for privileged behavior that
    static never attributed to the tool.
    """
    if cap == Capability.SHELL_EXEC and Weakness.W5_COMMAND_INJECTION.value in known:
        return Weakness.W5_COMMAND_INJECTION.value, "confirmed"
    if cap in {Capability.FS_READ, Capability.FS_WRITE} and Weakness.W6_PATH_TRAVERSAL.value in known:
        return Weakness.W6_PATH_TRAVERSAL.value, "confirmed"
    if cap == Capability.NET_OUTBOUND and Weakness.W7_SSRF.value in known:
        return Weakness.W7_SSRF.value, "confirmed"
    if not in_code and not in_declared and cap in PRIVILEGED_CAPS:
        return Weakness.W9_TOOL_EXEC_HIJACK.value, "runtime_only"
    if not in_code and Weakness.W3_OVERPRIVILEGED.value in known:
        return Weakness.W3_OVERPRIVILEGED.value, "confirmed"
    if not in_code:
        return Weakness.W3_OVERPRIVILEGED.value, "runtime_only"
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


