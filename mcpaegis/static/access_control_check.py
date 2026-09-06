"""W8: privileged sinks without an obvious auth check."""

from __future__ import annotations

import re

from mcpaegis.core.models import AccessControlFinding, SinkFact
from mcpaegis.core.taxonomy import SinkType

PRIVILEGED_SINKS = {
    SinkType.SHELL_EXEC,
    SinkType.FILE_WRITE,
    SinkType.DB_QUERY,
    SinkType.CREDENTIAL_READ,
}

AUTH_NAME_RE = re.compile(
    r"(check_permission|require_auth|requires_auth|is_authorized|verify_scope|"
    r"has_permission|authorize|authorise|authenticate|ensure_auth|assert_auth|"
    r"permission_required|login_required|acl_check|guard|can_access)",
    re.IGNORECASE,
)


def check(sinks: list[SinkFact]) -> list[AccessControlFinding]:
    """Shallow heuristic: look for auth-like names on the reverse taint path.

    False negatives are expected when checks use unusual names — acceptable for v1.
    Direct (dataflow-confirmed) privileged sinks are MEDIUM; proximate-only are LOW.
    """
    findings: list[AccessControlFinding] = []
    for sink in sinks:
        if sink.sink_type not in PRIVILEGED_SINKS:
            continue
        path_names = list(sink.taint_path or [])
        if sink.function_name:
            path_names.append(sink.function_name)
        if any(AUTH_NAME_RE.search(name or "") for name in path_names):
            continue
        tool = sink.tool_name or "<unattributed>"
        severity: str = "MEDIUM" if sink.confidence == "direct" else "LOW"
        findings.append(
            AccessControlFinding(
                tool_name=tool,
                weakness_id="W8",
                sink_ref=sink.id,
                reason=(
                    f"privileged sink {sink.sink_type.value} in {sink.function_name} "
                    f"({sink.file}:{sink.line}) has no auth-like function on the taint path "
                    f"{path_names or ['<empty>']}"
                ),
                severity=severity,  # type: ignore[arg-type]
            )
        )
    return findings
