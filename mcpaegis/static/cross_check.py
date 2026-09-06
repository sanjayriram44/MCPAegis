"""W3 join: declared vs code capability cross-check."""

from __future__ import annotations

from collections import defaultdict

from mcpaegis.core.models import CodeCapability, CrossCheckFinding, DeclaredCapability, SinkFact
from mcpaegis.core.taxonomy import Capability, Weakness
from mcpaegis.static.taint.semgrep_runner import max_confidence_by_tool_capability

HIGH_UNDERDECLARED = {
    Capability.SHELL_EXEC,
    Capability.CREDENTIAL_HANDLING,
    Capability.NET_OUTBOUND,
}


def check(
    declared: list[DeclaredCapability],
    code: list[CodeCapability],
    sinks: list[SinkFact] | None = None,
) -> list[CrossCheckFinding]:
    declared_map: dict[str, set[Capability]] = defaultdict(set)
    for item in declared:
        if item.capability is Capability.BENIGN_UTILITY:
            continue
        declared_map[item.tool_name].add(item.capability)

    code_map: dict[str, set[Capability]] = defaultdict(set)
    for item in code:
        code_map[item.tool_name].add(item.capability)

    confidence = max_confidence_by_tool_capability(sinks or [])

    tools = sorted(set(declared_map) | set(code_map))
    findings: list[CrossCheckFinding] = []
    for tool in tools:
        declared_caps = declared_map.get(tool, set())
        code_caps = code_map.get(tool, set())
        missing_from_declared = sorted(code_caps - declared_caps, key=lambda c: c.value)
        missing_from_code = sorted(declared_caps - code_caps, key=lambda c: c.value)
        declared_list = sorted(declared_caps, key=lambda c: c.value)
        code_list = sorted(code_caps, key=lambda c: c.value)

        if missing_from_declared:
            findings.append(
                CrossCheckFinding(
                    tool_name=tool,
                    weakness_id="W3",
                    direction="under_declared",
                    declared_capabilities=declared_list,
                    code_capabilities=code_list,
                    missing_from_declared=missing_from_declared,
                    missing_from_code=[],
                    severity=_underdeclared_severity(tool, missing_from_declared, confidence),
                )
            )
        if missing_from_code:
            findings.append(
                CrossCheckFinding(
                    tool_name=tool,
                    weakness_id="W3",
                    direction="over_declared",
                    declared_capabilities=declared_list,
                    code_capabilities=code_list,
                    missing_from_declared=[],
                    missing_from_code=missing_from_code,
                    severity="LOW",
                )
            )
    return findings


def _underdeclared_severity(
    tool: str,
    missing: list[Capability],
    confidence: dict[tuple[str, Capability], str],
) -> str:
    high_caps = [cap for cap in missing if cap in HIGH_UNDERDECLARED]
    if not high_caps:
        return "MEDIUM"
    if any(confidence.get((tool, cap)) == "direct" for cap in high_caps):
        return "HIGH"
    return "MEDIUM"


_ = Weakness
