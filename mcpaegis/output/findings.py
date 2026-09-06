"""Normalize static, dynamic, and combined findings for SARIF/markdown/HTML."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from pydantic import BaseModel

from mcpaegis.core.models import (
    AccessControlFinding,
    CombinedFinding,
    CombinedReport,
    CombinedToolReport,
    CrossCheckFinding,
    DependencyFinding,
    DynamicReport,
    InjectionFinding,
    PoisoningFlag,
    RuntimeFinding,
    ShadowingFlag,
    StaticCredentialFinding,
    StaticReport,
)
from mcpaegis.core.taxonomy import Capability, Weakness

ReportLike = StaticReport | DynamicReport | CombinedReport
FindingLike = (
    PoisoningFlag
    | ShadowingFlag
    | CrossCheckFinding
    | AccessControlFinding
    | DependencyFinding
    | StaticCredentialFinding
    | InjectionFinding
    | RuntimeFinding
    | CombinedFinding
)

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

WEAKNESS_TITLES: dict[str, str] = {
    Weakness.W1_TOOL_POISONING.value: "Tool Poisoning",
    Weakness.W2_TOOL_SHADOWING.value: "Tool Shadowing",
    Weakness.W3_RUG_PULL.value: "Rug Pull",
    Weakness.W4_OVERPRIVILEGED.value: "Over-privileged / Capability Mismatch",
    Weakness.W5_SUPPLY_CHAIN.value: "Supply Chain Vulnerability",
    Weakness.W6_COMMAND_INJECTION.value: "Command / SQL Injection",
    Weakness.W7_PATH_TRAVERSAL.value: "Path Traversal",
    Weakness.W9_SSRF.value: "Server-Side Request Forgery",
    Weakness.W10_SCHEMA_BYPASS.value: "Schema Bypass",
    Weakness.W11_ACCESS_CONTROL.value: "Missing Access Control",
    Weakness.W12_TOOL_EXEC_HIJACK.value: "Tool Execution Hijack",
    Weakness.W13_INDIRECT_PROMPT_INJECTION.value: "Indirect Prompt Injection",
    Weakness.W14_STATIC_CRED_EXPOSURE.value: "Static Credential Exposure",
    Weakness.W15_RUNTIME_CRED_LEAKAGE.value: "Runtime Credential Leakage",
    Weakness.W16_CONTEXT_OVERSHARING.value: "Context Oversharing",
    Weakness.W17_HOST_SIDE_ATTACKS.value: "Host-Side Attacks",
}

SEVERITY_RANK: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_DEFAULT_SEVERITY: dict[str, Severity] = {
    "W1": "HIGH",
    "W2": "MEDIUM",
    "W4": "MEDIUM",
    "W5": "HIGH",
    "W6": "HIGH",
    "W7": "HIGH",
    "W9": "HIGH",
    "W11": "MEDIUM",
    "W12": "HIGH",
    "W13": "HIGH",
    "W14": "HIGH",
    "W15": "CRITICAL",
}


def weakness_title(weakness_id: str) -> str:
    return WEAKNESS_TITLES.get(weakness_id, weakness_id)


def format_capability(cap: Capability | str) -> str:
    if isinstance(cap, Capability):
        return f"{cap.name} ({cap.value})"
    try:
        parsed = Capability(cap)
    except ValueError:
        return str(cap)
    return f"{parsed.name} ({parsed.value})"


def format_capabilities(caps: Iterable[Capability | str]) -> str:
    items = [format_capability(c) for c in caps]
    return ", ".join(items) if items else "(none)"


@dataclass
class FindingRecord:
    """Writer-facing view of a single finding."""

    weakness_id: str
    severity: Severity
    message: str
    tool_name: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    function_name: Optional[str] = None
    snippet: Optional[str] = None
    confidence: Optional[str] = None
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return weakness_title(self.weakness_id)

    @property
    def rule_name(self) -> str:
        return f"{self.weakness_id} — {self.title}"


def _severity_for(weakness_id: str, explicit: str | None = None) -> Severity:
    if explicit in SEVERITY_RANK:
        return explicit  # type: ignore[return-value]
    return _DEFAULT_SEVERITY.get(weakness_id, "MEDIUM")


def _from_poisoning(item: PoisoningFlag) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=(
            f"Tool {item.tool_name!r} description/schema matched poisoning "
            f"pattern {item.pattern_matched!r} ({item.detection_tier})."
        ),
        tool_name=item.tool_name,
        snippet=item.snippet,
        confidence=str(item.confidence),
        properties={
            "pattern_matched": item.pattern_matched,
            "detection_tier": item.detection_tier,
        },
    )


def _from_shadowing(item: ShadowingFlag) -> FindingRecord:
    conflict = item.conflicting_tool_name
    server = f" (server {item.conflicting_server})" if item.conflicting_server else ""
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id),
        message=(
            f"Tool {item.tool_name!r} shadows {conflict!r}{server}: {item.reason} "
            f"(similarity {item.similarity_score:.2f})."
        ),
        tool_name=item.tool_name,
        confidence=str(item.similarity_score),
        properties={
            "conflicting_tool_name": item.conflicting_tool_name,
            "conflicting_server": item.conflicting_server,
            "similarity_score": item.similarity_score,
            "reason": item.reason,
        },
    )


def _from_cross_check(item: CrossCheckFinding) -> FindingRecord:
    direction = item.direction.replace("_", " ")
    missing_decl = format_capabilities(item.missing_from_declared)
    missing_code = format_capabilities(item.missing_from_code)
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=(
            f"Tool {item.tool_name!r} is {direction}: "
            f"missing from declared [{missing_decl}]; "
            f"missing from code [{missing_code}]."
        ),
        tool_name=item.tool_name,
        properties={
            "direction": item.direction,
            "declared_capabilities": [c.value for c in item.declared_capabilities],
            "code_capabilities": [c.value for c in item.code_capabilities],
            "missing_from_declared": [c.value for c in item.missing_from_declared],
            "missing_from_code": [c.value for c in item.missing_from_code],
        },
    )


def _from_access(item: AccessControlFinding) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=f"Tool {item.tool_name!r} privileged sink {item.sink_ref} has no auth check: {item.reason}",
        tool_name=item.tool_name,
        properties={"sink_ref": item.sink_ref, "reason": item.reason, "severity": item.severity},
    )


def _from_dependency(item: DependencyFinding) -> FindingRecord:
    cve = f" ({item.cve_id})" if item.cve_id else ""
    rng = f" vulnerable range {item.vulnerable_range}" if item.vulnerable_range else ""
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=(
            f"Package {item.package_name}@{item.installed_version}{cve}{rng} "
            f"reported by {item.source_tool}."
        ),
        properties={
            "package_name": item.package_name,
            "installed_version": item.installed_version,
            "vulnerable_range": item.vulnerable_range,
            "cve_id": item.cve_id,
            "source_tool": item.source_tool,
        },
    )


def _from_injection(item: InjectionFinding) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=(
            f"Tool {item.tool_name!r} has a dataflow-confirmed {item.sink_type.value} "
            f"path into {item.file}:{item.line} ({item.weakness_id})."
        ),
        tool_name=item.tool_name,
        file=item.file,
        line=item.line,
        snippet=item.snippet,
        confidence=item.confidence,
        properties={
            "sink_ref": item.sink_ref,
            "sink_type": item.sink_type.value,
            "confidence": item.confidence,
        },
    )


def _from_credential(item: StaticCredentialFinding) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id),
        message=f"Possible hardcoded secret ({item.pattern}) at {item.file}:{item.line}.",
        file=item.file,
        line=item.line,
        snippet=item.snippet,
        properties={"pattern": item.pattern},
    )


def _from_runtime(item: RuntimeFinding) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=item.description,
        tool_name=item.tool_name,
        confidence=item.status,
        properties={
            "call_id": item.call_id,
            "status": item.status,
            "evidence_refs": item.evidence_refs,
        },
    )


def _from_combined(item: CombinedFinding, tool_name: str | None = None) -> FindingRecord:
    return FindingRecord(
        weakness_id=item.weakness_id,
        severity=_severity_for(item.weakness_id, item.severity),
        message=item.description,
        tool_name=tool_name,
        confidence=item.confidence_tier,
        properties={
            "confidence_tier": item.confidence_tier,
            "evidence": item.evidence,
        },
    )


def finding_from_model(item: FindingLike | FindingRecord, *, tool_name: str | None = None) -> FindingRecord:
    if isinstance(item, FindingRecord):
        return item
    if isinstance(item, PoisoningFlag):
        return _from_poisoning(item)
    if isinstance(item, ShadowingFlag):
        return _from_shadowing(item)
    if isinstance(item, CrossCheckFinding):
        return _from_cross_check(item)
    if isinstance(item, AccessControlFinding):
        return _from_access(item)
    if isinstance(item, DependencyFinding):
        return _from_dependency(item)
    if isinstance(item, StaticCredentialFinding):
        return _from_credential(item)
    if isinstance(item, InjectionFinding):
        return _from_injection(item)
    if isinstance(item, RuntimeFinding):
        return _from_runtime(item)
    if isinstance(item, CombinedFinding):
        return _from_combined(item, tool_name=tool_name)
    raise TypeError(f"unsupported finding type: {type(item)!r}")


def collect_static_findings(report: StaticReport) -> list[FindingRecord]:
    records: list[FindingRecord] = []
    records.extend(finding_from_model(x) for x in report.poisoning_flags)
    records.extend(finding_from_model(x) for x in report.shadowing_flags)
    records.extend(finding_from_model(x) for x in report.cross_check_findings)
    records.extend(finding_from_model(x) for x in report.access_control_findings)
    records.extend(finding_from_model(x) for x in report.dependency_findings)
    records.extend(finding_from_model(x) for x in report.static_credential_findings)
    records.extend(finding_from_model(x) for x in report.injection_findings)
    return records


def collect_dynamic_findings(report: DynamicReport) -> list[FindingRecord]:
    return [finding_from_model(x) for x in report.runtime_findings]


def collect_combined_findings(report: CombinedReport) -> list[FindingRecord]:
    records: list[FindingRecord] = []
    for tool in report.tools:
        records.extend(finding_from_model(f, tool_name=tool.tool_name) for f in tool.findings)
    return records


def collect_findings(
    source: (
        ReportLike
        | CombinedToolReport
        | Sequence[FindingLike | FindingRecord]
        | FindingLike
        | FindingRecord
    ),
) -> list[FindingRecord]:
    if isinstance(source, StaticReport):
        return collect_static_findings(source)
    if isinstance(source, DynamicReport):
        return collect_dynamic_findings(source)
    if isinstance(source, CombinedReport):
        return collect_combined_findings(source)
    if isinstance(source, CombinedToolReport):
        return [finding_from_model(f, tool_name=source.tool_name) for f in source.findings]
    if isinstance(source, Sequence) and not isinstance(source, (str, bytes, BaseModel)):
        return [finding_from_model(item) for item in source]
    return [finding_from_model(source)]  # type: ignore[arg-type]


def filter_findings(
    records: Sequence[FindingRecord],
    categories: frozenset[Weakness] | Iterable[str] | None,
) -> list[FindingRecord]:
    if categories is None:
        return list(records)
    allowed = {c.value if isinstance(c, Weakness) else str(c) for c in categories}
    return [r for r in records if r.weakness_id in allowed]


def sort_findings(records: Sequence[FindingRecord]) -> list[FindingRecord]:
    return sorted(
        records,
        key=lambda r: (-SEVERITY_RANK.get(r.severity, 0), r.weakness_id, r.tool_name or "", r.message),
    )
