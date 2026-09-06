"""Merge StaticReport + optional DynamicReport into CombinedReport."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

from mcpaegis.core.models import (
    CombinedFinding,
    CombinedReport,
    CombinedToolReport,
    DynamicReport,
    StaticReport,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Capability
from mcpaegis.dynamic.post_execution_verifier import observed_capabilities
from mcpaegis.output import json_writer, markdown_writer, sarif_writer
from mcpaegis.output.findings import SEVERITY_RANK, collect_static_findings

COMBINED_JSON = "combined-report.json"
COMBINED_SARIF = "combined-report.sarif"
COMBINED_MD = "combined-report.md"

STATIC_REPORT_NAME = "static-report.json"
RUNTIME_REPORT_NAME = "runtime-report.json"

SERVER_WIDE_TOOL = "*"

ConfidenceTier = Literal["static_only", "runtime_confirmed", "runtime_only"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def merge(
    static_report: StaticReport | Path | str,
    dynamic_report: DynamicReport | Path | str | None = None,
    *,
    session: AuditSession | None = None,
    server_path: str | Path | None = None,
    static_report_ref: str | Path | None = None,
    dynamic_report_ref: str | Path | None = None,
    write_output: bool = True,
) -> CombinedReport:
    """Merge static findings with optional runtime findings.

    Each combined finding is tagged ``static_only``, ``runtime_confirmed``, or
    ``runtime_only``. When ``write_output`` is true, writes ``combined-report.json``
    plus SARIF and markdown via the existing output writers.
    """
    static = _coerce_static(static_report)
    dynamic = _coerce_dynamic(dynamic_report) if dynamic_report is not None else None
    session = session or (AuditSession.from_cli() if write_output else None)

    output_dir = session.output_dir if session is not None else Path.cwd()
    static_ref = str(
        static_report_ref
        if static_report_ref is not None
        else _default_ref(static_report, output_dir / STATIC_REPORT_NAME)
    )
    if dynamic is None:
        dynamic_ref: str | None = None
    else:
        dynamic_ref = str(
            dynamic_report_ref
            if dynamic_report_ref is not None
            else _default_ref(dynamic_report, output_dir / RUNTIME_REPORT_NAME)
        )

    path = _resolve_server_path(server_path, static, dynamic)
    report = CombinedReport(
        server_path=path,
        static_report_ref=static_ref,
        dynamic_report_ref=dynamic_ref,
        tools=_build_tools(static, dynamic, session),
        generated_at=datetime.now(timezone.utc),
    )
    if write_output:
        if session is None:
            session = AuditSession.from_cli()
        write_reports(report, session)
    return report


def write_reports(report: CombinedReport, session: AuditSession) -> dict[str, Path]:
    """Write combined-report.json plus SARIF and markdown companions."""
    session.output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    json_path = session.output_dir / COMBINED_JSON
    json_writer.write(report, json_path)
    written["json"] = json_path

    categories = session.categories
    sarif_path = session.output_dir / COMBINED_SARIF
    sarif_writer.write(report, sarif_path, categories=categories)
    written["sarif"] = sarif_path

    md_path = session.output_dir / COMBINED_MD
    markdown_writer.write(report, md_path, categories=categories)
    written["md"] = md_path
    return written


def _coerce_static(value: StaticReport | Path | str) -> StaticReport:
    if isinstance(value, StaticReport):
        return value
    loaded = json_writer.load_report(value)
    if not isinstance(loaded, StaticReport):
        raise TypeError(f"expected StaticReport, got {type(loaded).__name__}")
    return loaded


def _coerce_dynamic(value: DynamicReport | Path | str) -> DynamicReport:
    if isinstance(value, DynamicReport):
        return value
    loaded = json_writer.load_report(value)
    if not isinstance(loaded, DynamicReport):
        raise TypeError(f"expected DynamicReport, got {type(loaded).__name__}")
    return loaded


def _default_ref(source: object, fallback: Path) -> str:
    if isinstance(source, (str, Path)):
        return str(Path(source))
    return str(fallback)


def _resolve_server_path(
    server_path: str | Path | None,
    static: StaticReport,
    dynamic: DynamicReport | None,
) -> str:
    if server_path is not None:
        return str(Path(server_path))
    if dynamic is not None and dynamic.server_path:
        return dynamic.server_path
    if static.server.manifest_path:
        return str(Path(static.server.manifest_path).parent)
    return static.server.entrypoint


def _build_tools(
    static: StaticReport,
    dynamic: DynamicReport | None,
    session: AuditSession | None,
) -> list[CombinedToolReport]:
    declared_map = _declared_by_tool(static)
    code_map = _code_by_tool(static)
    observed_map = _observed_by_tool(dynamic) if dynamic is not None else {}
    findings_by_tool = _merge_findings(static, dynamic, session)

    names = _tool_names(static, dynamic, findings_by_tool)
    tools: list[CombinedToolReport] = []
    for name in names:
        tools.append(
            CombinedToolReport(
                tool_name=name,
                declared_capabilities=_uniq_caps(declared_map.get(name, [])),
                code_capabilities=_uniq_caps(code_map.get(name, [])),
                observed_capabilities=_uniq_caps(observed_map.get(name, [])),
                findings=findings_by_tool.get(name, []),
            )
        )
    return tools


def _tool_names(
    static: StaticReport,
    dynamic: DynamicReport | None,
    findings_by_tool: dict[str, list[CombinedFinding]],
) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name and name not in seen and name != SERVER_WIDE_TOOL:
            seen.add(name)
            ordered.append(name)

    for tool in static.server.tools:
        add(tool.name)
    for profile in static.expected_behavior_profiles:
        add(profile.tool_name)
    if dynamic is not None:
        for tree in dynamic.tool_behavior_trees:
            add(tree.tool_name)
        for finding in dynamic.runtime_findings:
            add(finding.tool_name)
    extras = sorted(n for n in findings_by_tool if n not in seen and n != SERVER_WIDE_TOOL)
    ordered.extend(extras)
    if SERVER_WIDE_TOOL in findings_by_tool:
        ordered.append(SERVER_WIDE_TOOL)
    elif not ordered and findings_by_tool:
        ordered.extend(sorted(findings_by_tool))
    return ordered


def _declared_by_tool(static: StaticReport) -> dict[str, list[Capability]]:
    by_tool: dict[str, list[Capability]] = defaultdict(list)
    for item in static.declared_capabilities:
        by_tool[item.tool_name].append(item.capability)
    for profile in static.expected_behavior_profiles:
        if profile.tool_name not in by_tool:
            by_tool[profile.tool_name].extend(profile.declared_capabilities)
    return by_tool


def _code_by_tool(static: StaticReport) -> dict[str, list[Capability]]:
    by_tool: dict[str, list[Capability]] = defaultdict(list)
    for item in static.code_capabilities:
        by_tool[item.tool_name].append(item.capability)
    for profile in static.expected_behavior_profiles:
        if profile.tool_name not in by_tool:
            by_tool[profile.tool_name].extend(profile.code_capabilities)
    return by_tool


def _observed_by_tool(dynamic: DynamicReport) -> dict[str, list[Capability]]:
    by_tool: dict[str, list[Capability]] = defaultdict(list)
    for tree in dynamic.tool_behavior_trees:
        by_tool[tree.tool_name].extend(observed_capabilities(tree))
    return by_tool


def _uniq_caps(caps: Iterable[Capability]) -> list[Capability]:
    seen: list[Capability] = []
    for cap in caps:
        if cap not in seen:
            seen.append(cap)
    return seen


def _merge_findings(
    static: StaticReport,
    dynamic: DynamicReport | None,
    session: AuditSession | None,
) -> dict[str, list[CombinedFinding]]:
    static_items = _static_items(static)
    runtime_items = _runtime_items(dynamic) if dynamic is not None else []

    grouped_static: dict[tuple[str, str], list[_FindingItem]] = defaultdict(list)
    grouped_runtime: dict[tuple[str, str], list[_FindingItem]] = defaultdict(list)
    for item in static_items:
        grouped_static[(item.tool_name, item.weakness_id)].append(item)
    for item in runtime_items:
        grouped_runtime[(item.tool_name, item.weakness_id)].append(item)

    keys = set(grouped_static) | set(grouped_runtime)
    by_tool: dict[str, list[CombinedFinding]] = defaultdict(list)
    for tool_name, weakness_id in sorted(keys, key=lambda k: (k[0], k[1])):
        if session is not None and not session.uses_category(weakness_id):
            continue
        static_group = grouped_static.get((tool_name, weakness_id), [])
        runtime_group = grouped_runtime.get((tool_name, weakness_id), [])
        by_tool[tool_name].extend(_combine_group(static_group, runtime_group))
    return by_tool


def _combine_group(
    static_group: Sequence[_FindingItem],
    runtime_group: Sequence[_FindingItem],
) -> list[CombinedFinding]:
    confirmed = [item for item in runtime_group if item.status == "confirmed"]
    runtime_only = [item for item in runtime_group if item.status == "runtime_only"]
    # ``unconfirmed_static_flag_stands`` leaves the static finding as static_only.
    combined: list[CombinedFinding] = []
    used_runtime: set[int] = set()

    for item in static_group:
        match = None
        for idx, runtime_item in enumerate(confirmed):
            if idx in used_runtime:
                continue
            if _same_sink(item, runtime_item):
                match = runtime_item
                used_runtime.add(idx)
                break
        if match is not None:
            combined.append(
                CombinedFinding(
                    weakness_id=item.weakness_id,
                    severity=_max_severity([item.severity, match.severity]),
                    confidence_tier="runtime_confirmed",
                    description=match.description or item.description,
                    evidence={
                        "static": item.evidence,
                        "runtime": [match.evidence],
                    },
                )
            )
        else:
            combined.append(
                CombinedFinding(
                    weakness_id=item.weakness_id,
                    severity=item.severity,  # type: ignore[arg-type]
                    confidence_tier="static_only",
                    description=item.description,
                    evidence={"static": item.evidence},
                )
            )

    for idx, item in enumerate(confirmed):
        if idx in used_runtime:
            continue
        combined.append(
            CombinedFinding(
                weakness_id=item.weakness_id,
                severity=item.severity,  # type: ignore[arg-type]
                confidence_tier="runtime_confirmed",
                description=item.description,
                evidence={"runtime": item.evidence},
            )
        )

    for item in runtime_only:
        combined.append(
            CombinedFinding(
                weakness_id=item.weakness_id,
                severity=item.severity,  # type: ignore[arg-type]
                confidence_tier="runtime_only",
                description=item.description,
                evidence={"runtime": item.evidence},
            )
        )
    return combined


def _sink_locations(item: "_FindingItem") -> set[str]:
    evidence = item.evidence or {}
    keys: set[str] = set()
    ref = evidence.get("sink_ref")
    if ref:
        keys.add(f"ref:{ref}")
    location = evidence.get("sink_location")
    if location:
        keys.add(f"loc:{location}")
    file = evidence.get("file")
    line = evidence.get("line")
    if file is not None and line is not None:
        keys.add(f"file:{file}:{line}")
    return keys


def _same_sink(static_item: "_FindingItem", runtime_item: "_FindingItem") -> bool:
    """Confirm only the exercised sink; weakness-level flags (no sink) still match 1:1."""
    static_locs = _sink_locations(static_item)
    runtime_locs = _sink_locations(runtime_item)
    if not static_locs and not runtime_locs:
        return True
    return bool(static_locs & runtime_locs)


def _max_severity(severities: Iterable[str]) -> Severity:
    best: Severity = "LOW"
    best_rank = 0
    for sev in severities:
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > best_rank:
            best_rank = rank
            best = sev  # type: ignore[assignment]
    return best


class _FindingItem:
    __slots__ = ("tool_name", "weakness_id", "severity", "description", "evidence", "status")

    def __init__(
        self,
        *,
        tool_name: str,
        weakness_id: str,
        severity: str,
        description: str,
        evidence: dict[str, Any],
        status: str | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.weakness_id = weakness_id
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.status = status


def _static_items(static: StaticReport) -> list[_FindingItem]:
    items: list[_FindingItem] = []
    for record in collect_static_findings(static):
        evidence: dict[str, Any] = dict(record.properties)
        if record.file:
            evidence["file"] = record.file
        if record.line is not None:
            evidence["line"] = record.line
        if record.snippet:
            evidence["snippet"] = record.snippet
        items.append(
            _FindingItem(
                tool_name=record.tool_name or SERVER_WIDE_TOOL,
                weakness_id=record.weakness_id,
                severity=record.severity,
                description=record.message,
                evidence=evidence,
            )
        )
    return items


def _runtime_items(dynamic: DynamicReport) -> list[_FindingItem]:
    items: list[_FindingItem] = []
    for finding in dynamic.runtime_findings:
        items.append(
            _FindingItem(
                tool_name=finding.tool_name or SERVER_WIDE_TOOL,
                weakness_id=finding.weakness_id,
                severity=finding.severity,
                description=finding.description,
                evidence={
                    "call_id": finding.call_id,
                    "status": finding.status,
                    **finding.evidence_refs,
                },
                status=finding.status,
            )
        )
    return items
