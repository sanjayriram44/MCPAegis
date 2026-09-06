"""Wave 3: assemble StaticReport, ExpectedBehaviorProfile, and write outputs."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from mcpaegis.core.models import (
    AccessControlFinding,
    CodeCapability,
    CrossCheckFinding,
    DeclaredCapability,
    DependencyFinding,
    ExpectedBehaviorProfile,
    InjectionFinding,
    PoisoningFlag,
    ServerMetadata,
    ShadowingFlag,
    SinkFact,
    StaticCredentialFinding,
    StaticReport,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Capability, Weakness

STATIC_JSON = "static-report.json"
STATIC_SARIF = "static-report.sarif"
STATIC_MD = "static-report.md"


def build_profiles(
    tools: Iterable[str],
    *,
    declared: list[DeclaredCapability],
    code: list[CodeCapability],
    sinks: list[SinkFact],
    known_flags_by_tool: dict[str, list[str]],
) -> list[ExpectedBehaviorProfile]:
    declared_map: dict[str, list[Capability]] = defaultdict(list)
    for item in declared:
        if item.capability not in declared_map[item.tool_name]:
            declared_map[item.tool_name].append(item.capability)

    code_map: dict[str, list[Capability]] = defaultdict(list)
    sink_refs_from_code: dict[str, list[str]] = defaultdict(list)
    for item in code:
        if item.capability not in code_map[item.tool_name]:
            code_map[item.tool_name].append(item.capability)
        sink_refs_from_code[item.tool_name].extend(item.sink_refs)

    sink_map: dict[str, list[str]] = defaultdict(list)
    for sink in sinks:
        if sink.tool_name:
            sink_map[sink.tool_name].append(sink.id)

    names = sorted(set(tools) | set(declared_map) | set(code_map) | set(sink_map) | set(known_flags_by_tool))
    profiles: list[ExpectedBehaviorProfile] = []
    for name in names:
        refs = list(dict.fromkeys(sink_refs_from_code.get(name, []) or sink_map.get(name, [])))
        profiles.append(
            ExpectedBehaviorProfile(
                tool_name=name,
                declared_capabilities=declared_map.get(name, []),
                code_capabilities=code_map.get(name, []),
                sink_refs=refs,
                known_flags=list(dict.fromkeys(known_flags_by_tool.get(name, []))),
            )
        )
    return profiles


def collect_known_flags(
    *,
    poisoning: list[PoisoningFlag],
    shadowing: list[ShadowingFlag],
    cross: list[CrossCheckFinding],
    access: list[AccessControlFinding],
    credentials: list[StaticCredentialFinding],
    dependencies: list[DependencyFinding],
    injections: list[InjectionFinding] | None = None,
) -> dict[str, list[str]]:
    flags: dict[str, list[str]] = defaultdict(list)

    def add(tool: str, weakness: str) -> None:
        if weakness not in flags[tool]:
            flags[tool].append(weakness)

    for item in poisoning:
        add(item.tool_name, item.weakness_id)
    for item in shadowing:
        add(item.tool_name, item.weakness_id)
        add(item.conflicting_tool_name, item.weakness_id)
    for item in cross:
        add(item.tool_name, item.weakness_id)
    for item in access:
        add(item.tool_name, item.weakness_id)
    for item in injections or []:
        add(item.tool_name, item.weakness_id)
    if credentials:
        add("*", Weakness.W10_STATIC_CRED_EXPOSURE.value)
    if dependencies:
        add("*", Weakness.W4_SUPPLY_CHAIN.value)
    return flags


def assemble(
    server: ServerMetadata,
    *,
    poisoning_flags: list[PoisoningFlag],
    shadowing_flags: list[ShadowingFlag],
    declared_capabilities: list[DeclaredCapability],
    sink_facts: list[SinkFact],
    code_capabilities: list[CodeCapability],
    cross_check_findings: list[CrossCheckFinding],
    access_control_findings: list[AccessControlFinding],
    dependency_findings: list[DependencyFinding],
    static_credential_findings: list[StaticCredentialFinding],
    injection_findings: list[InjectionFinding] | None = None,
    scanned_at: datetime | None = None,
) -> StaticReport:
    tool_names = [t.name for t in server.tools]
    known = collect_known_flags(
        poisoning=poisoning_flags,
        shadowing=shadowing_flags,
        cross=cross_check_findings,
        access=access_control_findings,
        credentials=static_credential_findings,
        dependencies=dependency_findings,
        injections=injection_findings,
    )
    # Server-wide flags (W4/W10) attach to every tool profile as known context.
    global_flags = known.pop("*", [])
    for name in tool_names:
        for flag in global_flags:
            if flag not in known[name]:
                known[name].append(flag)

    profiles = build_profiles(
        tool_names,
        declared=declared_capabilities,
        code=code_capabilities,
        sinks=sink_facts,
        known_flags_by_tool=known,
    )
    return StaticReport(
        server=server,
        poisoning_flags=poisoning_flags,
        shadowing_flags=shadowing_flags,
        declared_capabilities=declared_capabilities,
        sink_facts=sink_facts,
        code_capabilities=code_capabilities,
        cross_check_findings=cross_check_findings,
        access_control_findings=access_control_findings,
        dependency_findings=dependency_findings,
        static_credential_findings=static_credential_findings,
        injection_findings=list(injection_findings or []),
        expected_behavior_profiles=profiles,
        scanned_at=scanned_at or datetime.now(timezone.utc),
    )


def write_reports(report: StaticReport, session: AuditSession) -> dict[str, Path]:
    """Write json/sarif/md using output writers when available, else JSON fallback."""
    session.output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    json_path = session.output_dir / STATIC_JSON
    _write_json(report, json_path, session)
    written["json"] = json_path

    fmt = (session.output_format or "json").lower()
    if fmt in {"sarif", "all"}:
        sarif_path = session.output_dir / STATIC_SARIF
        if _write_sarif(report, sarif_path, session):
            written["sarif"] = sarif_path
    if fmt in {"md", "markdown", "all"}:
        md_path = session.output_dir / STATIC_MD
        if _write_markdown(report, md_path, session):
            written["md"] = md_path
    # Always emit companion formats when writers succeed and format is json
    # so later `full` / `report` commands can pick them up. Best-effort only.
    if fmt == "json":
        sarif_path = session.output_dir / STATIC_SARIF
        if _write_sarif(report, sarif_path, session):
            written["sarif"] = sarif_path
        md_path = session.output_dir / STATIC_MD
        if _write_markdown(report, md_path, session):
            written["md"] = md_path
    return written


def build(
    server: ServerMetadata,
    *,
    session: AuditSession,
    poisoning_flags: list[PoisoningFlag],
    shadowing_flags: list[ShadowingFlag],
    declared_capabilities: list[DeclaredCapability],
    sink_facts: list[SinkFact],
    code_capabilities: list[CodeCapability],
    cross_check_findings: list[CrossCheckFinding],
    access_control_findings: list[AccessControlFinding],
    dependency_findings: list[DependencyFinding],
    static_credential_findings: list[StaticCredentialFinding],
    injection_findings: list[InjectionFinding] | None = None,
) -> StaticReport:
    report = assemble(
        server,
        poisoning_flags=poisoning_flags,
        shadowing_flags=shadowing_flags,
        declared_capabilities=declared_capabilities,
        sink_facts=sink_facts,
        code_capabilities=code_capabilities,
        cross_check_findings=cross_check_findings,
        access_control_findings=access_control_findings,
        dependency_findings=dependency_findings,
        static_credential_findings=static_credential_findings,
        injection_findings=injection_findings,
    )
    write_reports(report, session)
    return report


def _call_writer(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    try:
        fn(*args, **kwargs)
        return True
    except NotImplementedError:
        return False
    except TypeError:
        try:
            fn(*args)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _write_json(report: StaticReport, path: Path, session: AuditSession) -> None:
    try:
        from mcpaegis.output import json_writer

        writer = getattr(json_writer, "write", None)
        if callable(writer) and _call_writer(writer, report, path, session=session):
            if path.is_file():
                return
    except Exception:
        pass
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _write_sarif(report: StaticReport, path: Path, session: AuditSession) -> bool:
    try:
        from mcpaegis.output import sarif_writer

        writer = getattr(sarif_writer, "write", None)
        if callable(writer) and _call_writer(writer, report, path, session=session):
            return path.is_file()
    except Exception:
        pass
    return False


def _write_markdown(report: StaticReport, path: Path, session: AuditSession) -> bool:
    try:
        from mcpaegis.output import markdown_writer

        writer = getattr(markdown_writer, "write", None)
        if callable(writer) and _call_writer(writer, report, path, session=session):
            return path.is_file()
    except Exception:
        pass
    return False
