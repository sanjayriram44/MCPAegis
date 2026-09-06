"""Orchestrates static waves: discovery, parallel lanes, joins, report."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcpaegis.core.models import (
    DeclaredCapability,
    InjectionFinding,
    PoisoningFlag,
    ShadowingFlag,
    SinkFact,
    StaticReport,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.static import (
    access_control_check,
    advertisement,
    cross_check,
    discovery,
    injection_findings,
    inventory,
    metadata_classifier,
    report_builder,
)
from mcpaegis.static.taint import codeql_runner, semgrep_runner


def run(
    path: Path | str,
    session: AuditSession,
    *,
    extra_server_tools: list[tuple[str, object]] | None = None,
) -> StaticReport:
    """Discovery, then lanes A/B/C in parallel, then W3 join + W8, then report."""
    root = Path(path).resolve()
    server = discovery.discover(root)

    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_a = pool.submit(
            _lane_a,
            server.tools,
            session,
            extra_server_tools,
        )
        fut_b = pool.submit(_lane_b, root, server.tools, server.language, session)
        fut_c = pool.submit(inventory.scan, root, session)
        poisoning, shadowing, declared = fut_a.result()
        sink_facts, code_caps, injections = fut_b.result()
        cred_findings, dep_findings = fut_c.result()

    cross_findings = (
        cross_check.check(declared, code_caps, sinks=sink_facts)
        if session.uses_category(Weakness.W3_OVERPRIVILEGED)
        else []
    )
    access_findings = (
        access_control_check.check(sink_facts)
        if session.uses_category(Weakness.W8_ACCESS_CONTROL)
        else []
    )

    return report_builder.build(
        server,
        session=session,
        poisoning_flags=poisoning,
        shadowing_flags=shadowing,
        declared_capabilities=declared,
        sink_facts=sink_facts,
        code_capabilities=code_caps,
        cross_check_findings=cross_findings,
        access_control_findings=access_findings,
        dependency_findings=dep_findings,
        static_credential_findings=cred_findings,
        injection_findings=injections,
    )


def _lane_a(
    tools,
    session: AuditSession,
    extra_server_tools: list[tuple[str, object]] | None,
) -> tuple[list[PoisoningFlag], list[ShadowingFlag], list[DeclaredCapability]]:
    poisoning, declared = advertisement.classify(tools, session=session)
    if not session.uses_category(Weakness.W1_TOOL_POISONING):
        poisoning = []
    shadowing: list[ShadowingFlag] = []
    if session.uses_category(Weakness.W2_TOOL_SHADOWING):
        shadowing = metadata_classifier.shadowing_flags(
            tools,
            extra_tools=extra_server_tools,  # type: ignore[arg-type]
        )
    return poisoning, shadowing, declared


def _lane_b(
    root: Path,
    tools,
    language: str,
    session: AuditSession,
) -> tuple[list[SinkFact], list, list[InjectionFinding]]:
    sink_facts = semgrep_runner.run(root, tools, language=language)
    sink_facts.extend(codeql_runner.run(root, tools, language=language))
    code_caps = semgrep_runner.derive_code_capabilities(sink_facts)
    injections = injection_findings.from_sinks(sink_facts)
    injections = [item for item in injections if session.uses_category(item.weakness_id)]
    return sink_facts, code_caps, injections
