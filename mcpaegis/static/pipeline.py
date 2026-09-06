"""Orchestrates static stages 0–7 and produces a StaticReport."""

from __future__ import annotations

from pathlib import Path

from mcpaegis.core.models import StaticReport
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.static import (
    access_control_check,
    capability_classifier,
    credential_scanner,
    cross_check,
    discovery,
    injection_findings,
    metadata_classifier,
    report_builder,
    sca_scan,
)
from mcpaegis.static.taint import codeql_runner, semgrep_runner


def run(
    path: Path | str,
    session: AuditSession,
    *,
    extra_server_tools: list[tuple[str, object]] | None = None,
) -> StaticReport:
    """Run discovery → classify → taint → checks → SCA → reports."""
    root = Path(path).resolve()
    server = discovery.discover(root)

    declared = capability_classifier.classify(server.tools)

    sink_facts = semgrep_runner.run(root, server.tools, language=server.language)
    # v2 stub — same interface; currently always empty.
    sink_facts.extend(codeql_runner.run(root, server.tools, language=server.language))
    code_caps = semgrep_runner.derive_code_capabilities(sink_facts)

    poisoning, shadowing = metadata_classifier.classify(
        server.tools,
        session=session,
        sink_facts=sink_facts,
        extra_tools=extra_server_tools,  # type: ignore[arg-type]
    )

    injections = injection_findings.from_sinks(sink_facts)
    injections = [item for item in injections if session.uses_category(item.weakness_id)]

    cross_findings = (
        cross_check.check(declared, code_caps, sinks=sink_facts)
        if session.uses_category(Weakness.W4_OVERPRIVILEGED)
        else []
    )
    access_findings = (
        access_control_check.check(sink_facts)
        if session.uses_category(Weakness.W11_ACCESS_CONTROL)
        else []
    )
    cred_findings = (
        credential_scanner.scan(root)
        if session.uses_category(Weakness.W14_STATIC_CRED_EXPOSURE)
        else []
    )
    dep_findings = (
        sca_scan.scan(root) if session.uses_category(Weakness.W5_SUPPLY_CHAIN) else []
    )

    if not session.uses_category(Weakness.W1_TOOL_POISONING):
        poisoning = []
    if not session.uses_category(Weakness.W2_TOOL_SHADOWING):
        shadowing = []

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
