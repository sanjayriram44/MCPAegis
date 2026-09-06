from datetime import datetime, timezone

from mcpaegis.combine.merger import merge
from mcpaegis.core.models import CombinedFinding, CrossCheckFinding, InjectionFinding, PoisoningFlag
from mcpaegis.core.taxonomy import Capability, SinkType
from tests.unit.helpers import dynamic_report, runtime_finding, server, static_report


def _poisoning() -> PoisoningFlag:
    return PoisoningFlag(
        tool_name="echo",
        weakness_id="W1",
        pattern_matched="ignore_previous",
        detection_tier="fast_rule",
        severity="HIGH",
        snippet="ignore previous",
        confidence=0.85,
    )


def _w4() -> CrossCheckFinding:
    return CrossCheckFinding(
        tool_name="echo",
        weakness_id="W4",
        direction="under_declared",
        declared_capabilities=[],
        code_capabilities=[Capability.SHELL_EXEC],
        missing_from_declared=[Capability.SHELL_EXEC],
        missing_from_code=[],
        severity="HIGH",
    )


def _findings_by_tier(report):
    out: dict[str, list[CombinedFinding]] = {}
    for tool in report.tools:
        for finding in tool.findings:
            out.setdefault(finding.confidence_tier, []).append(finding)
    return out


def test_static_only_when_no_runtime(tmp_path):
    static = static_report(
        server=server("echo"),
        poisoning_flags=[_poisoning()],
        cross_check_findings=[_w4()],
    )
    combined = merge(static, None, write_output=False, server_path=tmp_path)
    tiers = _findings_by_tier(combined)
    assert set(tiers) == {"static_only"}
    assert {f.weakness_id for f in tiers["static_only"]} == {"W1", "W4"}
    assert combined.dynamic_report_ref is None


def test_runtime_confirmed_when_same_weakness_confirmed():
    static = static_report(
        server=server("echo"),
        poisoning_flags=[_poisoning()],
    )
    dynamic = dynamic_report(
        findings=[
            runtime_finding(
                tool_name="echo",
                weakness_id="W1",
                status="confirmed",
                description="poisoning confirmed at runtime",
            )
        ]
    )
    combined = merge(static, dynamic, write_output=False)
    tiers = _findings_by_tier(combined)
    assert "runtime_confirmed" in tiers
    confirmed = tiers["runtime_confirmed"]
    assert confirmed[0].weakness_id == "W1"
    assert "runtime" in confirmed[0].evidence
    assert "static" in confirmed[0].evidence


def test_runtime_only_finding():
    static = static_report(server=server("echo"))
    dynamic = dynamic_report(
        findings=[
            runtime_finding(
                tool_name="echo",
                weakness_id="W15",
                status="runtime_only",
                severity="CRITICAL",
                description="canary leaked",
            )
        ]
    )
    combined = merge(static, dynamic, write_output=False)
    tiers = _findings_by_tier(combined)
    assert "runtime_only" in tiers
    only = tiers["runtime_only"][0]
    assert only.weakness_id == "W15"
    assert only.severity == "CRITICAL"
    assert only.confidence_tier == "runtime_only"


def test_unconfirmed_static_flag_stands_as_static_only():
    static = static_report(server=server("echo"), poisoning_flags=[_poisoning()])
    dynamic = dynamic_report(
        findings=[
            runtime_finding(
                tool_name="echo",
                weakness_id="W1",
                status="unconfirmed_static_flag_stands",
                description="not exercised",
            )
        ]
    )
    combined = merge(static, dynamic, write_output=False)
    tiers = _findings_by_tier(combined)
    assert "static_only" in tiers
    assert all(f.confidence_tier != "runtime_confirmed" for f in tiers.get("runtime_confirmed", []))
    assert {f.weakness_id for f in tiers["static_only"]} == {"W1"}


def test_static_w6_upgraded_when_runtime_confirms():
    static = static_report(
        server=server("run_cmd"),
        injection_findings=[
            InjectionFinding(
                tool_name="run_cmd",
                weakness_id="W6",
                sink_ref="sink_1",
                sink_type=SinkType.SHELL_EXEC,
                file="server.py",
                line=22,
                snippet="subprocess.run(command)",
            )
        ],
    )
    dynamic = dynamic_report(
        findings=[
            runtime_finding(
                tool_name="run_cmd",
                weakness_id="W6",
                status="confirmed",
                description="command injection confirmed at runtime",
                evidence_refs={"sink_ref": "sink_1"},
            )
        ]
    )
    combined = merge(static, dynamic, write_output=False)
    tiers = _findings_by_tier(combined)
    assert any(f.weakness_id == "W6" and f.confidence_tier == "runtime_confirmed" for f in tiers["runtime_confirmed"])


def test_runtime_confirms_only_matching_sink_ref():
    static = static_report(
        server=server("run_cmd"),
        injection_findings=[
            InjectionFinding(
                tool_name="run_cmd",
                weakness_id="W6",
                sink_ref="sink_search",
                sink_type=SinkType.SHELL_EXEC,
                file="server.py",
                line=10,
                snippet="subprocess.run(query)",
            ),
            InjectionFinding(
                tool_name="run_cmd",
                weakness_id="W6",
                sink_ref="sink_export",
                sink_type=SinkType.SHELL_EXEC,
                file="server.py",
                line=40,
                snippet="subprocess.run(export)",
            ),
        ],
    )
    dynamic = dynamic_report(
        findings=[
            runtime_finding(
                tool_name="run_cmd",
                weakness_id="W6",
                status="confirmed",
                description="search path exercised",
                evidence_refs={"sink_ref": "sink_search"},
            )
        ]
    )
    combined = merge(static, dynamic, write_output=False)
    w6 = [f for t in combined.tools for f in t.findings if f.weakness_id == "W6"]
    tiers = {f.confidence_tier for f in w6}
    assert tiers == {"runtime_confirmed", "static_only"}
    confirmed = next(f for f in w6 if f.confidence_tier == "runtime_confirmed")
    leftover = next(f for f in w6 if f.confidence_tier == "static_only")
    assert confirmed.evidence["static"]["sink_ref"] == "sink_search"
    assert leftover.evidence["static"]["sink_ref"] == "sink_export"


def test_write_output_emits_json(tmp_path):
    from mcpaegis.core.session import AuditSession

    static = static_report(server=server("echo"), poisoning_flags=[_poisoning()])
    session = AuditSession(output_dir=tmp_path, output_format="json", color=False)
    combined = merge(static, None, session=session, write_output=True, server_path=tmp_path)
    assert (tmp_path / "combined-report.json").is_file()
    assert combined.generated_at.tzinfo is timezone.utc or combined.generated_at
