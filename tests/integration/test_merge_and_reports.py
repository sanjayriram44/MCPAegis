"""Light integration tests: merger + report builders (no eBPF)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mcpaegis.combine.merger import merge
from mcpaegis.core.models import (
    AccessControlFinding,
    CodeCapability,
    CombinedReport,
    CrossCheckFinding,
    DeclaredCapability,
    PoisoningFlag,
    RuntimeFinding,
    StaticCredentialFinding,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Capability
from mcpaegis.output import json_writer, sarif_writer
from mcpaegis.static.report_builder import assemble
from tests.unit.helpers import dynamic_report, server, sink, static_report


def test_assemble_then_merge_static_only(tmp_path: Path):
    srv = server("run")
    static = assemble(
        srv,
        poisoning_flags=[
            PoisoningFlag(
                tool_name="run",
                weakness_id="W1",
                pattern_matched="ignore_previous",
                detection_tier="fast_rule",
                severity="HIGH",
                snippet="ignore previous",
                confidence=0.85,
            )
        ],
        shadowing_flags=[],
        declared_capabilities=[
            DeclaredCapability(
                tool_name="run",
                capability=Capability.FS_READ,
                confidence=0.5,
                evidence=["file"],
            )
        ],
        sink_facts=[sink(tool_name="run")],
        code_capabilities=[
            CodeCapability(tool_name="run", capability=Capability.SHELL_EXEC, sink_refs=["sink_1"])
        ],
        cross_check_findings=[
            CrossCheckFinding(
                tool_name="run",
                weakness_id="W3",
                direction="under_declared",
                declared_capabilities=[Capability.FS_READ],
                code_capabilities=[Capability.SHELL_EXEC],
                missing_from_declared=[Capability.SHELL_EXEC],
                missing_from_code=[],
                severity="HIGH",
            )
        ],
        access_control_findings=[
            AccessControlFinding(
                tool_name="run",
                weakness_id="W8",
                sink_ref="sink_1",
                reason="no auth",
            )
        ],
        dependency_findings=[],
        static_credential_findings=[
            StaticCredentialFinding(
                weakness_id="W10",
                file="server.py",
                line=3,
                pattern="aws_access_key_id",
                snippet="AKIA…MPLE [sha256=deadbeef]",
            )
        ],
        scanned_at=datetime.now(timezone.utc),
    )
    assert static.expected_behavior_profiles
    assert "W3" in static.expected_behavior_profiles[0].known_flags

    combined = merge(static, None, write_output=False, server_path=tmp_path)
    ids = {f.weakness_id for t in combined.tools for f in t.findings}
    assert {"W1", "W3", "W8", "W10"} <= ids
    assert all(f.confidence_tier == "static_only" for t in combined.tools for f in t.findings)


def test_json_and_sarif_writers_from_merged_report(tmp_path: Path):
    static = static_report(
        server=server("echo"),
        poisoning_flags=[
            PoisoningFlag(
                tool_name="echo",
                weakness_id="W1",
                pattern_matched="hidden_instruction",
                detection_tier="fast_rule",
                severity="HIGH",
                snippet="hidden instruction",
                confidence=0.85,
            )
        ],
    )
    dynamic = dynamic_report(
        findings=[
            RuntimeFinding(
                call_id="c1",
                tool_name="echo",
                weakness_id="W1",
                severity="HIGH",
                status="confirmed",
                evidence_refs={"call_id": "c1"},
                description="confirmed poisoning",
            )
        ]
    )
    session = AuditSession(output_dir=tmp_path, output_format="json", color=False)
    combined = merge(static, dynamic, session=session, write_output=True, server_path=tmp_path)
    json_path = tmp_path / "combined-report.json"
    sarif_path = tmp_path / "combined-report.sarif"
    assert json_path.is_file()
    loaded = json_writer.load_report(json_path)
    assert isinstance(loaded, CombinedReport)
    assert loaded.tools
    data = json_writer.load_json(sarif_path)
    assert data["version"] == "2.1.0"
    assert any(r["ruleId"] == "W1" for r in data["runs"][0]["results"])
    # Writers are also independently callable.
    extra = tmp_path / "copy.sarif"
    sarif_writer.write(combined, extra)
    assert extra.is_file()


def test_fixture_servers_are_vendored():
    root = Path(__file__).resolve().parents[1] / "fixtures"
    python_servers = (
        "poisoned_description",
        "command_injection",
        "path_traversal",
        "eval_format",
        "workspace_actions",
        "malicious_tools_adapted",
        "indirect_prompt_injection",
    )
    for name in python_servers:
        server_py = root / name / "server.py"
        assert server_py.is_file(), server_py
        text = server_py.read_text(encoding="utf-8")
        assert "@mcp.tool()" in text
