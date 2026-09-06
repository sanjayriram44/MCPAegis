from datetime import datetime, timezone
from pathlib import Path

from mcpaegis.core.models import CombinedFinding, CombinedReport, CombinedToolReport, PoisoningFlag
from mcpaegis.output import json_writer, sarif_writer
from tests.unit.helpers import server, static_report


def test_json_roundtrip_static_report(tmp_path: Path):
    report = static_report(
        server=server("echo"),
        poisoning_flags=[
            PoisoningFlag(
                tool_name="echo",
                weakness_id="W1",
                pattern_matched="ignore_previous",
                detection_tier="fast_rule",
                severity="HIGH",
                snippet="ignore previous",
                confidence=0.85,
            )
        ],
    )
    path = tmp_path / "static-report.json"
    json_writer.write(report, path)
    loaded = json_writer.load_report(path)
    assert loaded.__class__.__name__ == "StaticReport"
    assert loaded.poisoning_flags[0].tool_name == "echo"


def test_sarif_contains_schema_and_results(tmp_path: Path):
    report = static_report(
        server=server("echo"),
        poisoning_flags=[
            PoisoningFlag(
                tool_name="echo",
                weakness_id="W1",
                pattern_matched="ignore_previous",
                detection_tier="fast_rule",
                severity="HIGH",
                snippet="ignore previous",
                confidence=0.85,
            )
        ],
    )
    path = tmp_path / "out.sarif"
    sarif_writer.write(report, path)
    data = json_writer.load_json(path)
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-2.1.0.json")
    results = data["runs"][0]["results"]
    assert any(r["ruleId"] == "W1" for r in results)
    assert data["runs"][0]["tool"]["driver"]["name"] == "MCPAegis"


def test_sarif_combined_report(tmp_path: Path):
    combined = CombinedReport(
        server_path="/tmp/s",
        static_report_ref="static-report.json",
        dynamic_report_ref=None,
        tools=[
            CombinedToolReport(
                tool_name="echo",
                declared_capabilities=[],
                code_capabilities=[],
                observed_capabilities=[],
                findings=[
                    CombinedFinding(
                        weakness_id="W4",
                        severity="HIGH",
                        confidence_tier="static_only",
                        description="under declared",
                        evidence={"static": {}},
                    )
                ],
            )
        ],
        generated_at=datetime.now(timezone.utc),
    )
    path = tmp_path / "combined.sarif"
    sarif_writer.write(combined, path)
    data = json_writer.load_json(path)
    assert data["runs"][0]["properties"]["kind"] == "combined"
    assert data["runs"][0]["results"][0]["ruleId"] == "W4"
