"""Stage 6: assemble DynamicReport and write runtime-report.json/sarif/md."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from mcpaegis.core.models import (
    CanarySeed,
    DynamicReport,
    PostExecutionVerification,
    PreExecutionAuditResult,
    RuntimeFinding,
    SinkWitness,
    ToolBehaviorTree,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.dynamic.sink_inspector import classify_witness

SEVERITY_BY_WEAKNESS: dict[str, str] = {
    Weakness.W4_OVERPRIVILEGED.value: "HIGH",
    Weakness.W6_COMMAND_INJECTION.value: "HIGH",
    Weakness.W7_PATH_TRAVERSAL.value: "HIGH",
    Weakness.W9_SSRF.value: "HIGH",
    Weakness.W12_TOOL_EXEC_HIJACK.value: "CRITICAL",
    Weakness.W15_RUNTIME_CRED_LEAKAGE.value: "CRITICAL",
}


def build(
    *,
    server_path: str | Path,
    trees: Sequence[ToolBehaviorTree] | None = None,
    pre_audits: Sequence[PreExecutionAuditResult] | None = None,
    verifications: Sequence[PostExecutionVerification] | None = None,
    canary_seeds: Sequence[CanarySeed] | None = None,
    sink_witnesses: Sequence[SinkWitness] | None = None,
    findings: Sequence[RuntimeFinding] | None = None,
    scanned_at: datetime | None = None,
    session: AuditSession | None = None,
    output_dir: Path | str | None = None,
    output_format: str | None = None,
) -> DynamicReport:
    """Assemble a DynamicReport, derive findings, and write artifacts."""
    trees = list(trees or [])
    pre_audits = list(pre_audits or [])
    verifications = list(verifications or [])
    canary_seeds = list(canary_seeds or [])
    sink_witnesses = list(sink_witnesses or [])
    derived = list(findings) if findings is not None else derive_findings(
        verifications, sink_witnesses, canary_seeds, trees
    )
    if session is not None:
        derived = [f for f in derived if session.uses_category(f.weakness_id)]

    report = DynamicReport(
        server_path=str(server_path),
        tool_behavior_trees=trees,
        pre_execution_audits=pre_audits,
        post_execution_verifications=verifications,
        canary_seeds=canary_seeds,
        sink_witnesses=sink_witnesses,
        runtime_findings=derived,
        scanned_at=scanned_at or datetime.now(timezone.utc),
    )

    dest = Path(output_dir) if output_dir is not None else (session.output_dir if session else Path.cwd())
    dest.mkdir(parents=True, exist_ok=True)
    fmt = (output_format or (session.output_format if session else "json")).lower()
    write_reports(report, dest, fmt)
    return report


def derive_findings(
    verifications: Sequence[PostExecutionVerification],
    witnesses: Sequence[SinkWitness],
    seeds: Sequence[CanarySeed],
    trees: Sequence[ToolBehaviorTree],
) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []
    tool_by_call = {t.call_id: t.tool_name for t in trees}

    for ver in verifications:
        for wid in ver.confirmed_weakness_ids:
            findings.append(
                RuntimeFinding(
                    call_id=ver.call_id,
                    tool_name=ver.tool_name,
                    weakness_id=wid,
                    severity=SEVERITY_BY_WEAKNESS.get(wid, "MEDIUM"),
                    status="confirmed",
                    evidence_refs={"behavior_tree": ver.call_id, "verification": ver.call_id},
                    description=f"static flag {wid} confirmed at runtime for {ver.tool_name}: {ver.reason}",
                )
            )
        for wid in ver.runtime_only_weakness_ids:
            findings.append(
                RuntimeFinding(
                    call_id=ver.call_id,
                    tool_name=ver.tool_name,
                    weakness_id=wid,
                    severity=SEVERITY_BY_WEAKNESS.get(wid, "HIGH"),
                    status="runtime_only",
                    evidence_refs={"behavior_tree": ver.call_id, "verification": ver.call_id},
                    description=_runtime_only_description(wid, ver),
                )
            )

    for witness in witnesses:
        wid = classify_witness(witness, seeds)
        if not wid:
            continue
        findings.append(
            RuntimeFinding(
                call_id=witness.call_id,
                tool_name=tool_by_call.get(witness.call_id, ""),
                weakness_id=wid,
                severity=SEVERITY_BY_WEAKNESS.get(wid, "HIGH"),
                status="runtime_only",
                evidence_refs={"sink_witness": witness.canary_ref, "behavior_tree": witness.call_id},
                description=_witness_description(wid, witness),
            )
        )
    return findings


def write_reports(report: DynamicReport, output_dir: Path, fmt: str) -> None:
    payload = report.model_dump(mode="json")
    json_path = output_dir / "runtime-report.json"
    _write_json(payload, json_path)
    findings_payload = [f.model_dump(mode="json") for f in report.runtime_findings]
    # Spec: always emit json + sarif + markdown; ``fmt`` selects the primary extra.
    _write_sarif(findings_payload, output_dir / "runtime-report.sarif", json_path)
    _write_markdown(report, output_dir / "runtime-report.md")
    _ = fmt


def _write_json(payload: Any, path: Path) -> None:
    try:
        from mcpaegis.output.json_writer import write as json_write
    except Exception:
        json_write = None
    if json_write is not None:
        try:
            json_write(payload, path)
            return
        except NotImplementedError:
            pass
        except TypeError:
            try:
                json_write(payload, output_path=path)
                return
            except Exception:
                pass
        except Exception:
            pass
    path.write_text(
        __import__("json").dumps(payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _write_sarif(findings: list[dict[str, Any]], path: Path, report_path: Path) -> None:
    try:
        from mcpaegis.output.sarif_writer import write as sarif_write
    except Exception:
        sarif_write = None
    if sarif_write is not None:
        try:
            sarif_write(findings, path)
            return
        except NotImplementedError:
            pass
        except TypeError:
            try:
                sarif_write(findings, output_path=path, tool_name="mcpaegis")
                return
            except Exception:
                pass
        except Exception:
            pass
    results = []
    for item in findings:
        results.append(
            {
                "ruleId": item.get("weakness_id"),
                "level": _sarif_level(item.get("severity")),
                "message": {"text": item.get("description") or ""},
                "properties": {
                    "call_id": item.get("call_id"),
                    "tool_name": item.get("tool_name"),
                    "status": item.get("status"),
                },
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpaegis",
                        "informationUri": "https://github.com/mcpaegis",
                        "rules": [],
                    }
                },
                "results": results,
                "originalUriBaseIds": {"REPORT": {"uri": report_path.name}},
            }
        ],
    }
    path.write_text(__import__("json").dumps(doc, indent=2) + "\n", encoding="utf-8")


def _write_markdown(report: DynamicReport, path: Path) -> None:
    try:
        from mcpaegis.output.markdown_writer import write as md_write
    except Exception:
        md_write = None
    if md_write is not None:
        try:
            md_write(report, path)
            return
        except NotImplementedError:
            pass
        except TypeError:
            try:
                md_write(report.model_dump(mode="json"), path)
                return
            except Exception:
                pass
        except Exception:
            pass
    lines = [
        "# MCPAegis runtime report",
        "",
        f"- Server: `{report.server_path}`",
        f"- Scanned at: {report.scanned_at}",
        f"- Calls observed: {len(report.tool_behavior_trees)}",
        f"- Findings: {len(report.runtime_findings)}",
        "",
        "## Findings",
        "",
    ]
    if not report.runtime_findings:
        lines.append("_No runtime findings._")
    for finding in report.runtime_findings:
        lines.append(
            f"- **{finding.weakness_id}** ({finding.severity}, {finding.status}) "
            f"`{finding.tool_name}`: {finding.description}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sarif_level(severity: str | None) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    return mapping.get((severity or "").upper(), "warning")


def _runtime_only_description(wid: str, ver: PostExecutionVerification) -> str:
    if wid == Weakness.W12_TOOL_EXEC_HIJACK.value:
        return (
            f"hijack-shaped runtime behavior for {ver.tool_name}: observed privileged "
            f"capability not in declared/code profile ({ver.reason})"
        )
    return f"runtime-only {wid} for {ver.tool_name}: {ver.reason}"


def _witness_description(wid: str, witness: SinkWitness) -> str:
    return (
        f"canary {witness.canary_ref[:32]}… leaked into {witness.sink_location} "
        f"({witness.match_type})"
    )
