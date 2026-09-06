"""SARIF 2.1.0 writer for static, dynamic, and combined findings lists."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from mcpaegis import __version__
from mcpaegis.core.models import CombinedReport, DynamicReport, StaticReport
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.output.findings import (
    FindingLike,
    FindingRecord,
    ReportLike,
    collect_findings,
    filter_findings,
    sort_findings,
    weakness_title,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "MCPAegis"
TOOL_INFORMATION_URI = "https://github.com/mcpaegis/mcpaegis"

_LEVEL_FOR_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SARIF_KIND = {
    "CRITICAL": "fail",
    "HIGH": "fail",
    "MEDIUM": "fail",
    "LOW": "review",
}


def _rule_descriptor(weakness_id: str) -> dict[str, Any]:
    title = weakness_title(weakness_id)
    help_text = f"MCPAegis weakness {weakness_id}: {title}."
    return {
        "id": weakness_id,
        "name": title.replace(" ", "").replace("/", "").replace("-", ""),
        "shortDescription": {"text": title},
        "fullDescription": {"text": help_text},
        "help": {"text": help_text, "markdown": f"**{weakness_id}** — {title}"},
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["security", "mcp", weakness_id],
            "precision": "medium",
        },
    }


def _location(record: FindingRecord) -> dict[str, Any] | None:
    if not record.file:
        return None
    physical: dict[str, Any] = {"artifactLocation": {"uri": record.file.replace("\\", "/")}}
    if record.line is not None:
        physical["region"] = {"startLine": record.line}
        if record.snippet:
            physical["region"]["snippet"] = {"text": record.snippet}
    location: dict[str, Any] = {"physicalLocation": physical}
    if record.function_name:
        location["logicalLocations"] = [{"fullyQualifiedName": record.function_name, "kind": "function"}]
    return location


def _result(record: FindingRecord) -> dict[str, Any]:
    level = _LEVEL_FOR_SEVERITY.get(record.severity, "warning")
    result: dict[str, Any] = {
        "ruleId": record.weakness_id,
        "level": level,
        "kind": _SARIF_KIND.get(record.severity, "fail"),
        "message": {"text": record.message},
        "properties": {
            "severity": record.severity,
            "weaknessId": record.weakness_id,
            **({k: v for k, v in record.properties.items() if v is not None}),
        },
    }
    if record.tool_name:
        result["properties"]["toolName"] = record.tool_name
    if record.confidence is not None:
        result["properties"]["confidence"] = record.confidence
    if record.snippet and not record.file:
        result["properties"]["snippet"] = record.snippet
    loc = _location(record)
    if loc is not None:
        result["locations"] = [loc]
    return result


def _run_properties(source: Any) -> dict[str, Any]:
    props: dict[str, Any] = {"scanner": TOOL_NAME}
    if isinstance(source, StaticReport):
        props["kind"] = "static"
        props["language"] = source.server.language
        props["entrypoint"] = source.server.entrypoint
        if source.server.source:
            props["metadataSource"] = source.server.source
        props["scannedAt"] = source.scanned_at.isoformat()
    elif isinstance(source, DynamicReport):
        props["kind"] = "dynamic"
        props["serverPath"] = source.server_path
        props["scannedAt"] = source.scanned_at.isoformat()
    elif isinstance(source, CombinedReport):
        props["kind"] = "combined"
        props["serverPath"] = source.server_path
        props["staticReportRef"] = source.static_report_ref
        if source.dynamic_report_ref:
            props["dynamicReportRef"] = source.dynamic_report_ref
        props["generatedAt"] = source.generated_at.isoformat()
    else:
        props["kind"] = "findings"
    return props


def to_sarif(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    tool_name: str = TOOL_NAME,
    tool_version: str = __version__,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from a report or a list of findings."""
    records = sort_findings(filter_findings(collect_findings(source), categories))
    # Always publish the taxonomy as SARIF rules so empty runs still have a stable driver.
    rule_ids = [w.value for w in Weakness]
    extra = sorted({r.weakness_id for r in records if r.weakness_id not in rule_ids})
    rule_ids = rule_ids + extra

    driver: dict[str, Any] = {
        "name": tool_name,
        "version": tool_version,
        "semanticVersion": tool_version,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": [_rule_descriptor(wid) for wid in dict.fromkeys(rule_ids)],
    }
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": [_result(r) for r in records],
        "columnKind": "utf16CodeUnits",
        "properties": _run_properties(source),
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def dumps(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    indent: int = 2,
) -> str:
    """Serialize findings to a pretty-printed SARIF 2.1.0 document."""
    return json.dumps(to_sarif(source, categories=categories), indent=indent, ensure_ascii=False)


def write(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    path: str | Path,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    indent: int = 2,
) -> Path:
    """Write a SARIF 2.1.0 document to ``path``."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = dumps(source, categories=categories, indent=indent)
    if not text.endswith("\n"):
        text += "\n"
    destination.write_text(text, encoding="utf-8")
    return destination
