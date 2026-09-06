"""Hand-constructed models for unit tests (no pipeline / eBPF)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from mcpaegis.core.models import (
    CodeCapability,
    DeclaredCapability,
    DynamicReport,
    RuntimeFinding,
    ServerMetadata,
    SinkFact,
    StaticReport,
    ToolMetadata,
)
from mcpaegis.core.taxonomy import Capability, SinkType

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def tool(name: str, description: str = "", schema: dict[str, Any] | None = None) -> ToolMetadata:
    return ToolMetadata(
        name=name,
        description=description,
        input_schema=schema or {},
    )


def server(*names: str, language: str = "python") -> ServerMetadata:
    tools = [tool(n, f"{n} helper") for n in names] or [tool("echo", "echo text")]
    return ServerMetadata(
        entrypoint="server.py",
        language=language,
        manifest_path=None,
        tools=tools,
        resources=[],
        prompts=[],
        source="static_fallback",
    )


def declared(tool_name: str, capability: Capability, *, evidence: list[str] | None = None) -> DeclaredCapability:
    return DeclaredCapability(
        tool_name=tool_name,
        capability=capability,
        confidence=0.8,
        evidence=evidence or ["test"],
    )


def code_cap(tool_name: str, capability: Capability, *, sink_refs: list[str] | None = None) -> CodeCapability:
    return CodeCapability(
        tool_name=tool_name,
        capability=capability,
        sink_refs=sink_refs or [],
    )


def sink(
    *,
    id: str = "sink_1",
    tool_name: Optional[str] = "run",
    sink_type: SinkType = SinkType.SHELL_EXEC,
    file: str = "server.py",
    line: int = 10,
    function_name: str = "run",
    taint_path: list[str] | None = None,
    confidence: str = "direct",
) -> SinkFact:
    return SinkFact(
        id=id,
        tool_name=tool_name,
        sink_type=sink_type,
        file=file,
        line=line,
        function_name=function_name,
        taint_path=taint_path or [],
        confidence=confidence,  # type: ignore[arg-type]
        rule_id="mcpaegis.python.shell_exec.subprocess",
        snippet="subprocess.run(cmd)",
    )


def static_report(**overrides: Any) -> StaticReport:
    srv = overrides.pop("server", None) or server("echo")
    data: dict[str, Any] = {
        "server": srv,
        "poisoning_flags": [],
        "shadowing_flags": [],
        "declared_capabilities": [],
        "sink_facts": [],
        "code_capabilities": [],
        "cross_check_findings": [],
        "access_control_findings": [],
        "dependency_findings": [],
        "static_credential_findings": [],
        "expected_behavior_profiles": [],
        "scanned_at": NOW,
    }
    data.update(overrides)
    return StaticReport(**data)


def runtime_finding(
    *,
    tool_name: str = "echo",
    weakness_id: str = "W5",
    status: str = "confirmed",
    severity: str = "HIGH",
    call_id: str = "call-1",
    description: str = "runtime finding",
    evidence_refs: dict[str, Any] | None = None,
) -> RuntimeFinding:
    refs = {"tree": call_id}
    if evidence_refs:
        refs.update(evidence_refs)
    return RuntimeFinding(
        call_id=call_id,
        tool_name=tool_name,
        weakness_id=weakness_id,
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        evidence_refs=refs,
        description=description,
    )


def dynamic_report(*, findings: list[RuntimeFinding] | None = None, **overrides: Any) -> DynamicReport:
    data: dict[str, Any] = {
        "server_path": "/tmp/server",
        "tool_behavior_trees": [],
        "pre_execution_audits": [],
        "post_execution_verifications": [],
        "canary_seeds": [],
        "sink_witnesses": [],
        "runtime_findings": findings or [],
        "scanned_at": NOW,
    }
    data.update(overrides)
    return DynamicReport(**data)
