"""Pydantic v2 models for static, dynamic, and combined audit reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel

from mcpaegis.core.taxonomy import Capability, RuntimeEventKind, SinkType


class SourceLocation(BaseModel):
    file: str
    line: int
    function_name: Optional[str] = None


class ToolMetadata(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]
    source_location: Optional[SourceLocation] = None


class ServerMetadata(BaseModel):
    entrypoint: str
    language: str
    manifest_path: Optional[str] = None
    tools: list[ToolMetadata]
    resources: list[dict[str, Any]]
    prompts: list[dict[str, Any]]
    source: Optional[Literal["live", "static_fallback"]] = None


class PoisoningFlag(BaseModel):
    tool_name: str
    weakness_id: Literal["W1"]
    pattern_matched: str
    detection_tier: Literal["fast_rule", "llm_semantic"]
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    snippet: str
    confidence: float


class ShadowingFlag(BaseModel):
    tool_name: str
    weakness_id: Literal["W2"]
    conflicting_tool_name: str
    conflicting_server: Optional[str] = None
    similarity_score: float
    reason: str


class DeclaredCapability(BaseModel):
    tool_name: str
    capability: Capability
    confidence: float
    evidence: list[str]


class SinkFact(BaseModel):
    id: str
    tool_name: Optional[str] = None
    sink_type: SinkType
    file: str
    line: int
    function_name: str
    taint_path: list[str]
    # direct = Semgrep taint traced a tool-parameter source to this sink.
    # proximate = pattern match / call-graph reachability only (no proven dataflow).
    confidence: Literal["direct", "proximate"]
    rule_id: str
    snippet: str


class InjectionFinding(BaseModel):
    """Dataflow-confirmed W6/W7/W9 from Stage 3.5 (taint-mode Semgrep)."""

    tool_name: str
    weakness_id: Literal["W6", "W7", "W9"]
    sink_ref: str
    sink_type: SinkType
    file: str
    line: int
    snippet: str
    confidence: Literal["direct"] = "direct"
    severity: Literal["HIGH"] = "HIGH"


class CodeCapability(BaseModel):
    tool_name: str
    capability: Capability
    sink_refs: list[str]


class CrossCheckFinding(BaseModel):
    tool_name: str
    weakness_id: Literal["W4"]
    direction: Literal["under_declared", "over_declared"]
    declared_capabilities: list[Capability]
    code_capabilities: list[Capability]
    missing_from_declared: list[Capability]
    missing_from_code: list[Capability]
    severity: Literal["LOW", "MEDIUM", "HIGH"]


class AccessControlFinding(BaseModel):
    tool_name: str
    weakness_id: Literal["W11"]
    sink_ref: str
    reason: str
    severity: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"


class DependencyFinding(BaseModel):
    weakness_id: Literal["W5"]
    package_name: str
    installed_version: str
    vulnerable_range: Optional[str] = None
    cve_id: Optional[str] = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    source_tool: Literal["pip-audit", "npm-audit", "osv-scanner", "cargo-audit"]


class StaticCredentialFinding(BaseModel):
    weakness_id: Literal["W14"]
    file: str
    line: int
    pattern: str
    snippet: str


class ExpectedBehaviorProfile(BaseModel):
    """Per-tool summary consumed by the dynamic pipeline's post-execution verifier."""

    tool_name: str
    declared_capabilities: list[Capability]
    code_capabilities: list[Capability]
    sink_refs: list[str]
    known_flags: list[str]


class StaticReport(BaseModel):
    server: ServerMetadata
    poisoning_flags: list[PoisoningFlag]
    shadowing_flags: list[ShadowingFlag]
    declared_capabilities: list[DeclaredCapability]
    sink_facts: list[SinkFact]
    code_capabilities: list[CodeCapability]
    cross_check_findings: list[CrossCheckFinding]
    access_control_findings: list[AccessControlFinding]
    dependency_findings: list[DependencyFinding]
    static_credential_findings: list[StaticCredentialFinding]
    injection_findings: list[InjectionFinding] = []
    expected_behavior_profiles: list[ExpectedBehaviorProfile]
    scanned_at: datetime


class RuntimeEvent(BaseModel):
    id: str
    kind: RuntimeEventKind
    pid: int
    ppid: Optional[int] = None
    cgroup_id: str
    timestamp: float
    details: dict[str, Any]
    stack_trace: Optional[list[str]] = None


class ProcessNode(BaseModel):
    pid: int
    ppid: Optional[int] = None
    comm: str
    argv: str
    started_at: float
    ended_at: Optional[float] = None
    file_events: list[RuntimeEvent]
    net_events: list[RuntimeEvent]
    children: list[ProcessNode]


class ToolBehaviorTree(BaseModel):
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    process_branch: list[ProcessNode]
    dns_branch: list[RuntimeEvent]


class PreExecutionAuditResult(BaseModel):
    call_id: str
    tool_name: str
    decision: Literal["allow", "deny"]
    policy_type: Literal["code", "text"]
    reason: str
    evaluated_at: datetime


class DeclaredVsObservedMismatch(BaseModel):
    capability: Capability
    expected: bool
    observed: bool
    weakness_id: Optional[str] = None


class PostExecutionVerification(BaseModel):
    call_id: str
    tool_name: str
    decision: Literal["allow", "deny"]
    policy_type: Literal["code", "text"]
    mismatches: list[DeclaredVsObservedMismatch]
    confirmed_weakness_ids: list[str]
    runtime_only_weakness_ids: list[str]
    reason: str


class CanarySeed(BaseModel):
    type: Literal["env", "file", "arg"]
    key: str
    value: str
    planted_at: datetime


class SinkWitness(BaseModel):
    call_id: str
    canary_ref: str
    sink_location: str
    match_type: Literal[
        "exact",
        "prefix",
        "suffix",
        "separator_normalized",
        "base64",
        "hex",
        "rot13",
    ]
    confidence: float
    matched_snippet: str


class RuntimeFinding(BaseModel):
    call_id: str
    tool_name: str
    weakness_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    status: Literal["confirmed", "runtime_only", "unconfirmed_static_flag_stands"]
    evidence_refs: dict[str, Any]
    description: str


class DynamicReport(BaseModel):
    server_path: str
    tool_behavior_trees: list[ToolBehaviorTree]
    pre_execution_audits: list[PreExecutionAuditResult]
    post_execution_verifications: list[PostExecutionVerification]
    canary_seeds: list[CanarySeed]
    sink_witnesses: list[SinkWitness]
    runtime_findings: list[RuntimeFinding]
    scanned_at: datetime


class CombinedFinding(BaseModel):
    weakness_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence_tier: Literal["static_only", "runtime_confirmed", "runtime_only"]
    description: str
    evidence: dict[str, Any]


class CombinedToolReport(BaseModel):
    tool_name: str
    declared_capabilities: list[Capability]
    code_capabilities: list[Capability]
    observed_capabilities: list[Capability]
    findings: list[CombinedFinding]


class CombinedReport(BaseModel):
    server_path: str
    static_report_ref: str
    dynamic_report_ref: Optional[str] = None
    tools: list[CombinedToolReport]
    generated_at: datetime


ProcessNode.model_rebuild()
