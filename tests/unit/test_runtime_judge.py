"""Stage 4 LLM emits runtime weaknesses; static-only IDs are ignored."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from mcpaegis.core.models import (
    DeclaredVsObservedMismatch,
    ExpectedBehaviorProfile,
    PostExecutionVerification,
    ProcessNode,
    ToolBehaviorTree,
)
from mcpaegis.core.session import AuditSession, LLMConfig
from mcpaegis.core.taxonomy import Capability, Weakness
from mcpaegis.dynamic.runtime_judge import apply_classifications, apply_judge_actions, judge_verification
from mcpaegis.llm.prompts import build_judge_prompt


def _verification(*, confirmed: list[str] | None = None, runtime_only: list[str] | None = None) -> PostExecutionVerification:
    confirmed = confirmed or []
    runtime_only = runtime_only or []
    mismatches = []
    if Weakness.W5_COMMAND_INJECTION.value in confirmed:
        mismatches.append(
            DeclaredVsObservedMismatch(
                capability=Capability.SHELL_EXEC,
                expected=True,
                observed=True,
                weakness_id=Weakness.W5_COMMAND_INJECTION.value,
            )
        )
    if Weakness.W3_OVERPRIVILEGED.value in runtime_only:
        mismatches.append(
            DeclaredVsObservedMismatch(
                capability=Capability.FS_READ,
                expected=False,
                observed=True,
                weakness_id=Weakness.W3_OVERPRIVILEGED.value,
            )
        )
    return PostExecutionVerification(
        call_id="call_1",
        tool_name="run_quoted",
        decision="allow",
        policy_type="code",
        mismatches=mismatches,
        confirmed_weakness_ids=confirmed,
        runtime_only_weakness_ids=runtime_only,
        reason="runtime observed privileged behavior confirming static flags: W5",
    )


def test_emitter_replaces_code_findings_from_verdicts():
    before = _verification(
        confirmed=[Weakness.W5_COMMAND_INJECTION.value],
        runtime_only=[Weakness.W3_OVERPRIVILEGED.value],
    )
    after = apply_classifications(
        before,
        {
            "classifications": [
                {"weakness_id": "W5", "verdict": "false_positive", "reason": "quoted echo"},
                {"weakness_id": "W3", "verdict": "absent", "reason": "empty path"},
                {"weakness_id": "W8", "verdict": "static_only", "reason": "no auth"},
            ]
        },
    )
    assert after.confirmed_weakness_ids == []
    assert after.runtime_only_weakness_ids == []
    assert after.policy_type == "text"
    assert "W5=false_positive" in after.reason
    assert "quoted echo" in after.reason
    assert "W8=static_only" in after.reason
    by_id = {item.weakness_id: item for item in after.judge_classifications}
    assert by_id["W5"].reason == "quoted echo"
    assert by_id["W3"].verdict == "absent"


def test_emitter_can_confirm_w5_and_ignore_w8():
    before = _verification(confirmed=[Weakness.W5_COMMAND_INJECTION.value])
    after = apply_classifications(
        before,
        {
            "classifications": [
                {"weakness_id": "W5", "verdict": "runtime_confirmed", "reason": "/bin/sh"},
                {"weakness_id": "W8", "verdict": "runtime_confirmed", "reason": "should be ignored"},
            ]
        },
    )
    assert after.confirmed_weakness_ids == [Weakness.W5_COMMAND_INJECTION.value]
    assert Weakness.W8_ACCESS_CONTROL.value not in after.confirmed_weakness_ids
    assert Weakness.W8_ACCESS_CONTROL.value not in after.runtime_only_weakness_ids


def test_emitter_can_add_w7_when_code_had_none():
    before = _verification()
    after = apply_classifications(
        before,
        {
            "classifications": [
                {"weakness_id": "W7", "verdict": "runtime_confirmed", "reason": "connect to arg host"},
            ]
        },
    )
    assert after.confirmed_weakness_ids == [Weakness.W7_SSRF.value]


def test_unknown_and_static_only_ids_are_never_emitted():
    before = _verification()
    after = apply_classifications(
        before,
        {
            "classifications": [
                {"weakness_id": "W99", "verdict": "runtime_only", "reason": "no"},
                {"weakness_id": "W1", "verdict": "runtime_only", "reason": "no"},
            ]
        },
    )
    assert after.confirmed_weakness_ids == []
    assert after.runtime_only_weakness_ids == []


def test_disabled_llm_leaves_verification_unchanged():
    tree = ToolBehaviorTree(
        call_id="call_1",
        tool_name="run_quoted",
        arguments={"command": "x"},
        timestamp=1.0,
        process_branch=[
            ProcessNode(
                pid=1,
                ppid=None,
                comm="python3",
                argv="python3",
                started_at=0.0,
                ended_at=None,
                file_events=[],
                net_events=[],
                children=[],
            )
        ],
        dns_branch=[],
    )
    profile = ExpectedBehaviorProfile(
        tool_name="run_quoted",
        declared_capabilities=[Capability.SHELL_EXEC],
        code_capabilities=[Capability.SHELL_EXEC],
        sink_refs=[],
        known_flags=[Weakness.W5_COMMAND_INJECTION.value],
    )
    before = _verification(confirmed=[Weakness.W5_COMMAND_INJECTION.value])
    session = AuditSession(output_dir=Path("/tmp"), llm=LLMConfig(api_key=None, model="gpt-4o"))
    after = judge_verification(before, tree, profile, session=session)
    assert after.confirmed_weakness_ids == before.confirmed_weakness_ids


def test_judge_uses_session_model_via_client():
    tree = ToolBehaviorTree(
        call_id="call_1",
        tool_name="run_quoted",
        arguments={"command": "x"},
        timestamp=1.0,
        process_branch=[],
        dns_branch=[],
    )
    profile = ExpectedBehaviorProfile(
        tool_name="run_quoted",
        declared_capabilities=[],
        code_capabilities=[],
        sink_refs=[],
        known_flags=[],
    )
    before = _verification(
        confirmed=[Weakness.W5_COMMAND_INJECTION.value],
        runtime_only=[Weakness.W3_OVERPRIVILEGED.value],
    )
    session = AuditSession(
        output_dir=Path("/tmp"),
        llm=LLMConfig(api_key="sk-test", model="gpt-4.1-mini"),
    )

    class _Fake:
        def complete_json(self, **kwargs):
            assert kwargs.get("prompt") is not None
            return {
                "classifications": [
                    {"weakness_id": "W5", "verdict": "false_positive", "reason": "echo"},
                    {"weakness_id": "W3", "verdict": "absent", "reason": "empty path"},
                ]
            }

    with patch("mcpaegis.llm.client.LLMClient.from_session", return_value=_Fake()):
        after = judge_verification(before, tree, profile, session=session)
    assert after.confirmed_weakness_ids == []
    assert after.runtime_only_weakness_ids == []


def test_apply_judge_actions_uses_classifications():
    before = _verification(confirmed=[Weakness.W5_COMMAND_INJECTION.value])
    after = apply_judge_actions(
        before,
        {"classifications": [{"weakness_id": "W5", "verdict": "false_positive", "reason": "echo"}]},
    )
    assert after.confirmed_weakness_ids == []


def test_judge_prompt_includes_taxonomy_caps_and_tree():
    prompt = build_judge_prompt(
        tool_name="run_quoted",
        call_id="call_1",
        schema={"properties": {"command": {"type": "string"}}},
        arguments={"command": "hello"},
        expected_profile={"known_flags": ["W5"]},
        verification={"confirmed_weakness_ids": ["W5"]},
        process_tree={"comm": "echo"},
        dns_events=[],
        execution_result={"ok": True},
        tool_metadata={"name": "run_quoted", "description": "run a quoted command"},
        static_findings=[{"weakness_id": "W5", "snippet": "subprocess.run"}],
        declared_capabilities=["C3"],
        code_capabilities=["C3"],
        observed_capabilities=["C3"],
        known_flags=["W5"],
        sink_refs=[],
    )
    assert "W5 Command" in prompt.system
    assert "You are the source of truth for RUNTIME findings" in prompt.system
    assert "Every classification MUST include a non-empty \"reason\"" in prompt.system
    assert "===== DECLARED VS CODE VS OBSERVED =====" in prompt.user
    assert "===== THIS CALL =====" in prompt.user
    assert "C3" in prompt.user
    assert "subprocess.run" in prompt.user
    assert "Each classification needs weakness_id, verdict, and a reason" in prompt.user
