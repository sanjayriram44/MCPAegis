"""Stage 4 must confirm static W5/W6/W7 when the tree shows the sink."""

from __future__ import annotations

from mcpaegis.core.models import ExpectedBehaviorProfile, ProcessNode, RuntimeEvent, ToolBehaviorTree
from mcpaegis.core.taxonomy import Capability, RuntimeEventKind, Weakness
from mcpaegis.dynamic.post_execution_verifier import observed_capabilities, verify


def _event(kind: RuntimeEventKind, *, pid: int = 10, details: dict | None = None) -> RuntimeEvent:
    return RuntimeEvent(
        id="evt_1",
        kind=kind,
        pid=pid,
        ppid=1,
        cgroup_id="1",
        timestamp=1.0,
        details=details or {},
    )


def _tree(tool: str, *children: ProcessNode) -> ToolBehaviorTree:
    root = ProcessNode(
        pid=1,
        ppid=None,
        comm="python3",
        argv="python3",
        started_at=0.0,
        ended_at=None,
        file_events=[],
        net_events=[],
        children=list(children),
    )
    return ToolBehaviorTree(
        call_id="call_1",
        tool_name=tool,
        arguments={},
        timestamp=1.0,
        process_branch=[root],
        dns_branch=[],
    )


def test_echo_binary_exec_still_counts_as_shell():
    child = ProcessNode(
        pid=2,
        ppid=1,
        comm="echo",
        argv="/usr/bin/echo",
        started_at=1.0,
        ended_at=None,
        file_events=[],
        net_events=[],
        children=[],
    )
    tree = _tree("run_cmd", child)
    assert Capability.SHELL_EXEC in observed_capabilities(tree)


def test_shell_exec_confirms_w6_even_when_static_already_knew():
    child = ProcessNode(
        pid=2,
        ppid=1,
        comm="sh",
        argv="/bin/sh",
        started_at=1.0,
        ended_at=None,
        file_events=[],
        net_events=[],
        children=[],
    )
    tree = _tree("run_cmd", child)
    profile = ExpectedBehaviorProfile(
        tool_name="run_cmd",
        declared_capabilities=[Capability.SHELL_EXEC],
        code_capabilities=[Capability.SHELL_EXEC],
        sink_refs=[],
        known_flags=[Weakness.W5_COMMAND_INJECTION.value],
    )
    result = verify(tree, profile)
    assert Weakness.W5_COMMAND_INJECTION.value in result.confirmed_weakness_ids
    assert observed_capabilities(tree) == {Capability.SHELL_EXEC}


def test_missing_exec_does_not_confirm_w6():
    tree = _tree("run_cmd")
    profile = ExpectedBehaviorProfile(
        tool_name="run_cmd",
        declared_capabilities=[Capability.SHELL_EXEC],
        code_capabilities=[Capability.SHELL_EXEC],
        sink_refs=[],
        known_flags=[Weakness.W5_COMMAND_INJECTION.value],
    )
    result = verify(tree, profile)
    assert result.confirmed_weakness_ids == []
    assert any(m.capability == Capability.SHELL_EXEC and m.observed is False for m in result.mismatches)


def test_unexpected_shell_is_w12_when_static_did_not_flag_it():
    child = ProcessNode(
        pid=2,
        ppid=1,
        comm="sh",
        argv="/bin/sh",
        started_at=1.0,
        ended_at=None,
        file_events=[],
        net_events=[],
        children=[],
    )
    tree = _tree("echo", child)
    profile = ExpectedBehaviorProfile(
        tool_name="echo",
        declared_capabilities=[],
        code_capabilities=[],
        sink_refs=[],
        known_flags=[],
    )
    result = verify(tree, profile)
    assert Weakness.W9_TOOL_EXEC_HIJACK.value in result.runtime_only_weakness_ids


def test_openat_confirms_w7():
    open_evt = _event(
        RuntimeEventKind.FILE_OPEN,
        details={"path": "/tmp/mcpaegis-placeholder-path", "comm": "python3"},
    )
    tree = ToolBehaviorTree(
        call_id="call_1",
        tool_name="read_file",
        arguments={},
        timestamp=1.0,
        process_branch=[
            ProcessNode(
                pid=1,
                ppid=None,
                comm="python3",
                argv="python3",
                started_at=0.0,
                ended_at=None,
                file_events=[open_evt],
                net_events=[],
                children=[],
            )
        ],
        dns_branch=[],
    )
    profile = ExpectedBehaviorProfile(
        tool_name="read_file",
        declared_capabilities=[Capability.FS_READ],
        code_capabilities=[Capability.FS_READ],
        sink_refs=[],
        known_flags=[Weakness.W6_PATH_TRAVERSAL.value],
    )
    result = verify(tree, profile)
    assert Weakness.W6_PATH_TRAVERSAL.value in result.confirmed_weakness_ids


def test_libc_open_on_raw_does_not_emit_w4_when_scoring_simplified():
    libc = _event(
        RuntimeEventKind.FILE_OPEN,
        pid=2,
        details={"path": "/lib/aarch64-linux-gnu/libc.so.6", "comm": "sh"},
    )
    child = ProcessNode(
        pid=2,
        ppid=1,
        comm="sh",
        argv="/bin/sh",
        started_at=1.0,
        ended_at=None,
        file_events=[],
        net_events=[],
        children=[],
    )
    raw_child = ProcessNode(
        pid=2,
        ppid=1,
        comm="sh",
        argv="/bin/sh",
        started_at=1.0,
        ended_at=None,
        file_events=[libc],
        net_events=[],
        children=[],
    )
    simplified = _tree("run_cmd", child)
    raw = _tree("run_cmd", raw_child)
    profile = ExpectedBehaviorProfile(
        tool_name="run_cmd",
        declared_capabilities=[Capability.SHELL_EXEC],
        code_capabilities=[Capability.SHELL_EXEC],
        sink_refs=[],
        known_flags=[Weakness.W5_COMMAND_INJECTION.value],
    )
    result = verify(simplified, profile, raw=raw)
    assert Weakness.W5_COMMAND_INJECTION.value in result.confirmed_weakness_ids
    assert Weakness.W3_OVERPRIVILEGED.value not in result.runtime_only_weakness_ids
    assert not any(m.capability == Capability.FS_READ for m in result.mismatches)
