from mcpaegis.core.taxonomy import Capability, SinkType
from mcpaegis.static.cross_check import HIGH_UNDERDECLARED, check
from tests.unit.helpers import code_cap, declared, sink


def test_underdeclared_high_for_shell_exec_when_direct():
    findings = check(
        [declared("run", Capability.FS_READ)],
        [code_cap("run", Capability.SHELL_EXEC), code_cap("run", Capability.FS_READ)],
        sinks=[sink(tool_name="run", sink_type=SinkType.SHELL_EXEC, confidence="direct")],
    )
    under = [f for f in findings if f.direction == "under_declared"]
    assert len(under) == 1
    assert under[0].weakness_id == "W3"
    assert under[0].severity == "HIGH"
    assert Capability.SHELL_EXEC in under[0].missing_from_declared
    assert under[0].missing_from_code == []


def test_underdeclared_medium_when_shell_exec_is_only_proximate():
    findings = check(
        [declared("search", Capability.FS_READ)],
        [code_cap("search", Capability.SHELL_EXEC), code_cap("search", Capability.FS_READ)],
        sinks=[sink(tool_name="search", sink_type=SinkType.SHELL_EXEC, confidence="proximate")],
    )
    under = [f for f in findings if f.direction == "under_declared"]
    assert under[0].severity == "MEDIUM"
    assert Capability.SHELL_EXEC in under[0].missing_from_declared


def test_underdeclared_medium_for_high_cap_without_sink_facts():
    findings = check([], [code_cap("tool", Capability.SHELL_EXEC)])
    assert findings[0].direction == "under_declared"
    assert findings[0].severity == "MEDIUM"


def test_underdeclared_high_for_credential_and_net_when_direct():
    mapping = {
        Capability.CREDENTIAL_HANDLING: SinkType.CREDENTIAL_READ,
        Capability.NET_OUTBOUND: SinkType.NETWORK_CALL,
    }
    for cap in (Capability.CREDENTIAL_HANDLING, Capability.NET_OUTBOUND):
        assert cap in HIGH_UNDERDECLARED
        findings = check(
            [],
            [code_cap("tool", cap)],
            sinks=[sink(tool_name="tool", sink_type=mapping[cap], confidence="direct")],
        )
        assert findings[0].direction == "under_declared"
        assert findings[0].severity == "HIGH"
        assert findings[0].missing_from_declared == [cap]


def test_underdeclared_medium_for_fs_write():
    findings = check(
        [declared("write", Capability.FS_READ)],
        [code_cap("write", Capability.FS_WRITE), code_cap("write", Capability.FS_READ)],
    )
    under = [f for f in findings if f.direction == "under_declared"]
    assert under[0].severity == "MEDIUM"
    assert Capability.FS_WRITE in under[0].missing_from_declared


def test_overdeclared_is_always_low():
    findings = check(
        [declared("echo", Capability.SHELL_EXEC), declared("echo", Capability.NET_OUTBOUND)],
        [code_cap("echo", Capability.SHELL_EXEC)],
    )
    over = [f for f in findings if f.direction == "over_declared"]
    assert len(over) == 1
    assert over[0].severity == "LOW"
    assert over[0].missing_from_code == [Capability.NET_OUTBOUND]
    assert over[0].missing_from_declared == []


def test_benign_utility_is_ignored_on_declared_side():
    findings = check(
        [declared("echo", Capability.BENIGN_UTILITY)],
        [],
    )
    assert findings == []


def test_matching_capabilities_produce_no_finding():
    findings = check(
        [declared("read", Capability.FS_READ)],
        [code_cap("read", Capability.FS_READ)],
    )
    assert findings == []


def test_both_directions_can_fire_for_same_tool():
    findings = check(
        [declared("mixed", Capability.FS_READ)],
        [code_cap("mixed", Capability.SHELL_EXEC)],
        sinks=[sink(tool_name="mixed", confidence="direct")],
    )
    directions = {f.direction for f in findings}
    assert directions == {"under_declared", "over_declared"}
    under = next(f for f in findings if f.direction == "under_declared")
    assert under.severity == "HIGH"
