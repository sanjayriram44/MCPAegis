from mcpaegis.core.taxonomy import SinkType
from mcpaegis.static.access_control_check import PRIVILEGED_SINKS, check
from tests.unit.helpers import sink


def test_privileged_sink_without_auth_is_flagged():
    findings = check(
        [
            sink(
                id="sink_shell",
                tool_name="run",
                sink_type=SinkType.SHELL_EXEC,
                function_name="run_cmd",
                taint_path=["handler", "helper"],
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].weakness_id == "W11"
    assert findings[0].sink_ref == "sink_shell"
    assert findings[0].tool_name == "run"
    assert findings[0].severity == "MEDIUM"
    assert "no auth-like function" in findings[0].reason


def test_proximate_privileged_sink_is_low():
    findings = check(
        [
            sink(
                id="sink_shell",
                confidence="proximate",
                sink_type=SinkType.SHELL_EXEC,
            )
        ]
    )
    assert findings[0].severity == "LOW"


def test_require_auth_on_taint_path_skips_finding():
    findings = check(
        [
            sink(
                taint_path=["handler", "require_auth", "exec_shell"],
                function_name="exec_shell",
            )
        ]
    )
    assert findings == []


def test_auth_like_function_name_skips_finding():
    findings = check([sink(function_name="is_authorized", taint_path=[])])
    assert findings == []


def test_non_privileged_sinks_are_ignored():
    findings = check(
        [
            sink(id="read", sink_type=SinkType.FILE_READ, function_name="open_file"),
            sink(id="net", sink_type=SinkType.NETWORK_CALL, function_name="fetch"),
        ]
    )
    assert findings == []
    assert SinkType.FILE_READ not in PRIVILEGED_SINKS


def test_unattributed_sink_uses_placeholder_tool():
    findings = check([sink(tool_name=None, function_name="write_out", sink_type=SinkType.FILE_WRITE)])
    assert findings[0].tool_name == "<unattributed>"
