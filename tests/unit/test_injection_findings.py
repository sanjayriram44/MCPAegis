from mcpaegis.core.taxonomy import SinkType
from mcpaegis.output.findings import collect_static_findings
from mcpaegis.static.injection_findings import from_sinks
from tests.unit.helpers import sink, static_report


def test_direct_shell_exec_emits_w6():
    findings = from_sinks(
        [sink(id="s1", tool_name="run_cmd", sink_type=SinkType.SHELL_EXEC, confidence="direct")]
    )
    assert len(findings) == 1
    assert findings[0].weakness_id == "W6"
    assert findings[0].severity == "HIGH"
    assert findings[0].confidence == "direct"
    assert findings[0].sink_ref == "s1"


def test_direct_db_and_eval_emit_w6():
    findings = from_sinks(
        [
            sink(id="sql", tool_name="q", sink_type=SinkType.DB_QUERY, confidence="direct", line=4),
            sink(id="ev", tool_name="q", sink_type=SinkType.DYNAMIC_CODE_LOAD, confidence="direct", line=5),
        ]
    )
    assert all(f.weakness_id == "W6" for f in findings)
    assert len(findings) == 2


def test_direct_file_and_net_emit_w7_w9():
    findings = from_sinks(
        [
            sink(id="r", tool_name="read", sink_type=SinkType.FILE_READ, confidence="direct", line=11),
            sink(id="w", tool_name="write", sink_type=SinkType.FILE_WRITE, confidence="direct", line=12),
            sink(id="n", tool_name="fetch", sink_type=SinkType.NETWORK_CALL, confidence="direct", line=13),
        ]
    )
    by_id = {f.weakness_id: f for f in findings}
    assert by_id["W7"].tool_name in {"read", "write"}
    assert any(f.weakness_id == "W7" for f in findings)
    assert by_id["W9"].tool_name == "fetch"


def test_proximate_sinks_do_not_emit_injection_findings():
    findings = from_sinks(
        [sink(tool_name="search_docs", sink_type=SinkType.SHELL_EXEC, confidence="proximate")]
    )
    assert findings == []


def test_unattributed_direct_sink_skipped():
    findings = from_sinks([sink(tool_name=None, confidence="direct")])
    assert findings == []


def test_collect_static_findings_includes_injection():
    inj = from_sinks([sink(tool_name="run_cmd", confidence="direct")])
    report = static_report(injection_findings=inj)
    records = collect_static_findings(report)
    assert any(r.weakness_id == "W6" for r in records)
