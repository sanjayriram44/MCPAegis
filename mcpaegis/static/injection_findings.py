"""Stage 3.5: emit named W6/W7/W9 findings for dataflow-confirmed sinks."""

from __future__ import annotations

from mcpaegis.core.models import InjectionFinding, SinkFact
from mcpaegis.core.taxonomy import SinkType, Weakness

SINK_TO_INJECTION: dict[SinkType, str] = {
    SinkType.SHELL_EXEC: Weakness.W6_COMMAND_INJECTION.value,
    SinkType.DB_QUERY: Weakness.W6_COMMAND_INJECTION.value,
    SinkType.DYNAMIC_CODE_LOAD: Weakness.W6_COMMAND_INJECTION.value,
    SinkType.FILE_READ: Weakness.W7_PATH_TRAVERSAL.value,
    SinkType.FILE_WRITE: Weakness.W7_PATH_TRAVERSAL.value,
    SinkType.NETWORK_CALL: Weakness.W9_SSRF.value,
}


def from_sinks(sinks: list[SinkFact]) -> list[InjectionFinding]:
    """Emit HIGH W6/W7/W9 only for taint-confirmed (direct) sinks with a tool name."""
    findings: list[InjectionFinding] = []
    seen: set[tuple[str, str, str, int]] = set()
    for sink in sinks:
        if sink.confidence != "direct" or not sink.tool_name:
            continue
        weakness = SINK_TO_INJECTION.get(sink.sink_type)
        if weakness is None:
            continue
        key = (sink.tool_name, weakness, sink.file, sink.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            InjectionFinding(
                tool_name=sink.tool_name,
                weakness_id=weakness,  # type: ignore[arg-type]
                sink_ref=sink.id,
                sink_type=sink.sink_type,
                file=sink.file,
                line=sink.line,
                snippet=sink.snippet,
                confidence="direct",
                severity="HIGH",
            )
        )
    return findings
