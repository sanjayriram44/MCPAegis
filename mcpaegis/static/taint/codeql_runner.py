"""Lane B CodeQL stub: same interface as semgrep_runner (always empty)."""

from __future__ import annotations

from pathlib import Path

from mcpaegis.core.models import CodeCapability, SinkFact, ToolMetadata


def run(
    target: Path,
    tools: list[ToolMetadata],
    *,
    language: str = "python",
) -> list[SinkFact]:
    """CodeQL backend is reserved for v2. Returns no sinks."""
    _ = (target, tools, language)
    return []


def derive_code_capabilities(sinks: list[SinkFact]) -> list[CodeCapability]:
    from mcpaegis.static.taint.semgrep_runner import derive_code_capabilities as _derive

    return _derive(sinks)
