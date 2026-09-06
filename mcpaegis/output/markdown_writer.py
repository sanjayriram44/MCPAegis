"""Human-readable markdown and terminal summaries; HTML helper for ``report``."""

from __future__ import annotations

import html
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, TextIO

from mcpaegis.core.models import CombinedReport, DynamicReport, StaticReport
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.output.findings import (
    FindingLike,
    FindingRecord,
    ReportLike,
    collect_findings,
    filter_findings,
    format_capabilities,
    sort_findings,
    weakness_title,
)

_RESET = "\033[0m"
_BOLD = "\033[1m"
_SEVERITY_ANSI = {
    "CRITICAL": "\033[1;35m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
}
_SEVERITY_HTML = {
    "CRITICAL": "#7c3aed",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#0891b2",
}


def color_enabled(color: bool | None = None, stream: TextIO | None = None) -> bool:
    """Honor ``--no-color`` and non-TTY stdout (CI logs)."""
    if color is False:
        return False
    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", lambda: False)
    if not isatty():
        return False
    if color is True:
        return True
    return True


def _paint(text: str, *, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{_RESET}"


def _header(source: Any) -> tuple[str, list[str]]:
    """Return (title, metadata bullet lines)."""
    if isinstance(source, StaticReport):
        meta = [
            f"Language: {source.server.language}",
            f"Entrypoint: `{source.server.entrypoint}`",
            f"Tools: {len(source.server.tools)}",
            f"Scanned at: {source.scanned_at.isoformat()}",
        ]
        if source.server.source:
            meta.append(f"Metadata source: {source.server.source}")
        if source.server.manifest_path:
            meta.append(f"Manifest: `{source.server.manifest_path}`")
        return "MCPAegis static report", meta
    if isinstance(source, DynamicReport):
        meta = [
            f"Server path: `{source.server_path}`",
            f"Invocations: {len(source.tool_behavior_trees)}",
            f"Pre-exec audits: {len(source.pre_execution_audits)}",
            f"Canary seeds: {len(source.canary_seeds)}",
            f"Scanned at: {source.scanned_at.isoformat()}",
        ]
        return "MCPAegis runtime report", meta
    if isinstance(source, CombinedReport):
        meta = [
            f"Server path: `{source.server_path}`",
            f"Static report: `{source.static_report_ref}`",
            f"Runtime report: `{source.dynamic_report_ref or '(not run)'}`",
            f"Tools: {len(source.tools)}",
            f"Generated at: {source.generated_at.isoformat()}",
        ]
        return "MCPAegis combined report", meta
    return "MCPAegis findings", []


def _severity_counts(records: Sequence[FindingRecord]) -> dict[str, int]:
    counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for record in records:
        counts[record.severity] = counts.get(record.severity, 0) + 1
    return counts


def _finding_lines(record: FindingRecord) -> list[str]:
    location = ""
    if record.file:
        location = f" `{record.file}"
        if record.line is not None:
            location += f":{record.line}"
        location += "`"
    tool = f" tool `{record.tool_name}`" if record.tool_name else ""
    conf = f" _{record.confidence}_" if record.confidence else ""
    lines = [
        f"- **{record.severity}** `{record.weakness_id}` {weakness_title(record.weakness_id)}"
        f"{tool}{location}{conf}",
        f"  {record.message}",
    ]
    if record.snippet:
        snippet = record.snippet.replace("\n", " ").strip()
        if len(snippet) > 240:
            snippet = snippet[:237] + "..."
        lines.append(f"  `{snippet}`")
    return lines


def render_markdown(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
) -> str:
    """Render a GitHub-flavored markdown summary (no ANSI)."""
    records = sort_findings(filter_findings(collect_findings(source), categories))
    title, meta = _header(source)
    counts = _severity_counts(records)
    parts: list[str] = [f"# {title}", ""]
    if meta:
        parts.extend(f"- {line}" for line in meta)
        parts.append("")
    parts.append("## Summary")
    parts.append("")
    parts.append(
        f"{len(records)} finding(s) — "
        + ", ".join(f"{level}: {counts[level]}" for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    )
    parts.append("")

    if isinstance(source, CombinedReport):
        parts.append("## Tools")
        parts.append("")
        if not source.tools:
            parts.append("_No tools._")
            parts.append("")
        for tool in source.tools:
            parts.append(f"### `{tool.tool_name}`")
            parts.append("")
            parts.append(f"- Declared: {format_capabilities(tool.declared_capabilities)}")
            parts.append(f"- Code: {format_capabilities(tool.code_capabilities)}")
            parts.append(f"- Observed: {format_capabilities(tool.observed_capabilities)}")
            parts.append(f"- Findings: {len(tool.findings)}")
            parts.append("")

    parts.append("## Findings")
    parts.append("")
    if not records:
        parts.append("_No findings._")
        parts.append("")
    else:
        for record in records:
            parts.extend(_finding_lines(record))
        parts.append("")
    if isinstance(source, DynamicReport) and source.post_execution_verifications:
        parts.append("## Judge classifications")
        parts.append("")
        for ver in source.post_execution_verifications:
            parts.append(f"### `{ver.tool_name}` (`{ver.call_id}`)")
            parts.append("")
            if not ver.judge_classifications:
                parts.append("- _No LLM classifications._")
                parts.append("")
                continue
            for item in ver.judge_classifications:
                why = item.reason or "(no reason)"
                parts.append(f"- `{item.weakness_id}` **{item.verdict}**: {why}")
            parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def render_terminal(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    color: bool | None = None,
    stream: TextIO | None = None,
) -> str:
    """Render a terminal summary; strips ANSI when ``color`` is false or stdout is not a TTY."""
    use_color = color_enabled(color, stream)
    md = render_markdown(source, categories=categories)
    if not use_color:
        return md
    painted: list[str] = []
    for line in md.splitlines():
        for level, code in _SEVERITY_ANSI.items():
            token = f"**{level}**"
            if token in line:
                line = line.replace(token, _paint(level, code=code, enabled=True))
        if line.startswith("# "):
            line = _paint(line, code=_BOLD, enabled=True)
        painted.append(line)
    return "\n".join(painted) + "\n"


def dumps(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    color: bool | None = None,
    stream: TextIO | None = None,
) -> str:
    """Alias for :func:`render_terminal` (used by pipelines for md/terminal output)."""
    return render_terminal(source, categories=categories, color=color, stream=stream)


def write(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    path: str | Path,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    color: bool = False,
) -> Path:
    """Write a markdown file. Color is always off on disk."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _ = color  # disk output is never ANSI-colored
    destination.write_text(render_markdown(source, categories=categories), encoding="utf-8")
    return destination


def print_report(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
    color: bool | None = None,
    stream: TextIO | None = None,
) -> None:
    """Print a terminal summary to stdout (or ``stream``)."""
    target = stream if stream is not None else sys.stdout
    target.write(render_terminal(source, categories=categories, color=color, stream=target))


def render_html(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
) -> str:
    """Simple HTML summary used by ``mcpaegis report --format html``."""
    records = sort_findings(filter_findings(collect_findings(source), categories))
    title, meta = _header(source)
    counts = _severity_counts(records)

    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    rows: list[str] = []
    for record in records:
        loc = ""
        if record.file:
            loc = esc(record.file)
            if record.line is not None:
                loc += f":{record.line}"
        color = _SEVERITY_HTML.get(record.severity, "#334155")
        snippet = f"<pre>{esc(record.snippet)}</pre>" if record.snippet else ""
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{esc(record.severity)}</span></td>"
            f"<td><code>{esc(record.weakness_id)}</code></td>"
            f"<td>{esc(weakness_title(record.weakness_id))}</td>"
            f"<td>{esc(record.tool_name or '')}</td>"
            f"<td>{loc}</td>"
            f"<td>{esc(record.message)}{snippet}</td>"
            "</tr>"
        )

    chips = "".join(
        f"<span class='chip'><b style='color:{_SEVERITY_HTML[level]}'>{level}</b> {counts[level]}</span>"
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    meta_html = "".join(f"<li>{esc(line).replace('`', '')}</li>" for line in meta)
    tools_html = ""
    if isinstance(source, CombinedReport) and source.tools:
        tool_rows = []
        for tool in source.tools:
            tool_rows.append(
                "<tr>"
                f"<td><code>{esc(tool.tool_name)}</code></td>"
                f"<td>{esc(format_capabilities(tool.declared_capabilities))}</td>"
                f"<td>{esc(format_capabilities(tool.code_capabilities))}</td>"
                f"<td>{esc(format_capabilities(tool.observed_capabilities))}</td>"
                f"<td>{len(tool.findings)}</td>"
                "</tr>"
            )
        tools_html = (
            "<h2>Tools</h2><table><thead><tr>"
            "<th>Tool</th><th>Declared</th><th>Code</th><th>Observed</th><th>Findings</th>"
            "</tr></thead><tbody>"
            + "".join(tool_rows)
            + "</tbody></table>"
        )

    empty = "<tr><td colspan='6'><em>No findings.</em></td></tr>" if not rows else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{esc(title)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #0f172a; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .chip {{ display: inline-block; margin-right: 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 0.5rem 0.6rem; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    .sev {{ color: #fff; padding: 0.1rem 0.45rem; border-radius: 0.25rem; font-size: 0.8rem; }}
    pre {{ background: #f1f5f9; padding: 0.4rem; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>{esc(title)}</h1>
  <p>{chips} &nbsp; {len(records)} total</p>
  <ul>{meta_html}</ul>
  {tools_html}
  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>ID</th><th>Weakness</th><th>Tool</th><th>Location</th><th>Message</th></tr>
    </thead>
    <tbody>
      {"".join(rows) or empty}
    </tbody>
  </table>
</body>
</html>
"""


def write_html(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    path: str | Path,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
) -> Path:
    """Write an HTML summary to ``path``."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(source, categories=categories), encoding="utf-8")
    return destination
