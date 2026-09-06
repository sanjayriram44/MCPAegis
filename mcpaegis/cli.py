"""Typer CLI entrypoint: static / runtime / full / report."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from mcpaegis.combine.merger import RUNTIME_REPORT_NAME, STATIC_REPORT_NAME, merge
from mcpaegis.core.session import AuditSession
from mcpaegis.dynamic.errors import RuntimeUnavailableError
from mcpaegis.output.findings import SEVERITY_RANK, collect_findings, filter_findings
from mcpaegis.output.json_writer import load_report
from mcpaegis.output.markdown_writer import print_report

app = typer.Typer(
    name="mcpaegis",
    help="Static and dynamic security analysis of local MCP servers.",
    no_args_is_help=True,
    add_completion=False,
)


class StaticFormat(str, Enum):
    json = "json"
    sarif = "sarif"
    md = "md"


class ReportFormat(str, Enum):
    html = "html"
    md = "md"
    sarif = "sarif"


class SandboxProvider(str, Enum):
    process = "process"
    docker = "docker"  # accepted alias; runtime maps this to process


class FailOnSeverity(str, Enum):
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _session(
    *,
    output: Optional[Path],
    format: str,
    categories: Optional[str],
    no_color: bool,
) -> AuditSession:
    try:
        return AuditSession.from_cli(
            output=output,
            format=format,
            categories=categories,
            no_color=no_color,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _echo_error(message: str) -> None:
    typer.echo(message, err=True)


def _warn(message: str) -> None:
    typer.echo(f"warning: {message}", err=True)


def _print(report: object, session: AuditSession) -> None:
    print_report(report, categories=session.categories, color=session.color)


def _fail_on_exit(report: object, fail_on: Optional[FailOnSeverity], session: AuditSession) -> None:
    if fail_on is None:
        return
    threshold = SEVERITY_RANK[fail_on.value]
    records = filter_findings(collect_findings(report), session.categories)  # type: ignore[arg-type]
    if any(SEVERITY_RANK.get(record.severity, 0) >= threshold for record in records):
        raise typer.Exit(code=1)


def _static_report_path(session: AuditSession) -> Path:
    return session.output_dir / STATIC_REPORT_NAME


def _runtime_report_path(session: AuditSession) -> Path:
    return session.output_dir / RUNTIME_REPORT_NAME


@app.command()
def static(
    path: Path = typer.Argument(..., help="Path to the local MCP server source."),
    format: StaticFormat = typer.Option(StaticFormat.json, "--format", help="Output format."),
    output: Optional[Path] = typer.Option(None, "--output", help="Output directory."),
    categories: Optional[str] = typer.Option(
        None,
        "--categories",
        help="Comma-separated weakness IDs to include, e.g. W1,W4.",
    ),
    fail_on: Optional[FailOnSeverity] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding at or above this severity exists.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
) -> None:
    """Run the static analysis pipeline."""
    from mcpaegis.static.pipeline import run as run_static

    session = _session(output=output, format=format.value, categories=categories, no_color=no_color)
    report = run_static(path, session)
    _print(report, session)
    _fail_on_exit(report, fail_on, session)


@app.command()
def runtime(
    path: Path = typer.Argument(..., help="Path to the local MCP server source."),
    test_script: Optional[Path] = typer.Option(
        None,
        "--test-script",
        help="YAML/JSON file of explicit {tool_name, arguments} invocations.",
    ),
    sandbox: SandboxProvider = typer.Option(
        SandboxProvider.process,
        "--sandbox",
        help="How to run the server under test (local process in a nested cgroup).",
    ),
    max_calls: Optional[int] = typer.Option(None, "--max-calls", help="Maximum tool calls to dispatch."),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Per-call timeout in seconds."),
    format: StaticFormat = typer.Option(StaticFormat.json, "--format", help="Output format."),
    output: Optional[Path] = typer.Option(None, "--output", help="Output directory."),
    fail_on: Optional[FailOnSeverity] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding at or above this severity exists.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
) -> None:
    """Run the runtime (dynamic) analysis pipeline on Linux."""
    from mcpaegis.dynamic.pipeline import run as run_dynamic

    session = _session(output=output, format=format.value, categories=None, no_color=no_color)
    static_path = _static_report_path(session)
    if static_path.is_file():
        static_arg: Path | None = static_path
    else:
        static_arg = None
        _warn("no static profile found — running without declared-vs-observed verification")

    try:
        report = run_dynamic(
            path,
            session=session,
            test_script=test_script,
            max_calls=max_calls,
            timeout=timeout,
            sandbox=sandbox.value,
            static_report=static_arg,
        )
    except RuntimeUnavailableError as exc:
        _echo_error(str(exc))
        raise typer.Exit(code=1) from exc
    _print(report, session)
    _fail_on_exit(report, fail_on, session)


@app.command()
def full(
    path: Path = typer.Argument(..., help="Path to the local MCP server source."),
    test_script: Optional[Path] = typer.Option(
        None,
        "--test-script",
        help="YAML/JSON file of explicit {tool_name, arguments} invocations.",
    ),
    sandbox: SandboxProvider = typer.Option(
        SandboxProvider.process,
        "--sandbox",
        help="How to run the server under test (local process in a nested cgroup).",
    ),
    max_calls: Optional[int] = typer.Option(None, "--max-calls", help="Maximum tool calls to dispatch."),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Per-call timeout in seconds."),
    format: StaticFormat = typer.Option(StaticFormat.json, "--format", help="Output format."),
    output: Optional[Path] = typer.Option(None, "--output", help="Output directory."),
    categories: Optional[str] = typer.Option(
        None,
        "--categories",
        help="Comma-separated weakness IDs to include, e.g. W1,W4.",
    ),
    fail_on: Optional[FailOnSeverity] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding at or above this severity exists.",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
) -> None:
    """Run static analysis, then runtime, then merge reports."""
    from mcpaegis.dynamic.pipeline import run as run_dynamic
    from mcpaegis.static.pipeline import run as run_static

    session = _session(output=output, format=format.value, categories=categories, no_color=no_color)
    static_report = run_static(path, session)
    _print(static_report, session)

    dynamic_report = None
    try:
        dynamic_report = run_dynamic(
            path,
            session=session,
            test_script=test_script,
            max_calls=max_calls,
            timeout=timeout,
            sandbox=sandbox.value,
            static_report=static_report,
        )
        _print(dynamic_report, session)
    except RuntimeUnavailableError as exc:
        _echo_error(str(exc))
        _warn("runtime analysis skipped; writing combined report from static results only")

    combined = merge(
        static_report,
        dynamic_report,
        session=session,
        server_path=path,
        static_report_ref=_static_report_path(session),
        dynamic_report_ref=_runtime_report_path(session) if dynamic_report is not None else None,
        write_output=True,
    )
    _print(combined, session)
    _fail_on_exit(combined, fail_on, session)


@app.command()
def report(
    results: Path = typer.Argument(..., help="Path to a results JSON file."),
    format: ReportFormat = typer.Option(..., "--format", help="Output format (html, md, or sarif)."),
    output: Path = typer.Option(..., "--output", help="Output directory."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
) -> None:
    """Render an existing results JSON file as html, markdown, or SARIF."""
    from mcpaegis.output import html_writer, markdown_writer, sarif_writer

    session = _session(output=output, format=format.value, categories=None, no_color=no_color)
    try:
        loaded = load_report(results)
    except (OSError, ValueError) as exc:
        _echo_error(f"failed to load report {results}: {exc}")
        raise typer.Exit(code=1) from exc

    session.output_dir.mkdir(parents=True, exist_ok=True)
    dest = session.output_dir / f"{results.stem}.{format.value}"
    if format is ReportFormat.html:
        html_writer.write(loaded, dest)
    elif format is ReportFormat.md:
        markdown_writer.write(loaded, dest)
    else:
        sarif_writer.write(loaded, dest)
    _print(loaded, session)
    typer.echo(str(dest))


if __name__ == "__main__":
    app()
