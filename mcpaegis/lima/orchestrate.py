"""Run static on the host; runtime in Lima (Darwin) or locally (Linux)."""

from __future__ import annotations

import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcpaegis.combine.merger import RUNTIME_REPORT_NAME, STATIC_REPORT_NAME, merge
from mcpaegis.core.models import CombinedReport, DynamicReport, StaticReport
from mcpaegis.core.session import AuditSession
from mcpaegis.lima.doctor import DoctorReport, host_snapshot
from mcpaegis.lima.errors import LimaError, PathNotSharedError
from mcpaegis.lima.guest import (
    ensure_venv,
    guest_mcpaegis,
    llm_env_from_config,
    llm_env_from_os,
    local_runtime_argv,
    probe_guest,
    runtime_argv,
    venv_ready,
)
from mcpaegis.lima.paths import (
    default_output_dir,
    is_under_home,
    require_under_home,
    resolve_test_script,
    stage_file_under_home,
    stage_under_home,
)
from mcpaegis.lima.vm import (
    ensure_instance,
    ensure_lima_cli,
    find_limactl,
    run_streaming,
    shell,
    stop_instance,
)
from mcpaegis.output.json_writer import load_report
from mcpaegis.output.markdown_writer import render_markdown

Mode = Literal["static", "runtime", "full"]
LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]


@dataclass
class RunResult:
    mode: Mode
    server_path: Path
    output_dir: Path
    static_report: StaticReport | None = None
    dynamic_report: DynamicReport | None = None
    combined_report: CombinedReport | None = None
    markdown: str = ""
    error: str | None = None
    log: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def _log(lines: list[str], emit: LogFn | None, message: str) -> None:
    lines.append(message)
    if emit is not None:
        emit(message)


@dataclass
class PreparedPaths:
    original: Path
    runtime: Path
    output: Path
    script: Path | None
    copied: bool = False


def prepare_paths(
    server: Path | str,
    output: Path | str | None,
    test_script: Path | str | None,
    *,
    mode: Mode,
    home: Path | None = None,
) -> PreparedPaths:
    original = Path(server).expanduser().resolve()
    if not original.exists():
        raise FileNotFoundError(f"MCP server path does not exist: {original}")
    darwin_runtime = mode in {"runtime", "full"} and platform.system() == "Darwin"
    runtime = original
    copied = False
    if darwin_runtime:
        runtime = stage_under_home(original, home=home)
        copied = runtime != original
        out = (
            Path(output).expanduser().resolve()
            if output
            else default_output_dir(original, home=home)
        )
        if not is_under_home(out, home=home):
            out = default_output_dir(original, home=home)
        out = require_under_home(out, home=home, what="output directory")
    else:
        out = Path(output).expanduser().resolve() if output else (Path.cwd() / "mcpaegis-out")
    try:
        script = resolve_test_script(
            original,
            test_script,
            home=home,
            require_shared=False,
        )
    except FileNotFoundError:
        if not copied:
            raise
        script = resolve_test_script(
            runtime,
            test_script,
            home=home,
            require_shared=False,
        )
    if darwin_runtime and script is not None:
        dest_dir = None
        if copied:
            dest_dir = runtime if runtime.is_dir() else runtime.parent
        script = stage_file_under_home(script, dest_dir=dest_dir, home=home)
    out.mkdir(parents=True, exist_ok=True)
    return PreparedPaths(
        original=original,
        runtime=runtime,
        output=out,
        script=script,
        copied=copied,
    )


def run_static_local(server_path: Path, session: AuditSession, log: LogFn | None = None) -> StaticReport:
    from mcpaegis.static.pipeline import run as run_static

    if log:
        log(f"static: {server_path} → {session.output_dir}")
    return run_static(server_path, session)


def refresh_doctor(*, deep: bool = False) -> DoctorReport:
    snap = host_snapshot()
    if platform.system() == "Linux":
        btf = Path("/sys/kernel/btf/vmlinux").exists()
        cgroup = Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        return DoctorReport(
            system=snap.system,
            machine=snap.machine,
            apple_silicon=False,
            limactl=snap.limactl,
            instance=snap.instance,
            btf=btf,
            cgroup_v2=cgroup,
            notes=snap.notes,
        )
    from mcpaegis.lima.doctor import instance_named
    from mcpaegis.lima.vm import list_instances

    binary = find_limactl()
    inst = None
    if binary:
        try:
            inst = instance_named(list_instances(binary))
        except Exception:  # noqa: BLE001
            inst = None
    if not deep or platform.system() != "Darwin" or not binary:
        return DoctorReport(
            system=snap.system,
            machine=snap.machine,
            apple_silicon=snap.apple_silicon,
            limactl=binary,
            instance=inst,
            notes=snap.notes,
        )
    guest_uname = None
    btf = None
    cgroup = None
    home = None
    venv_ok = None
    bcc_ok = None
    if inst is not None and inst.running:
        try:
            probed = probe_guest(limactl=binary)
            home = str(probed.get("home") or "") or None
            guest_uname = str(probed.get("uname") or "") or None
            btf = bool(probed.get("btf")) if "btf" in probed else None
            cgroup = bool(probed.get("cgroup")) if "cgroup" in probed else None
            venv_ok = bool(probed.get("venv")) if "venv" in probed else None
            bcc_ok = bool(probed.get("bcc")) if "bcc" in probed else None
        except LimaError:
            pass
    return DoctorReport(
        system=snap.system,
        machine=snap.machine,
        apple_silicon=snap.apple_silicon,
        limactl=binary,
        instance=inst,
        guest_uname=guest_uname,
        btf=btf,
        cgroup_v2=cgroup,
        guest_home=home,
        venv_ok=venv_ok,
        bcc_ok=bcc_ok,
        notes=snap.notes,
    )


def ensure_runtime_guest(
    *,
    log: LogFn | None = None,
    cancel: CancelFn | None = None,
) -> str:
    """Start Lima, bootstrap the guest venv, return guest ``mcpaegis`` binary path."""
    write = log or (lambda _m: None)
    binary = ensure_lima_cli(log=write, cancel=cancel)
    ensure_instance(limactl=binary, log=write, cancel=cancel)
    if venv_ready(limactl=binary):
        write("Guest venv already installed.")
        return guest_mcpaegis(limactl=binary)
    return ensure_venv(limactl=binary, log=write)


def run_runtime_guest(
    *,
    server_path: Path,
    output_dir: Path,
    test_script: Path | None,
    timeout: int | None,
    log: LogFn | None = None,
    cancel: CancelFn | None = None,
    extra_env: dict[str, str] | None = None,
) -> int:
    write = log or (lambda _m: None)
    bin_path = ensure_runtime_guest(log=write, cancel=cancel)
    argv = runtime_argv(
        server_path=server_path,
        output_dir=output_dir,
        test_script=test_script,
        timeout=timeout,
        extra_env=extra_env if extra_env is not None else llm_env_from_os(),
        mcpaegis_bin=bin_path,
    )
    write("guest runtime: " + " ".join(_safe_preview(argv)))
    return shell(argv, log=write, cancel=cancel, check=False)


def run_runtime_linux(
    *,
    server_path: Path,
    output_dir: Path,
    test_script: Path | None,
    timeout: int | None,
    log: LogFn | None = None,
    cancel: CancelFn | None = None,
    extra_env: dict[str, str] | None = None,
) -> int:
    write = log or (lambda _m: None)
    argv = local_runtime_argv(
        server_path=server_path,
        output_dir=output_dir,
        test_script=test_script,
        timeout=timeout,
        extra_env=extra_env if extra_env is not None else llm_env_from_os(),
    )
    write("runtime: " + " ".join(_safe_preview(argv)))
    return run_streaming(argv, log=write, cancel=cancel)


def run_analysis(
    mode: Mode,
    server: Path | str,
    *,
    output: Path | str | None = None,
    test_script: Path | str | None = None,
    timeout: int | None = 30,
    log: LogFn | None = None,
    cancel: CancelFn | None = None,
    session: AuditSession | None = None,
) -> RunResult:
    lines: list[str] = []

    def emit(message: str) -> None:
        _log(lines, log, message)

    try:
        prepared = prepare_paths(server, output, test_script, mode=mode)
    except (FileNotFoundError, PathNotSharedError) as exc:
        result = RunResult(mode=mode, server_path=Path(server), output_dir=Path("."), error=str(exc))
        result.log = [str(exc)]
        return result

    original = prepared.original
    runtime_path = prepared.runtime
    out = prepared.output
    script = prepared.script
    sess = session or AuditSession.from_cli(output=out, format="json", no_color=True)
    sess.output_dir = out
    result = RunResult(mode=mode, server_path=original, output_dir=out)
    llm_env = llm_env_from_config(sess.llm)
    darwin_runtime = mode in {"runtime", "full"} and platform.system() == "Darwin"

    try:
        if prepared.copied:
            emit(f"copied MCP server to {runtime_path}")
        if mode in {"static", "full"}:
            emit("Running static analysis on this host…")
            result.static_report = run_static_local(original, sess, log=emit)
            emit("Static analysis finished.")
        if mode in {"runtime", "full"}:
            if platform.system() == "Darwin":
                emit("Ensuring Lima Ubuntu guest for eBPF runtime…")
                code = run_runtime_guest(
                    server_path=runtime_path,
                    output_dir=out,
                    test_script=script,
                    timeout=timeout,
                    log=emit,
                    cancel=cancel,
                    extra_env=llm_env,
                )
            elif platform.system() == "Linux":
                emit("Linux host: running runtime locally…")
                code = run_runtime_linux(
                    server_path=runtime_path,
                    output_dir=out,
                    test_script=script,
                    timeout=timeout,
                    log=emit,
                    cancel=cancel,
                    extra_env=llm_env,
                )
            else:
                raise LimaError(f"runtime is not supported on {platform.system()}")
            if code != 0:
                raise LimaError(f"runtime exited with status {code}")
            runtime_file = out / RUNTIME_REPORT_NAME
            if runtime_file.is_file():
                loaded = load_report(runtime_file)
                if isinstance(loaded, DynamicReport):
                    result.dynamic_report = loaded
            emit("Runtime analysis finished.")
        if mode == "full":
            static_file = out / STATIC_REPORT_NAME
            runtime_file = out / RUNTIME_REPORT_NAME
            static_arg: StaticReport | Path = result.static_report or static_file
            dynamic_arg = result.dynamic_report if result.dynamic_report is not None else (
                runtime_file if runtime_file.is_file() else None
            )
            emit("Merging static + runtime reports…")
            result.combined_report = merge(
                static_arg,
                dynamic_arg,
                session=sess,
                server_path=original,
                static_report_ref=static_file,
                dynamic_report_ref=runtime_file if dynamic_arg is not None else None,
                write_output=True,
            )
        result.markdown = _markdown_for(result)
        emit(f"Reports in {out}")
    except Exception as exc:  # noqa: BLE001 — surface any pipeline/Lima failure in the TUI
        result.error = str(exc)
        emit(f"error: {exc}")
    finally:
        if darwin_runtime:
            try:
                emit("Stopping Lima to free host resources…")
                stop_instance(log=emit)
            except Exception as stop_exc:  # noqa: BLE001
                emit(f"warning: could not stop Lima ({stop_exc})")
    result.log = lines
    return result


def _markdown_for(result: RunResult) -> str:
    if result.combined_report is not None:
        return render_markdown(result.combined_report)
    if result.dynamic_report is not None and result.mode == "runtime":
        return render_markdown(result.dynamic_report)
    if result.static_report is not None:
        return render_markdown(result.static_report)
    return ""


def _safe_preview(argv: list[str]) -> list[str]:
    from mcpaegis.lima.guest import redact_argv

    return redact_argv(argv)
