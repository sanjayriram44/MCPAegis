"""Stage 0: launch the MCP server as a local process in a nested cgroup v2."""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Sequence

from mcpaegis.dynamic.errors import DynamicPipelineError, RuntimeUnavailableError

CGROUP_FS = Path("/sys/fs/cgroup")


class ProcessSandboxError(RuntimeUnavailableError):
    """Linux/cgroup v2 missing, or the server process failed to start."""


@dataclass
class SandboxHandle:
    """Live MCP server: nested cgroup inode, stdio pipes, teardown helpers."""

    cgroup_id: str
    cgroup_path: str
    host_cgroup_path: str
    language: str
    workspace_host: Path
    canary_dir: Path
    proc: subprocess.Popen[bytes]
    extra_env: dict[str, str] = field(default_factory=dict)
    stderr_log: Path | None = None
    _stderr_handle: IO[bytes] | None = field(default=None, repr=False)
    _cgroup_dir: Path | None = field(default=None, repr=False)

    @property
    def stdin(self) -> IO[bytes]:
        if self.proc.stdin is None:
            raise DynamicPipelineError("sandbox stdin is not piped")
        return self.proc.stdin

    @property
    def stdout(self) -> IO[bytes]:
        if self.proc.stdout is None:
            raise DynamicPipelineError("sandbox stdout is not piped")
        return self.proc.stdout


def require_linux() -> None:
    """Raise if this host cannot run local-process runtime analysis."""
    system = platform.system()
    if system != "Linux":
        raise RuntimeUnavailableError(
            f"runtime analysis requires Linux with cgroup v2 and eBPF; "
            f"this host is {system}. Run `mcpaegis static` instead, or use a Lima "
            f"Ubuntu VM (see docs/lima-runtime.md)."
        )
    if not (CGROUP_FS / "cgroup.controllers").is_file():
        raise ProcessSandboxError(
            "runtime analysis requires cgroup v2 mounted at /sys/fs/cgroup."
        )


def launch(
    server_path: Path,
    *,
    entrypoint: str,
    language: str = "python",
    canary_dir: Path | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> SandboxHandle:
    """Start the MCP server in a nested cgroup; return a handle with stdio pipes."""
    require_linux()
    server_path = Path(server_path).resolve()
    if not server_path.exists():
        raise DynamicPipelineError(f"server path does not exist: {server_path}")

    canary_dir = Path(canary_dir).resolve() if canary_dir else Path(server_path) / ".mcpaegis-canary"
    canary_dir.mkdir(parents=True, exist_ok=True)

    cmd = resolve_launch_command(entrypoint, language, workspace=server_path)
    binary = cmd[0]
    if shutil.which(binary) is None and not Path(binary).exists():
        raise DynamicPipelineError(
            f"cannot launch MCP server: {binary!r} is not on PATH. "
            "Install the language runtime in the Lima guest (python3 / node)."
        )

    cgroup_dir = _create_nested_cgroup()
    inode = str(cgroup_dir.stat().st_ino)
    env = os.environ.copy()
    env.update(extra_env or {})
    # Fixtures import FastMCP; unbuffered stdio for NDJSON.
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    stderr_log = canary_dir / "sandbox.stderr"
    stderr_handle = stderr_log.open("wb")
    procs_file = cgroup_dir / "cgroup.procs"
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(server_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_handle,
            env=env,
            bufsize=0,
            start_new_session=True,
            preexec_fn=_enter_cgroup_preexec(procs_file),
        )
        _wait_alive(proc, timeout=min(timeout, 5.0))
        if not _pid_in_cgroup(proc.pid, procs_file):
            raise ProcessSandboxError(
                f"server pid {proc.pid} is not in {cgroup_dir}. "
                "Need permission to write cgroup.procs (sudo -E the venv mcpaegis)."
            )
    except Exception:
        if proc is not None:
            _kill_group(proc)
        try:
            stderr_handle.close()
        except OSError:
            pass
        _remove_cgroup(cgroup_dir)
        raise

    return SandboxHandle(
        cgroup_id=inode,
        cgroup_path=str(cgroup_dir),
        host_cgroup_path=str(cgroup_dir),
        language=language,
        workspace_host=server_path,
        canary_dir=canary_dir,
        proc=proc,
        extra_env=dict(extra_env or {}),
        stderr_log=stderr_log,
        _stderr_handle=stderr_handle,
        _cgroup_dir=cgroup_dir,
    )


def teardown(handle: SandboxHandle) -> None:
    """Stop the server process group and remove the nested cgroup."""
    _kill_group(handle.proc)
    if handle._stderr_handle is not None:
        try:
            handle._stderr_handle.close()
        except OSError:
            pass
    if handle._cgroup_dir is not None:
        _remove_cgroup(handle._cgroup_dir)


def read_cgroup_procs(handle: SandboxHandle) -> list[int]:
    """PIDs currently in the nested sandbox cgroup."""
    path = Path(handle.host_cgroup_path) / "cgroup.procs" if handle.host_cgroup_path else None
    if path is None or not path.is_file():
        if handle.proc.poll() is None:
            return [handle.proc.pid]
        return []
    pids: list[int] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
    except OSError:
        if handle.proc.poll() is None:
            return [handle.proc.pid]
    return sorted(set(pids))


def resolve_launch_command(
    entrypoint: str,
    language: str,
    *,
    workspace: Path | None = None,
) -> list[str]:
    """Parse discovery's entrypoint string into an argv for the Lima guest."""
    if not entrypoint or not str(entrypoint).strip():
        raise DynamicPipelineError("server entrypoint is empty; cannot launch sandbox")
    parts = shlex.split(str(entrypoint))
    if not parts:
        if language in {"javascript", "typescript"}:
            parts = ["node", "index.js"]
        else:
            parts = ["python3", "server.py"]
    if parts[0] in {"python", "python3"}:
        # Same interpreter as mcpaegis so `sudo -E venv/bin/mcpaegis` still
        # finds FastMCP installed in that venv — not a bare /usr/bin/python3.
        parts[0] = sys.executable
    if workspace is not None:
        parts = _resolve_relative_paths(parts, Path(workspace))
    return parts


def _resolve_relative_paths(parts: Sequence[str], workspace: Path) -> list[str]:
    mapped: list[str] = []
    for part in parts:
        candidate = Path(part)
        if candidate.is_absolute() or part.startswith("-"):
            mapped.append(part)
            continue
        if "/" in part or part.endswith((".py", ".js", ".mjs", ".cjs", ".ts")):
            mapped.append(str((workspace / part).resolve()))
            continue
        mapped.append(part)
    return mapped


def _enter_cgroup_preexec(procs_file: Path):
    def _inner() -> None:
        fd = -1
        try:
            fd = os.open(str(procs_file), os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("ascii"))
        except OSError as exc:
            os._exit(127 if exc.errno else 1)
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    return _inner


def _create_nested_cgroup() -> Path:
    parent = _current_cgroup_dir()
    name = f"mcpaegis-{os.getpid()}-{int(time.time())}"
    nested = parent / name
    try:
        nested.mkdir(parents=False, exist_ok=False)
        return nested
    except OSError:
        fallback_root = CGROUP_FS / "mcpaegis"
        try:
            fallback_root.mkdir(exist_ok=True)
            nested = fallback_root / name
            nested.mkdir(exist_ok=False)
            return nested
        except OSError as exc:
            raise ProcessSandboxError(
                "cannot create a nested cgroup for eBPF filtering "
                f"(tried {parent / name} and {nested}): {exc}. "
                'Run as root: sudo -E "$HOME/mcpaegis-venv/bin/mcpaegis" runtime …'
            ) from exc


def _current_cgroup_dir() -> Path:
    rel = ""
    try:
        text = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        parts = line.split(":")
        if not parts:
            continue
        if parts[0] == "0" and len(parts) >= 3:
            rel = parts[-1]
            break
        rel = parts[-1]
    if not rel or rel == "/":
        return CGROUP_FS
    path = CGROUP_FS / rel.lstrip("/")
    return path if path.is_dir() else CGROUP_FS


def _pid_in_cgroup(pid: int, procs_file: Path) -> bool:
    try:
        text = procs_file.read_text(encoding="utf-8")
    except OSError:
        return False
    return str(pid) in {line.strip() for line in text.splitlines()}


def _wait_alive(proc: subprocess.Popen[bytes], timeout: float) -> None:
    # Import errors (missing `mcp`) happen immediately; FastMCP bind is next.
    time.sleep(min(0.4, max(float(timeout), 0.1)))
    code = proc.poll()
    if code is not None:
        raise ProcessSandboxError(
            f"MCP server exited immediately (code {code}). "
            "Install the `mcp` package in the guest venv (`pip install mcp`) "
            "and check canaries/sandbox.stderr."
        )


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


def _remove_cgroup(path: Path) -> None:
    try:
        # Move leftovers back to the parent so rmdir succeeds.
        parent_procs = path.parent / "cgroup.procs"
        procs = path / "cgroup.procs"
        if procs.is_file() and parent_procs.is_file():
            for line in procs.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.isdigit():
                    try:
                        parent_procs.write_text(line, encoding="utf-8")
                    except OSError:
                        pass
        path.rmdir()
    except OSError:
        pass
