"""Install/start the Lima instance and run commands in the guest."""

from __future__ import annotations

import os
import platform
import select
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from mcpaegis.lima.doctor import INSTANCE_NAME, LimaInstance, instance_named, parse_limactl_list
from mcpaegis.lima.errors import LimaError
from mcpaegis.lima.paths import lima_yaml_path
from mcpaegis.lima.stream import split_stream

LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]

_LIMACTL_CANDIDATES = (
    Path("/opt/homebrew/bin/limactl"),
    Path("/usr/local/bin/limactl"),
)


def _noop_log(_line: str) -> None:
    return


def find_limactl() -> str | None:
    found = shutil.which("limactl")
    if found:
        return found
    extra = list(_LIMACTL_CANDIDATES)
    homebrew = Path.home() / "homebrew" / "bin" / "limactl"
    extra.append(homebrew)
    for path in extra:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def find_brew() -> str | None:
    for candidate in (shutil.which("brew"), "/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def ensure_lima_cli(*, log: LogFn = _noop_log, cancel: CancelFn | None = None) -> str:
    """Return ``limactl`` path, installing Lima via Homebrew if needed."""
    existing = find_limactl()
    if existing:
        log(f"limactl: {existing}")
        return existing
    if platform.system() != "Darwin":
        raise LimaError("limactl is not on PATH (Lima is only auto-installed on macOS).")
    brew = find_brew()
    if not brew:
        raise LimaError(
            "Lima is not installed and Homebrew was not found. Install Homebrew from "
            "https://brew.sh then re-run, or `brew install lima` yourself."
        )
    log("Installing Lima with Homebrew (brew install lima)…")
    code = run_streaming([brew, "install", "lima"], log=log, cancel=cancel)
    if code != 0:
        raise LimaError(f"brew install lima failed with exit {code}")
    os.environ["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "")
    installed = find_limactl()
    if not installed:
        raise LimaError("brew install lima finished but limactl is still not on PATH")
    log(f"limactl: {installed}")
    return installed


def list_instances(limactl: str) -> list[LimaInstance]:
    proc = subprocess.run(
        [limactl, "list", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    text = proc.stdout or ""
    if proc.returncode != 0 or not text.strip():
        proc = subprocess.run(
            [limactl, "list"],
            capture_output=True,
            text=True,
            check=False,
        )
        text = proc.stdout or ""
    return parse_limactl_list(text)


def ensure_instance(
    *,
    limactl: str | None = None,
    name: str = INSTANCE_NAME,
    yaml_path: Path | None = None,
    log: LogFn = _noop_log,
    cancel: CancelFn | None = None,
) -> LimaInstance:
    """Create or start the MCPAegis Lima VM. First boot downloads Ubuntu (minutes)."""
    if platform.system() == "Darwin":
        machine = platform.machine()
        if machine not in {"arm64", "aarch64"}:
            raise LimaError(
                f"Apple Silicon required for the bundled vz aarch64 guest; this host is {machine}."
            )
    binary = limactl or ensure_lima_cli(log=log, cancel=cancel)
    current = instance_named(list_instances(binary), name)
    if current is not None and current.running:
        log(f"Lima instance {name!r} already running ({current.vm_type or 'vz'}).")
        return current
    yaml_file = yaml_path or lima_yaml_path()
    # ``-y`` / ``--tty=false`` is required: a PTY or real TTY otherwise opens
    # Lima's "Proceed with the current configuration" wizard and hangs forever.
    if current is None:
        log(f"Creating Lima instance {name!r} from {yaml_file}")
        log("First start downloads Ubuntu (~600MB) and can take several minutes. Logs should keep moving.")
        argv = [binary, "start", "-y", "--progress", f"--name={name}", str(yaml_file)]
    else:
        log(f"Starting stopped Lima instance {name!r}…")
        argv = [binary, "start", "-y", "--progress", name]
    code = run_streaming(argv, log=log, cancel=cancel)
    if code != 0:
        raise LimaError(f"limactl start failed with exit {code}")
    deadline = time.time() + 90
    while time.time() < deadline:
        current = instance_named(list_instances(binary), name)
        if current is not None and current.running:
            log(f"Lima instance {name!r} is Running.")
            return current
        time.sleep(1)
    raise LimaError(f"Lima instance {name!r} did not reach Running")


def stop_instance(
    *,
    limactl: str | None = None,
    name: str = INSTANCE_NAME,
    log: LogFn = _noop_log,
    cancel: CancelFn | None = None,
) -> None:
    """Stop the shared VM so host RAM/CPU are freed. Disk and guest venv stay."""
    binary = limactl or find_limactl()
    if not binary:
        log("limactl is not on PATH; skipping Lima stop.")
        return
    current = instance_named(list_instances(binary), name)
    if current is None:
        log(f"Lima instance {name!r} is not present.")
        return
    if not current.running:
        log(f"Lima instance {name!r} already stopped.")
        return
    log(f"Stopping Lima instance {name!r} to free host resources…")
    code = run_streaming([binary, "stop", "-y", name], log=log, cancel=cancel)
    if code != 0:
        log(f"warning: limactl stop failed with exit {code}")
        return
    log(f"Lima instance {name!r} stopped. Disk kept for the next start.")


def shell(
    argv: Sequence[str],
    *,
    limactl: str | None = None,
    name: str = INSTANCE_NAME,
    env: Mapping[str, str] | None = None,
    log: LogFn = _noop_log,
    cancel: CancelFn | None = None,
    check: bool = True,
) -> int:
    """Run ``argv`` inside the guest. Does not inherit the Mac environment."""
    binary = limactl or find_limactl()
    if not binary:
        raise LimaError("limactl is not on PATH")
    wrapped = _wrap_env(list(argv), env)
    cmd = [binary, "shell", name, "--", *wrapped]
    code = run_streaming(cmd, log=log, cancel=cancel)
    if check and code != 0:
        raise LimaError(f"guest command failed with exit {code}: {' '.join(argv[:6])}")
    return code


def capture_shell(
    argv: Sequence[str],
    *,
    limactl: str | None = None,
    name: str = INSTANCE_NAME,
    env: Mapping[str, str] | None = None,
) -> str:
    binary = limactl or find_limactl()
    if not binary:
        raise LimaError("limactl is not on PATH")
    wrapped = _wrap_env(list(argv), env)
    proc = subprocess.run(
        [binary, "shell", name, "--", *wrapped],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise LimaError(f"guest command failed: {err or proc.returncode}")
    return proc.stdout


def run_streaming(
    argv: Sequence[str],
    *,
    log: LogFn = _noop_log,
    cancel: CancelFn | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Run a host process, stream stdout/stderr, emit a heartbeat every 5s."""
    merged = os.environ.copy()
    merged["PYTHONUNBUFFERED"] = "1"
    if env:
        merged.update(env)
    log("$ " + " ".join(_redact(argv)))
    # Pipes, not a PTY: Lima treats a PTY as an interactive TTY and blocks on
    # the instance-config wizard. Heartbeats still fire every 5s.
    return _run_pipes(list(argv), log=log, cancel=cancel, cwd=cwd, env=merged)


def _run_pipes(
    argv: list[str],
    *,
    log: LogFn,
    cancel: CancelFn | None,
    cwd: Path | None,
    env: dict[str, str],
) -> int:
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(cwd) if cwd else None,
        env=env,
        start_new_session=True,
        bufsize=0,
    )
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    buf = b""
    start = time.time()
    last_beat = start
    try:
        while True:
            if cancel is not None and cancel():
                _kill_group(proc)
                log("cancelled")
                break
            ready, _, _ = select.select([fd], [], [], 0.5)
            if ready:
                chunk = os.read(fd, 4096)
                if chunk:
                    buf += chunk
                    lines, buf = split_stream(buf)
                    for line in lines:
                        log(line)
                elif proc.poll() is not None:
                    if buf.strip():
                        extra, _ = split_stream(buf + b"\n")
                        for line in extra:
                            log(line)
                    break
            elif proc.poll() is not None:
                try:
                    leftover = os.read(fd, 4096)
                except OSError:
                    leftover = b""
                buf += leftover
                if buf.strip():
                    extra, _ = split_stream(buf + b"\n")
                    for line in extra:
                        log(line)
                break
            now = time.time()
            if now - last_beat >= 5:
                name = Path(argv[0]).name
                log(f"… still working ({int(now - start)}s) — {name}")
                last_beat = now
    finally:
        if proc.poll() is None:
            _kill_group(proc)
            proc.wait(timeout=8)
    return int(proc.returncode or 0)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.pid is None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except OSError:
            return


def _wrap_env(argv: list[str], env: Mapping[str, str] | None) -> list[str]:
    if not env:
        return argv
    prefix = ["env"]
    for key, value in env.items():
        if not key or any(ch in key for ch in " =\n"):
            continue
        prefix.append(f"{key}={value}")
    return prefix + argv


def _redact(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    secret_keys = ("KEY", "TOKEN", "SECRET", "PASSWORD")
    for item in argv:
        if "=" in item and any(token in item.split("=", 1)[0].upper() for token in secret_keys):
            key, _, _ = item.partition("=")
            redacted.append(f"{key}=***")
        else:
            redacted.append(item)
    return redacted
