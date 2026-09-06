"""Guest venv bootstrap and runtime argv (sudo -E, env forwarding)."""

from __future__ import annotations

import io
import os
import tarfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import mcpaegis
from mcpaegis.lima.errors import LimaError
from mcpaegis.lima.paths import (
    GUEST_SRC_NAME,
    GUEST_VENV_NAME,
    LLM_FORWARD_KEYS,
    is_under_home,
    mcpaegis_checkout,
)
from mcpaegis.lima.vm import LogFn, capture_shell, shell

_GUEST_HOME_CACHE: str | None = None


def guest_home(*, limactl: str | None = None, name: str = "mcpaegis") -> str:
    """Linux home inside the guest (``/home/<user>.linux``), not the virtiofs Mac home."""
    global _GUEST_HOME_CACHE
    if _GUEST_HOME_CACHE:
        return _GUEST_HOME_CACHE
    home = capture_shell(["printenv", "HOME"], limactl=limactl, name=name).strip()
    if not home:
        raise LimaError("guest HOME is empty")
    _GUEST_HOME_CACHE = home
    return home


def guest_venv_bin(home: str | None = None, *, limactl: str | None = None) -> str:
    root = home or guest_home(limactl=limactl)
    return f"{root}/{GUEST_VENV_NAME}/bin"


def guest_mcpaegis(home: str | None = None, *, limactl: str | None = None) -> str:
    return f"{guest_venv_bin(home, limactl=limactl)}/mcpaegis"


def llm_env_from_os(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    src = environ if environ is not None else os.environ
    return {key: src[key] for key in LLM_FORWARD_KEYS if src.get(key)}


def llm_env_from_config(config: object | None) -> dict[str, str]:
    """Forward only the session's LLM settings (TUI model toggle / off)."""
    if config is None:
        return {}
    api_key = getattr(config, "api_key", None)
    if not api_key:
        return {}
    env = {"MCPAEGIS_LLM_API_KEY": str(api_key)}
    base_url = getattr(config, "base_url", None)
    model = getattr(config, "model", None)
    if base_url:
        env["MCPAEGIS_LLM_BASE_URL"] = str(base_url)
    if model:
        env["MCPAEGIS_LLM_MODEL"] = str(model)
    return env


def runtime_argv(
    *,
    server_path: Path | str,
    output_dir: Path | str,
    test_script: Path | str | None = None,
    timeout: int | None = 30,
    extra_env: Mapping[str, str] | None = None,
    mcpaegis_bin: str,
    no_color: bool = True,
) -> list[str]:
    """``env … sudo -n -E <venv>/mcpaegis runtime …`` for ``limactl shell --``."""
    inner: list[str] = [
        "sudo",
        "-n",
        "-E",
        mcpaegis_bin,
        "runtime",
        str(server_path),
        "--output",
        str(output_dir),
    ]
    if no_color:
        inner.append("--no-color")
    if test_script is not None:
        inner.extend(["--test-script", str(test_script)])
    if timeout is not None:
        inner.extend(["--timeout", str(int(timeout))])
    env = dict(extra_env or {})
    if not env:
        return inner
    prefix = ["env"]
    for key, value in env.items():
        prefix.append(f"{key}={value}")
    return prefix + inner


def venv_ready(*, limactl: str | None = None, name: str = "mcpaegis") -> bool:
    script = (
        f'test -x "$HOME/{GUEST_VENV_NAME}/bin/mcpaegis" && '
        f'"$HOME/{GUEST_VENV_NAME}/bin/python" -c "import bcc, mcpaegis"'
    )
    try:
        capture_shell(["bash", "-lc", script], limactl=limactl, name=name)
    except LimaError:
        return False
    return True


def probe_guest(*, limactl: str | None = None, name: str = "mcpaegis") -> dict[str, str | bool]:
    script = r"""
set -e
echo "HOME=$HOME"
uname -s -r -m
if test -e /sys/kernel/btf/vmlinux; then echo BTF=yes; else echo BTF=no; fi
if test -f /sys/fs/cgroup/cgroup.controllers; then echo CGROUP=yes; else echo CGROUP=no; fi
if test -x "$HOME/mcpaegis-venv/bin/mcpaegis"; then echo VENV=yes; else echo VENV=no; fi
if "$HOME/mcpaegis-venv/bin/python" -c "import bcc" 2>/dev/null; then echo BCC=yes; else echo BCC=no; fi
"""
    text = capture_shell(["bash", "-lc", script], limactl=limactl, name=name)
    parsed: dict[str, str | bool] = {"raw": text}
    for line in text.splitlines():
        if line.startswith("HOME="):
            parsed["home"] = line.split("=", 1)[1]
        elif line.startswith("Linux") or line.startswith("linux"):
            parsed["uname"] = line
        elif "=" in line:
            key, _, value = line.partition("=")
            parsed[key.lower()] = value.strip().lower() in {"yes", "true", "1"}
    return parsed


def ensure_venv(
    *,
    limactl: str | None = None,
    name: str = "mcpaegis",
    log: LogFn | None = None,
) -> str:
    """Create ``$HOME/mcpaegis-venv`` in the guest and install MCPAegis + mcp."""
    write = log or (lambda _m: None)
    home = guest_home(limactl=limactl, name=name)
    src = _guest_install_src(limactl=limactl, name=name, log=write)
    write(f"Guest venv at {home}/{GUEST_VENV_NAME} (system-site-packages for Ubuntu bcc)")
    script = f"""
set -euo pipefail
python3 -m venv --system-site-packages "$HOME/{GUEST_VENV_NAME}"
"$HOME/{GUEST_VENV_NAME}/bin/pip" install -U pip
"$HOME/{GUEST_VENV_NAME}/bin/pip" install -e "{src}[runtime]"
"$HOME/{GUEST_VENV_NAME}/bin/python" -c "import bcc, mcpaegis"
test -x "$HOME/{GUEST_VENV_NAME}/bin/mcpaegis"
"""
    shell(["bash", "-lc", script], limactl=limactl, name=name, log=write, check=True)
    return guest_mcpaegis(home, limactl=limactl)


def _guest_install_src(*, limactl: str | None, name: str, log: LogFn) -> str:
    checkout = mcpaegis_checkout()
    if checkout is not None and is_under_home(checkout):
        log(f"Installing MCPAegis from shared checkout {checkout}")
        return str(checkout)
    dest = f"$HOME/{GUEST_SRC_NAME}"
    log("Checkout is not under ~ (or this is a wheel install); copying package into the guest home")
    payload = _source_tarball()
    _push_tarball(payload, dest=dest, limactl=limactl, name=name)
    return f"{guest_home(limactl=limactl, name=name)}/{GUEST_SRC_NAME}"


def _source_tarball() -> bytes:
    pkg = Path(mcpaegis.__file__).resolve().parent
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(pkg, arcname="mcpaegis")
        pyproject = (
            "[build-system]\n"
            'requires = ["setuptools>=68", "wheel"]\n'
            'build-backend = "setuptools.build_meta"\n\n'
            "[project]\n"
            'name = "mcpaegis"\n'
            'version = "0.1.0"\n'
            'requires-python = ">=3.11"\n'
            "dependencies = [\n"
            '    "pydantic>=2.0",\n'
            '    "typer>=0.12",\n'
            '    "textual>=0.80",\n'
            "]\n\n"
            "[project.optional-dependencies]\n"
            "runtime = [\n"
            '    "mcp>=1.2,<2",\n'
            "]\n\n"
            "[project.scripts]\n"
            'mcpaegis = "mcpaegis.cli:app"\n\n'
            "[tool.setuptools.packages.find]\n"
            'include = ["mcpaegis*"]\n'
        ).encode("utf-8")
        info = tarfile.TarInfo(name="pyproject.toml")
        info.size = len(pyproject)
        tar.addfile(info, io.BytesIO(pyproject))
    return buf.getvalue()


def _push_tarball(data: bytes, *, dest: str, limactl: str | None, name: str) -> None:
    """Extract a gzip tar in the guest. ``dest`` may use ``$HOME``."""
    import base64
    import subprocess as sp

    from mcpaegis.lima.vm import find_limactl

    binary = limactl or find_limactl()
    if not binary:
        raise LimaError("limactl is not on PATH")
    b64 = base64.b64encode(data).decode("ascii")
    script = (
        f"mkdir -p {dest} && rm -rf {dest}/* {dest}/.[!.]* 2>/dev/null || true; "
        f"python3 -c \"import base64,sys,tarfile,io,os; "
        f"os.chdir(os.path.expandvars('{dest}')); "
        f"raw=base64.b64decode(sys.stdin.read()); "
        f"tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz').extractall('.')\""
    )
    proc = sp.run(
        [binary, "shell", name, "--", "bash", "-lc", script],
        input=b64,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise LimaError(f"failed to copy MCPAegis sources into the guest: {proc.stderr or proc.stdout}")


def local_runtime_argv(
    *,
    server_path: Path | str,
    output_dir: Path | str,
    test_script: Path | str | None = None,
    timeout: int | None = 30,
    mcpaegis_bin: str | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> list[str]:
    """Runtime on an already-Linux host (inside the VM or native Linux)."""
    bin_path = mcpaegis_bin or _local_mcpaegis_bin()
    need_sudo = hasattr(os, "geteuid") and os.geteuid() != 0
    inner = [
        bin_path,
        "runtime",
        str(server_path),
        "--output",
        str(output_dir),
        "--no-color",
    ]
    if test_script is not None:
        inner.extend(["--test-script", str(test_script)])
    if timeout is not None:
        inner.extend(["--timeout", str(int(timeout))])
    if need_sudo:
        inner = ["sudo", "-n", "-E", *inner]
    env = dict(extra_env or {})
    if env:
        prefix = ["env"]
        for key, value in env.items():
            prefix.append(f"{key}={value}")
        return prefix + inner
    return inner


def _local_mcpaegis_bin() -> str:
    import sys

    sibling = Path(sys.executable).resolve().parent / "mcpaegis"
    if sibling.is_file():
        return str(sibling)
    return "mcpaegis"


def redact_argv(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    secret_keys = ("KEY", "TOKEN", "SECRET", "PASSWORD")
    for item in argv:
        if "=" in item and any(token in item.split("=", 1)[0].upper() for token in secret_keys):
            key, _, _ = item.partition("=")
            redacted.append(f"{key}=***")
        else:
            redacted.append(item)
    return list(redacted)
