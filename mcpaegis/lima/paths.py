"""Shared path helpers: Mac home must be the Lima virtiofs mount."""

from __future__ import annotations

import shutil
from pathlib import Path

from mcpaegis.lima.errors import PathNotSharedError

INSTANCE_NAME = "mcpaegis"
GUEST_VENV_NAME = "mcpaegis-venv"
GUEST_SRC_NAME = "mcpaegis-src"
STAGED_DIR_NAME = "mcpaegis-servers"
COPY_IGNORE_NAMES = frozenset(
    {
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
    }
)

LLM_FORWARD_KEYS = (
    "OPENAI_API_KEY",
    "MCPAEGIS_LLM_API_KEY",
    "MCPAEGIS_LLM_BASE_URL",
    "MCPAEGIS_LLM_MODEL",
)


def lima_yaml_path() -> Path:
    """Packaged guest config; fall back to the repo-root copy."""
    packaged = Path(__file__).resolve().with_name("lima.yaml")
    if packaged.is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "lima.yaml"
    if repo.is_file():
        return repo
    raise FileNotFoundError("lima.yaml is not packaged and was not found at the repo root")


def host_home() -> Path:
    return Path.home().expanduser().resolve()


def is_under_home(path: Path | str, home: Path | None = None) -> bool:
    """True when ``path`` resolves inside the host home directory."""
    root = (home or host_home()).resolve()
    try:
        Path(path).expanduser().resolve().relative_to(root)
    except (ValueError, OSError):
        return False
    return True


def require_under_home(path: Path | str, *, home: Path | None = None, what: str = "path") -> Path:
    """Resolve ``path`` and refuse anything Lima will not mount (outside ``~``)."""
    root = (home or host_home()).resolve()
    resolved = Path(path).expanduser().resolve()
    if not is_under_home(resolved, root):
        raise PathNotSharedError(
            f"{what} {resolved} is outside {root}. Lima only shares your home directory; "
            "move or copy the MCP server (and output dir) under ~."
        )
    return resolved


def mcpaegis_checkout() -> Path | None:
    """Editable checkout if this install still lives in the source tree."""
    root = Path(__file__).resolve().parents[2]
    if (root / "pyproject.toml").is_file() and (root / "mcpaegis").is_dir():
        return root
    return None


def default_output_dir(server_path: Path, home: Path | None = None) -> Path:
    """TUI default: always under the Mac home so the guest can write reports."""
    return (home or host_home()) / "mcpaegis-out" / server_path.name


def staged_root(home: Path | None = None) -> Path:
    return (home or host_home()).resolve() / STAGED_DIR_NAME


def _ignore_copy(directory: str, names: list[str]) -> set[str]:
    _ = directory
    return {name for name in names if name in COPY_IGNORE_NAMES}


def stage_under_home(path: Path | str, *, home: Path | None = None) -> Path:
    """Copy ``path`` into ``~/mcpaegis-servers`` when it is outside home.

    Paths already under home are returned unchanged. Lima only mounts ``~``.
    """
    root = (home or host_home()).resolve()
    resolved = Path(path).expanduser().resolve()
    if is_under_home(resolved, root):
        return resolved
    dest_root = staged_root(root)
    dest_root.mkdir(parents=True, exist_ok=True)
    dest = dest_root / resolved.name
    try:
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        if resolved.is_dir():
            shutil.copytree(resolved, dest, ignore=_ignore_copy, symlinks=False)
            return dest
        dest.mkdir(parents=True, exist_ok=True)
        copied = dest / resolved.name
        shutil.copy2(resolved, copied)
        return copied
    except OSError as exc:
        raise PathNotSharedError(
            f"could not copy {resolved} into {dest_root} so Lima can see it: {exc}"
        ) from exc


def stage_file_under_home(
    path: Path | str,
    *,
    dest_dir: Path | None = None,
    home: Path | None = None,
) -> Path:
    """Copy a single file under home (test scripts outside ``~``)."""
    root = (home or host_home()).resolve()
    resolved = Path(path).expanduser().resolve()
    if is_under_home(resolved, root):
        return resolved
    target_dir = dest_dir if dest_dir is not None else staged_root(root) / "_scripts"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / resolved.name
        shutil.copy2(resolved, dest)
        return dest
    except OSError as exc:
        raise PathNotSharedError(
            f"could not copy test script {resolved} into {target_dir}: {exc}"
        ) from exc


PLACEHOLDER_SCRIPTS = frozenset(
    {
        "",
        "runtime.yaml  — optional",
        "runtime.yaml — optional",
    }
)


def resolve_test_script(
    server_path: Path,
    test_script: Path | str | None,
    *,
    home: Path | None = None,
    require_shared: bool = False,
) -> Path | None:
    """Resolve ``--test-script``. Relative names are tried next to the server, then cwd.

    Empty / placeholder strings mean auto-args (no script). Bare ``runtime.yaml``
    uses ``<server>/runtime.yaml`` when that file exists.
    """
    if test_script is None:
        return None
    raw = str(test_script).strip()
    if raw in PLACEHOLDER_SCRIPTS:
        return None
    path = Path(raw).expanduser()
    candidates: list[Path] = []
    if not path.is_absolute():
        candidates.append((server_path / path).resolve())
        candidates.append((Path.cwd() / path).resolve())
    else:
        candidates.append(path.resolve())
    for candidate in candidates:
        if candidate.is_file():
            if require_shared:
                return require_under_home(candidate, home=home, what="test script")
            return candidate
    raise FileNotFoundError(
        f"test script does not exist: {raw} (looked next to the server and in the current directory)"
    )
