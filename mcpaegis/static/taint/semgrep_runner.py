"""Lane B: Semgrep pattern sinks (proximate) plus taint-mode dataflow (direct)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from mcpaegis.core.models import CodeCapability, SinkFact, ToolMetadata
from mcpaegis.core.taxonomy import SINK_TO_CAPABILITY, Capability, SinkType
from mcpaegis.static.taint.call_graph import (
    CallGraph,
    build_python_call_graph,
    function_at,
    js_function_name_near,
    reverse_paths,
)

RULES_DIR = Path(__file__).resolve().parent / "rules"
TAINT_RULES_DIR = RULES_DIR / "taint"
PATTERN_RULE_FILES = ("python.yaml", "javascript.yaml")
MAX_HOPS = 10


def rules_dir() -> Path:
    return RULES_DIR


def run(
    target: Path,
    tools: list[ToolMetadata],
    *,
    language: str = "python",
) -> list[SinkFact]:
    """Run Semgrep against ``target`` and attribute sinks to tools.

    Pattern-pack hits are call-graph reachability only (``confidence="proximate"``).
    Taint-mode hits are parameter-to-sink dataflow (``confidence="direct"``).
    Shared helpers emit one ``SinkFact`` per attributing tool.
    If Semgrep is missing or fails, returns an empty list (static still proceeds).
    """
    target = Path(target)
    if _semgrep_cmd() is None:
        warnings.warn(
            "semgrep is not on PATH (sudo often uses secure_path and drops the venv). "
            "Install it in the same environment as mcpaegis (`pip install semgrep`) "
            "or run `mcpaegis static` without sudo. Stage 3 sinks will be empty.",
            UserWarning,
            stacklevel=2,
        )
        return []

    pattern_results = _semgrep_json(_pattern_configs(), target)
    proximate = _facts_from_results(
        target,
        tools,
        pattern_results,
        language=language,
        force_confidence="proximate",
    )

    taint_results = _run_taint(target, tools, language=language)
    direct = _facts_from_results(
        target,
        tools,
        taint_results,
        language=language,
        force_confidence="direct",
    )
    return _merge_facts(proximate, direct)


def derive_code_capabilities(sinks: list[SinkFact]) -> list[CodeCapability]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for sink in sinks:
        if not sink.tool_name:
            continue
        cap = SINK_TO_CAPABILITY.get(sink.sink_type)
        if cap is None:
            continue
        key = (sink.tool_name, cap.value)
        grouped.setdefault(key, []).append(sink.id)
    out: list[CodeCapability] = []
    for (tool_name, cap_value), refs in grouped.items():
        out.append(
            CodeCapability(
                tool_name=tool_name,
                capability=Capability(cap_value),
                sink_refs=sorted(set(refs)),
            )
        )
    return out


def max_confidence_by_tool_capability(
    sinks: list[SinkFact],
) -> dict[tuple[str, Capability], str]:
    """Map (tool_name, capability) to the strongest sink confidence."""
    rank = {"proximate": 1, "direct": 2}
    best: dict[tuple[str, Capability], str] = {}
    for sink in sinks:
        if not sink.tool_name:
            continue
        cap = SINK_TO_CAPABILITY.get(sink.sink_type)
        if cap is None:
            continue
        key = (sink.tool_name, cap)
        prev = best.get(key)
        if prev is None or rank.get(sink.confidence, 0) > rank.get(prev, 0):
            best[key] = sink.confidence
    return best


def _pattern_configs() -> list[str]:
    return [str(RULES_DIR / name) for name in PATTERN_RULE_FILES if (RULES_DIR / name).is_file()]


def _run_taint(
    target: Path,
    tools: list[ToolMetadata],
    *,
    language: str,
) -> list[dict[str, Any]]:
    if not TAINT_RULES_DIR.is_dir():
        return []
    configs = [str(TAINT_RULES_DIR)]
    generated = _handler_taint_yaml(tools, language=language)
    tmp_path: Path | None = None
    try:
        if generated:
            handle = tempfile.NamedTemporaryFile(
                "w",
                suffix="-mcpaegis-taint.yaml",
                delete=False,
                encoding="utf-8",
            )
            handle.write(generated)
            handle.close()
            tmp_path = Path(handle.name)
            configs.append(str(tmp_path))
        return _semgrep_json(configs, target)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _handler_taint_yaml(tools: list[ToolMetadata], *, language: str) -> str | None:
    """Generate per-file taint sources so same-named helpers in other modules are not tainted."""
    by_file: dict[str, list[str]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for tool in tools:
        loc = tool.source_location
        fn = loc.function_name if loc else None
        if loc is None or not fn or not fn.isidentifier():
            continue
        file_key = str(Path(loc.file))
        pair = (file_key, fn)
        if pair in seen:
            continue
        seen.add(pair)
        by_file[file_key].append(fn)
    if not by_file:
        return None

    js = language in {"javascript", "typescript"}
    lang_yaml = "[javascript, typescript]" if js else "[python]"
    sinks_by_type = _JS_TAINT_SINKS if js else _PYTHON_TAINT_SINKS
    source_fn = _js_handler_sources if js else _python_handler_sources

    rules: list[str] = []
    rule_i = 0
    for file_path, names in sorted(by_file.items()):
        include = _yaml_quote(file_path)
        sources = source_fn(names)
        for sink_type, sink_patterns in sinks_by_type.items():
            sink_block = "\n".join(f"      - pattern: {pat}" for pat in sink_patterns)
            sanitizers = _TAINT_SANITIZERS.get((language, sink_type), ())
            if js:
                sanitizers = _TAINT_SANITIZERS.get(("javascript", sink_type), sanitizers)
            sanitizer_block = ""
            if sanitizers:
                sanitizer_block = "\n    pattern-sanitizers:\n" + "\n".join(
                    f"      - pattern: {pat}" for pat in sanitizers
                )
            rules.append(
                "\n".join(
                    [
                        f"  - id: mcpaegis.generated.taint.{sink_type}.{rule_i}",
                        "    mode: taint",
                        f"    message: Tool handler parameter flows into {sink_type} sink",
                        f"    languages: {lang_yaml}",
                        "    severity: ERROR",
                        "    metadata:",
                        f"      sink_type: {sink_type}",
                        "    paths:",
                        "      include:",
                        f"        - {include}",
                        "    pattern-sources:",
                        sources,
                        "    pattern-sinks:",
                        sink_block,
                    ]
                )
                + sanitizer_block
            )
            rule_i += 1
    return "rules:\n" + "\n\n".join(rules) + "\n"


def _yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _python_handler_sources(names: list[str]) -> str:
    lines: list[str] = []
    for name in names:
        for prefix in ("def", "async def"):
            lines.append("      - pattern: |")
            lines.append(f"          {prefix} {name}(...):")
            lines.append("            ...")
    return "\n".join(lines)


def _js_handler_sources(names: list[str]) -> str:
    lines: list[str] = []
    for name in names:
        lines.append(f"      - pattern: function {name}(...) {{ ... }}")
        lines.append(f"      - pattern: async function {name}(...) {{ ... }}")
        lines.append(f"      - pattern: const {name} = (...) => {{ ... }}")
        lines.append(f"      - pattern: const {name} = async (...) => {{ ... }}")
    return "\n".join(lines)


_PYTHON_TAINT_SINKS: dict[str, tuple[str, ...]] = {
    "shell_exec": (
        "subprocess.run(...)",
        "subprocess.Popen(...)",
        "subprocess.call(...)",
        "os.system(...)",
        "os.popen(...)",
    ),
    "file_read": (
        "open($PATH)",
        "open($PATH, ...)",
        'open($PATH, "r", ...)',
        "Path($PATH).read_text(...)",
        "Path($PATH).read_bytes(...)",
    ),
    "file_write": (
        'open($PATH, "w", ...)',
        'open($PATH, "wb", ...)',
        'open($PATH, "a", ...)',
        "Path($PATH).write_text(...)",
        "os.remove(...)",
    ),
    "network_call": (
        "requests.$METHOD(...)",
        "httpx.$METHOD(...)",
        "urllib.request.urlopen(...)",
    ),
    "db_query": (
        "$CUR.execute(...)",
        "$CUR.executemany(...)",
    ),
    "dynamic_code_load": (
        "eval(...)",
        "exec(...)",
    ),
}

# Sanitizers apply only to generated taint rules for the matching sink type.
# Shell quoting does not make a filesystem or eval sink safe.
_TAINT_SANITIZERS: dict[tuple[str, str], tuple[str, ...]] = {
    ("python", "shell_exec"): (
        "shlex.quote(...)",
        "shlex.split(...)",
        "shlex.join(...)",
    ),
    ("javascript", "shell_exec"): (
        "shellQuote(...)",
    ),
}


_JS_TAINT_SINKS: dict[str, tuple[str, ...]] = {
    "shell_exec": (
        "child_process.exec(...)",
        "exec(...)",
        "execSync(...)",
    ),
    "file_read": (
        "fs.readFile(...)",
        "fs.readFileSync(...)",
    ),
    "file_write": (
        "fs.writeFile(...)",
        "fs.writeFileSync(...)",
    ),
    "network_call": (
        "fetch(...)",
        "axios.$METHOD(...)",
    ),
    "db_query": (
        "$DB.query(...)",
        "$DB.execute(...)",
    ),
    "dynamic_code_load": (
        "eval(...)",
        "Function(...)",
    ),
}


def _semgrep_bin() -> str | None:
    """Return a semgrep executable path, or None. Prefer ``_semgrep_cmd``."""
    cmd = _semgrep_cmd()
    if cmd is None:
        return None
    return cmd[-1] if cmd[:2] == [sys.executable, "-m"] else cmd[0]


def _semgrep_cmd() -> list[str] | None:
    """Locate Semgrep even when sudo strips PATH.

    Order: PATH, venv sibling of this interpreter, ``python -m semgrep``,
    then the invoking user's PATH (``SUDO_USER``).
    """
    found = shutil.which("semgrep")
    if found:
        return [found]
    # Do not resolve() the interpreter first: on macOS the venv python is a
    # symlink into Homebrew Cellar, and that bin/ has no semgrep.
    sibling = Path(sys.executable).parent / "semgrep"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return [str(sibling)]
    if _python_module_works(sys.executable, "semgrep"):
        return [sys.executable, "-m", "semgrep"]
    for directory in _extra_bin_dirs():
        candidate = Path(directory) / "semgrep"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]
        python = Path(directory) / "python3"
        if python.is_file() and _python_module_works(str(python), "semgrep"):
            return [str(python), "-m", "semgrep"]
    return None


def _python_module_works(python: str, module: str) -> bool:
    try:
        completed = subprocess.run(
            [python, "-c", f"import {module}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _extra_bin_dirs() -> list[str]:
    dirs: list[str] = []
    homes: list[Path] = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        homes.append(Path("/home") / sudo_user)
    home_env = os.environ.get("HOME")
    if home_env:
        homes.append(Path(home_env))
    for home in homes:
        dirs.extend(
            [
                str(home / "mcpaegis-venv" / "bin"),
                str(home / ".local" / "bin"),
            ]
        )
    path = os.environ.get("PATH") or ""
    dirs.extend(part for part in path.split(":") if part)
    seen: list[str] = []
    for item in dirs:
        if item and item not in seen:
            seen.append(item)
    return seen


def _semgrep_json(configs: list[str], target: Path) -> list[dict[str, Any]]:
    if not configs:
        return []
    binary = _semgrep_cmd()
    if binary is None:
        return []
    # Default .semgrepignore skips tests/; --x-ignore-semgrepignore-files is
    # required to scan fixture trees and other paths Semgrep would drop.
    cmd = [
        *binary,
        "--json",
        "--quiet",
        "--metrics=off",
        "--x-ignore-semgrepignore-files",
        str(target),
    ]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not completed.stdout.strip():
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    results = payload.get("results") or []
    return results if isinstance(results, list) else []


def _entrypoint_index(tools: list[ToolMetadata]) -> dict[str, str]:
    index: dict[str, str] = {}
    for tool in tools:
        loc = tool.source_location
        if loc is None or not loc.function_name:
            continue
        index[f"{Path(loc.file).resolve()}:{loc.function_name}"] = tool.name
        # Unqualified name only when unique across tools.
        index.setdefault(loc.function_name, tool.name)
    return index


def _tools_at(file: Path, line: int, function_name: str, tools: list[ToolMetadata]) -> list[str]:
    file_r = file.resolve()
    names: list[str] = []
    for tool in tools:
        loc = tool.source_location
        if loc is None:
            continue
        try:
            loc_file = Path(loc.file).resolve()
        except OSError:
            loc_file = Path(loc.file)
        if loc_file != file_r:
            continue
        if loc.function_name and loc.function_name == function_name:
            names.append(tool.name)
        elif loc.line == line:
            names.append(tool.name)
    return list(dict.fromkeys(names))


def _sink_snippet(path: Path, line: int, extra: dict[str, Any]) -> str:
    """Prefer the sink source line over Semgrep's ``extra.lines`` blob.

    ``extra.lines`` is often a multi-line window (or unrelated nearby text)
    rather than the matched call. File+line on the finding are authoritative.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:500]
    except OSError:
        pass
    raw = extra.get("message") if isinstance(extra.get("message"), str) else ""
    if not raw:
        raw = extra.get("lines") if isinstance(extra.get("lines"), str) else ""
    return raw.strip().splitlines()[0].strip()[:500] if raw.strip() else ""


def _facts_from_results(
    root: Path,
    tools: list[ToolMetadata],
    results: list[dict[str, Any]],
    *,
    language: str,
    force_confidence: str,
) -> list[SinkFact]:
    graph = build_python_call_graph(root) if language == "python" else None
    entrypoints = _entrypoint_index(tools)
    facts: list[SinkFact] = []
    for item in results:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        sink_raw = metadata.get("sink_type")
        if not sink_raw:
            continue
        try:
            sink_type = SinkType(sink_raw)
        except ValueError:
            continue
        raw_path = Path(item.get("path") or "")
        path = (raw_path if raw_path.is_absolute() else (root / raw_path)).resolve()
        start = item.get("start") or {}
        line = int(start.get("line") or 1)
        snippet = _sink_snippet(path, line, extra)
        rule_id = str(item.get("check_id") or "unknown")

        function_name = "<unknown>"
        taint_path_default: list[str] = []
        if graph is not None and path.suffix == ".py":
            fn = function_at(graph, path, line)
            if fn is not None:
                function_name = fn.name
                taint_path_default = [fn.name]
        elif path.suffix in {".js", ".ts", ".mjs", ".cjs"}:
            function_name = js_function_name_near(path, line)
            taint_path_default = [function_name] if function_name != "<unknown>" else []

        dataflow = _dataflow_names(extra)
        if force_confidence == "direct":
            attributions = _direct_attributions(
                extra,
                root,
                path,
                line,
                function_name,
                tools,
                graph,
                entrypoints,
            )
        else:
            attributions = _proximate_attributions(
                path,
                line,
                function_name,
                tools,
                graph,
                entrypoints,
            )

        if not attributions:
            if force_confidence == "direct":
                continue
            attributions = [(None, dataflow or taint_path_default)]

        for tool_name, walked in attributions:
            facts.append(
                SinkFact(
                    id=f"sink_{uuid.uuid4().hex[:12]}",
                    tool_name=tool_name,
                    sink_type=sink_type,
                    file=str(path),
                    line=line,
                    function_name=function_name,
                    taint_path=dataflow or walked or taint_path_default,
                    confidence="direct" if force_confidence == "direct" else "proximate",
                    rule_id=rule_id,
                    snippet=snippet,
                )
            )
    return facts


def _proximate_attributions(
    path: Path,
    line: int,
    function_name: str,
    tools: list[ToolMetadata],
    graph: CallGraph | None,
    entrypoints: dict[str, str],
) -> list[tuple[Optional[str], list[str]]]:
    in_handlers = _tools_at(path, line, function_name, tools)
    if graph is not None and path.suffix == ".py":
        fn = function_at(graph, path, line)
        if fn is not None:
            hits = reverse_paths(graph, fn, entrypoints, max_hops=MAX_HOPS)
            if hits:
                return [(tool, walked) for tool, walked in hits]
            if in_handlers:
                return [(name, [fn.name]) for name in in_handlers]
            return []
    if in_handlers:
        path_names = [function_name] if function_name != "<unknown>" else []
        return [(name, path_names) for name in in_handlers]
    tool = entrypoints.get(f"{path.resolve()}:{function_name}") or entrypoints.get(function_name)
    walked = [function_name] if function_name != "<unknown>" else []
    return [(tool, walked)] if tool else []


def _direct_attributions(
    extra: dict[str, Any],
    root: Path,
    sink_path: Path,
    sink_line: int,
    function_name: str,
    tools: list[ToolMetadata],
    graph: CallGraph | None,
    entrypoints: dict[str, str],
) -> list[tuple[Optional[str], list[str]]]:
    """Direct confidence is per (tool, sink): only the tainting handler, not every reachable tool."""
    source_tool = _tool_from_taint_source(extra, root, tools, graph, entrypoints)
    if source_tool:
        return [(source_tool, _dataflow_names(extra) or [function_name])]
    in_handlers = _tools_at(sink_path, sink_line, function_name, tools)
    if in_handlers:
        walked = [function_name] if function_name != "<unknown>" else []
        return [(name, walked) for name in in_handlers]
    return []


def _tool_from_taint_source(
    extra: dict[str, Any],
    root: Path,
    tools: list[ToolMetadata],
    graph: CallGraph | None,
    entrypoints: dict[str, str],
) -> Optional[str]:
    loc = _taint_source_location(extra, root)
    if loc is None:
        return None
    src_path, src_line = loc
    src_fn = "<unknown>"
    if graph is not None and src_path.suffix == ".py":
        fn = function_at(graph, src_path, src_line)
        if fn is not None:
            src_fn = fn.name
            keyed = f"{fn.file.resolve()}:{fn.name}"
            if keyed in entrypoints:
                return entrypoints[keyed]
    else:
        src_fn = js_function_name_near(src_path, src_line)
    names = _tools_at(src_path, src_line, src_fn, tools)
    if len(names) == 1:
        return names[0]
    if names:
        return names[0]
    return entrypoints.get(f"{src_path.resolve()}:{src_fn}") or entrypoints.get(src_fn)


def _taint_source_location(extra: dict[str, Any], root: Path) -> tuple[Path, int] | None:
    trace = extra.get("dataflow_trace") or extra.get("taint_trace")
    if not isinstance(trace, dict):
        return None
    node = trace.get("taint_source")
    items = node if isinstance(node, list) else [node] if node else []
    for item in items:
        location = item
        if isinstance(item, dict) and "location" in item:
            location = item.get("location")
        if not isinstance(location, dict):
            continue
        raw = location.get("path") or location.get("file")
        start = location.get("start") or {}
        if not raw:
            continue
        path = Path(str(raw))
        path = path if path.is_absolute() else (root / path)
        try:
            path = path.resolve()
        except OSError:
            pass
        line = int(start.get("line") or 1)
        return path, line
    return None


def _dataflow_names(extra: dict[str, Any]) -> list[str]:
    trace = extra.get("dataflow_trace") or extra.get("taint_trace")
    if not isinstance(trace, dict):
        return []
    names: list[str] = []
    for key in ("taint_source", "intermediate_vars", "taint_sink"):
        node = trace.get(key)
        items = node if isinstance(node, list) else [node] if node else []
        for item in items:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, str) and content.strip():
                names.append(content.strip()[:80])
    return names


def _merge_facts(proximate: list[SinkFact], direct: list[SinkFact]) -> list[SinkFact]:
    """Union by (tool, file, line, sink_type); taint/direct wins on overlap for that tool."""
    by_key: dict[tuple[str, str, int, str], SinkFact] = {}
    for fact in proximate:
        by_key[_fact_key(fact)] = fact
    for fact in direct:
        by_key[_fact_key(fact)] = fact
    return list(by_key.values())


def _fact_key(fact: SinkFact) -> tuple[str, str, int, str]:
    return (fact.tool_name or "", fact.file, fact.line, fact.sink_type.value)
