"""Stage 0: language detection, MCP handshake, static tool fallback."""

from __future__ import annotations

import ast
import json
import re
import shlex
from pathlib import Path
from typing import Any, Optional

from mcpaegis.core.mcp_client import MCPClientError, handshake
from mcpaegis.core.models import ServerMetadata, SourceLocation, ToolMetadata

HANDSHAKE_TIMEOUT = 10.0

TOOL_DECORATOR_NAMES = frozenset({"tool"})

JS_TOOL_PATTERNS = [
    re.compile(
        r"""(?:server|mcp)\.tool\(\s*['"]([^'"]+)['"]""",
        re.MULTILINE,
    ),
    re.compile(
        r"""name\s*:\s*['"]([^'"]+)['"]\s*,\s*description\s*:\s*['"]([^'"]*)['"]""",
        re.MULTILINE,
    ),
]


def discover(path: Path | str, *, timeout: float = HANDSHAKE_TIMEOUT) -> ServerMetadata:
    root = Path(path).resolve()
    language, manifest_path = detect_language(root)
    entrypoint, launch_cmd = detect_entrypoint(root, language)

    live = _try_live(root, launch_cmd, timeout=timeout)
    if live is not None:
        tools, resources, prompts = live
        _enrich_source_locations(root, tools)
        return ServerMetadata(
            entrypoint=entrypoint,
            language=language,
            manifest_path=str(manifest_path) if manifest_path else None,
            tools=tools,
            resources=resources,
            prompts=prompts,
            source="live",
        )

    tools = _static_tools(root, language)
    return ServerMetadata(
        entrypoint=entrypoint,
        language=language,
        manifest_path=str(manifest_path) if manifest_path else None,
        tools=tools,
        resources=[],
        prompts=[],
        source="static_fallback",
    )


def detect_language(root: Path) -> tuple[str, Optional[Path]]:
    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    setup_py = root / "setup.py"
    setup_cfg = root / "setup.cfg"
    package_json = root / "package.json"
    cargo = root / "Cargo.toml"

    if pyproject.is_file() or requirements.is_file() or setup_py.is_file() or setup_cfg.is_file():
        manifest = pyproject if pyproject.is_file() else requirements if requirements.is_file() else setup_py if setup_py.is_file() else setup_cfg
        if package_json.is_file() and not (pyproject.is_file() or requirements.is_file()):
            return _js_or_ts(package_json), package_json
        return "python", manifest
    if package_json.is_file():
        return _js_or_ts(package_json), package_json
    if cargo.is_file():
        return "other", cargo
    # Heuristic from source suffixes.
    py_files = list(root.rglob("*.py"))
    js_files = list(root.rglob("*.js")) + list(root.rglob("*.ts"))
    if py_files and len(py_files) >= len(js_files):
        return "python", None
    if js_files:
        return "javascript", None
    return "other", None


def _js_or_ts(package_json: Path) -> str:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "javascript"
    if data.get("types") or "typescript" in {*(data.get("devDependencies") or {}), *(data.get("dependencies") or {})}:
        return "typescript"
    main = str(data.get("main") or "")
    if main.endswith(".ts"):
        return "typescript"
    return "javascript"


def detect_entrypoint(root: Path, language: str) -> tuple[str, list[str]]:
    if language == "python":
        cmd = _python_launch(root)
        if cmd:
            return " ".join(shlex.quote(p) for p in cmd), cmd
        for name in ("server.py", "main.py", "mcp_server.py", "app.py"):
            candidate = root / name
            if candidate.is_file():
                cmd = ["python", str(candidate)]
                return " ".join(cmd), cmd
    elif language in {"javascript", "typescript"}:
        cmd = _node_launch(root)
        if cmd:
            return " ".join(shlex.quote(p) for p in cmd), cmd
    return "", []


def _python_launch(root: Path) -> list[str]:
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="replace")
        scripts = _toml_table_entries(text, "project.scripts") or _toml_table_entries(text, "tool.poetry.scripts")
        if scripts:
            value = next(iter(scripts.values()))
            # "package.module:app" or a console script name — prefer python -m if module-like.
            if ":" in value and " " not in value:
                module = value.split(":", 1)[0]
                return ["python", "-m", module]
        mcp_cmd = _toml_table_entries(text, "project.entry-points.\"mcp.server\"") or {}
        if mcp_cmd:
            value = next(iter(mcp_cmd.values()))
            if ":" in value:
                return ["python", "-m", value.split(":", 1)[0]]
    if (root / "__main__.py").is_file():
        return ["python", "-m", root.name]
    src_main = root / "src" / "__main__.py"
    if src_main.is_file():
        return ["python", "-m", root.name]
    return []


def _toml_table_entries(text: str, header: str) -> dict[str, str]:
    """Tiny TOML table reader for string assignments (no extra dependency)."""
    entries: dict[str, str] = {}
    pattern = re.compile(rf"^\[{re.escape(header)}\]\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return entries
    rest = text[match.end() :]
    for line in rest.splitlines():
        if line.startswith("["):
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().strip('"').strip("'")
        value = value.strip().split("#", 1)[0].strip().strip('"').strip("'")
        entries[key] = value
    return entries


def _node_launch(root: Path) -> list[str]:
    package_json = root / "package.json"
    if not package_json.is_file():
        for name in ("index.js", "server.js", "src/index.js", "dist/index.js"):
            if (root / name).is_file():
                return ["node", str(root / name)]
        return []
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    bin_field = data.get("bin")
    if isinstance(bin_field, str):
        return ["node", str(root / bin_field)]
    if isinstance(bin_field, dict) and bin_field:
        return ["node", str(root / next(iter(bin_field.values())))]
    main = data.get("main")
    if isinstance(main, str):
        return ["node", str(root / main)]
    scripts = data.get("scripts") or {}
    start = scripts.get("start")
    if isinstance(start, str) and start.strip():
        return shlex.split(start)
    return []


def _try_live(
    root: Path,
    launch_cmd: list[str],
    *,
    timeout: float,
) -> Optional[tuple[list[ToolMetadata], list[dict[str, Any]], list[dict[str, Any]]]]:
    if not launch_cmd:
        return None
    try:
        listed = handshake(launch_cmd, cwd=root, timeout=timeout)
    except (MCPClientError, OSError, FileNotFoundError):
        return None
    tools = [_tool_from_rpc(item) for item in listed.tools if isinstance(item, dict) and item.get("name")]
    return tools, listed.resources, listed.prompts


def _tool_from_rpc(item: dict[str, Any]) -> ToolMetadata:
    schema = item.get("inputSchema") or item.get("input_schema") or {}
    if not isinstance(schema, dict):
        schema = {}
    return ToolMetadata(
        name=str(item.get("name")),
        description=str(item.get("description") or ""),
        input_schema=schema,
        source_location=None,
    )


def _enrich_source_locations(root: Path, tools: list[ToolMetadata]) -> None:
    static = {t.name: t for t in _static_tools(root, "python") + _static_tools(root, "javascript")}
    for tool in tools:
        match = static.get(tool.name)
        if match and match.source_location:
            tool.source_location = match.source_location


def _static_tools(root: Path, language: str) -> list[ToolMetadata]:
    if language == "python":
        return _static_python_tools(root)
    if language in {"javascript", "typescript"}:
        return _static_js_tools(root)
    # Try both if language is unknown.
    return _static_python_tools(root) + _static_js_tools(root)


def _skip_dir(path: Path) -> bool:
    skip = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".tox",
        "dist",
        "build",
    }
    return any(part in skip for part in path.parts)


def _static_python_tools(root: Path) -> list[ToolMetadata]:
    tools: list[ToolMetadata] = []
    seen: set[str] = set()
    for file in root.rglob("*.py"):
        if _skip_dir(file):
            continue
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(file))
        except SyntaxError:
            tools.extend(_regex_python_tools(file, source, seen))
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = _decorator_tool_name(node)
                if not name:
                    continue
                if name in seen:
                    continue
                seen.add(name)
                desc, schema = _doc_and_schema(node, source)
                tools.append(
                    ToolMetadata(
                        name=name,
                        description=desc,
                        input_schema=schema,
                        source_location=SourceLocation(
                            file=str(file),
                            line=node.lineno,
                            function_name=node.name,
                        ),
                    )
                )
        tools.extend(_regex_python_tools(file, source, seen))
    return tools


def _decorator_tool_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Optional[str]:
    for dec in node.decorator_list:
        ident = _decorator_identity(dec)
        if ident is None:
            continue
        attr = ident.split(".")[-1]
        if attr not in TOOL_DECORATOR_NAMES:
            continue
        return _decorator_kwarg_name(dec) or node.name
    return None


def _decorator_identity(dec: ast.AST) -> Optional[str]:
    call = dec
    if isinstance(dec, ast.Call):
        call = dec.func
    if isinstance(call, ast.Name):
        return call.id
    if isinstance(call, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = call
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _decorator_kwarg_name(dec: ast.AST) -> Optional[str]:
    if not isinstance(dec, ast.Call):
        return None
    for kw in dec.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
        return dec.args[0].value
    return None


def _doc_and_schema(node: ast.FunctionDef | ast.AsyncFunctionDef, source: str) -> tuple[str, dict[str, Any]]:
    desc = ast.get_docstring(node) or ""
    properties: dict[str, Any] = {}
    required: list[str] = []
    for arg in node.args.args:
        if arg.arg in {"self", "cls"}:
            continue
        properties[arg.arg] = {"type": "string"}
        required.append(arg.arg)
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return desc, schema


def _regex_python_tools(file: Path, source: str, seen: set[str]) -> list[ToolMetadata]:
    tools: list[ToolMetadata] = []
    patterns = [
        re.compile(r"@(?:mcp|server|app)\.tool\(\s*(?:name\s*=\s*)?['\"]([^'\"]+)['\"]", re.MULTILINE),
        re.compile(r"@(?:mcp|server|app)\.tool\(\s*\)\s*(?:async\s+)?def\s+(\w+)", re.MULTILINE),
        re.compile(r"(?:mcp|server|app)\.tool\(\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
    ]
    for pat in patterns:
        for match in pat.finditer(source):
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            line = source[: match.start()].count("\n") + 1
            tools.append(
                ToolMetadata(
                    name=name,
                    description="",
                    input_schema={},
                    source_location=SourceLocation(file=str(file), line=line, function_name=name),
                )
            )
    return tools


def _static_js_tools(root: Path) -> list[ToolMetadata]:
    tools: list[ToolMetadata] = []
    seen: set[str] = set()
    suffixes = {".js", ".ts", ".mjs", ".cjs"}
    for file in root.rglob("*"):
        if file.suffix not in suffixes or _skip_dir(file):
            continue
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in JS_TOOL_PATTERNS:
            for match in pat.finditer(source):
                name = match.group(1)
                if name in seen:
                    continue
                seen.add(name)
                desc = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                line = source[: match.start()].count("\n") + 1
                tools.append(
                    ToolMetadata(
                        name=name,
                        description=desc,
                        input_schema={},
                        source_location=SourceLocation(file=str(file), line=line, function_name=name),
                    )
                )
    return tools
