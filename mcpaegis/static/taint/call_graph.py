"""Lightweight reverse call-graph walk (ast, N=10) for sink attribution."""

from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "dist",
    "build",
    ".eggs",
}


@dataclass
class FunctionDef:
    name: str
    file: Path
    lineno: int
    end_lineno: int
    qualname: str


@dataclass
class CallGraph:
    functions: list[FunctionDef] = field(default_factory=list)
    # callee simple/qualname -> list of caller FunctionDef
    callers: dict[str, list[FunctionDef]] = field(default_factory=lambda: defaultdict(list))
    by_file: dict[Path, list[FunctionDef]] = field(default_factory=lambda: defaultdict(list))


def iter_source_files(root: Path, suffixes: Iterable[str] = (".py",)) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in suffixes:
            files.append(path)
    return files


def _func_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, file: Path) -> None:
        self.file = file
        self.stack: list[FunctionDef] = []
        self.functions: list[FunctionDef] = []
        self.calls: list[tuple[FunctionDef, str]] = []

    def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionDef:
        parent = self.stack[-1].qualname if self.stack else ""
        qual = f"{parent}.{node.name}" if parent else node.name
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        fn = FunctionDef(name=node.name, file=self.file, lineno=node.lineno, end_lineno=end, qualname=qual)
        self.functions.append(fn)
        self.stack.append(fn)
        return fn

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._enter(node)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._enter(node)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if self.stack:
            name = _func_name(node.func)
            if name:
                self.calls.append((self.stack[-1], name))
        self.generic_visit(node)


def build_python_call_graph(root: Path) -> CallGraph:
    graph = CallGraph()
    for file in iter_source_files(root, (".py",)):
        try:
            tree = ast.parse(file.read_text(encoding="utf-8", errors="replace"), filename=str(file))
        except (OSError, SyntaxError):
            continue
        visitor = _CallVisitor(file)
        visitor.visit(tree)
        for fn in visitor.functions:
            graph.functions.append(fn)
            graph.by_file[file.resolve()].append(fn)
        for caller, callee in visitor.calls:
            graph.callers[callee].append(caller)
    return graph


def function_at(graph: CallGraph, file: Path, line: int) -> Optional[FunctionDef]:
    candidates = graph.by_file.get(file.resolve(), [])
    enclosing = [fn for fn in candidates if fn.lineno <= line <= fn.end_lineno]
    if not enclosing:
        return None
    return max(enclosing, key=lambda fn: fn.lineno)


def reverse_paths(
    graph: CallGraph,
    start: FunctionDef,
    entrypoints: dict[str, str],
    *,
    max_hops: int = 10,
) -> list[tuple[str, list[str]]]:
    """Walk callers up to max_hops and collect every reaching tool entrypoint.

    ``entrypoints`` maps function name (and optionally ``file:function``) to tool name.
    A shared helper can legitimately reach more than one tool; each pair is
    ``(tool_name, path of function names from entrypoint → start)``.
    """
    entry_by_name = {name: tool for name, tool in entrypoints.items()}

    def match_tool(fn: FunctionDef) -> Optional[str]:
        keyed = f"{fn.file.resolve()}:{fn.name}"
        if keyed in entry_by_name:
            return entry_by_name[keyed]
        if fn.qualname in entry_by_name:
            return entry_by_name[fn.qualname]
        has_file_key = any(k != fn.name and k.endswith(f":{fn.name}") for k in entry_by_name)
        if has_file_key:
            return None
        return entry_by_name.get(fn.name)

    hits: list[tuple[str, list[str]]] = []
    seen_tools: set[str] = set()

    def add_hit(tool: str, path: list[str]) -> None:
        if tool in seen_tools:
            return
        seen_tools.add(tool)
        hits.append((tool, path))

    direct = match_tool(start)
    if direct:
        add_hit(direct, [start.name])

    visited: set[tuple[Path, int]] = {(start.file.resolve(), start.lineno)}
    queue: deque[tuple[FunctionDef, list[str], int]] = deque([(start, [start.name], 0)])
    while queue:
        current, path, hops = queue.popleft()
        if hops >= max_hops:
            continue
        seen_callers: set[tuple[Path, int]] = set()
        for caller in graph.callers.get(current.name, []) + graph.callers.get(current.qualname, []):
            key = (caller.file.resolve(), caller.lineno)
            if key in visited or key in seen_callers:
                continue
            seen_callers.add(key)
            visited.add(key)
            new_path = [caller.name, *path]
            tool = match_tool(caller)
            if tool:
                add_hit(tool, new_path)
                continue
            queue.append((caller, new_path, hops + 1))
    return hits


def reverse_path(
    graph: CallGraph,
    start: FunctionDef,
    entrypoints: dict[str, str],
    *,
    max_hops: int = 10,
) -> tuple[Optional[str], list[str]]:
    """Walk callers up to max_hops looking for the nearest tool entrypoint."""
    hits = reverse_paths(graph, start, entrypoints, max_hops=max_hops)
    if not hits:
        return None, [start.name]
    return hits[0]


def js_function_name_near(file: Path, line: int) -> str:
    """Best-effort JS/TS function name from nearby source (no full parser)."""
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "<unknown>"
    idx = max(0, min(line - 1, len(lines) - 1)) if lines else 0
    window = lines[max(0, idx - 30) : idx + 1]
    patterns = [
        re.compile(r"(?:async\s+)?function\s+([A-Za-z_][\w]*)"),
        re.compile(r"(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(?:async\s*)?\("),
        re.compile(r"([A-Za-z_][\w]*)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>"),
        re.compile(r"(?:async\s+)?([A-Za-z_][\w]*)\s*\([^)]*\)\s*\{"),
    ]
    for text in reversed(window):
        for pat in patterns:
            m = pat.search(text)
            if m:
                return m.group(1)
    return "<unknown>"
