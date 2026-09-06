"""Keyword multi-label classifier for declared capabilities (Lane A fallback).

Declared capabilities are what the tool *advertises* to a client: the MCP
tool name and its input-schema argument names (plus per-argument titles /
descriptions). Free-text tool descriptions are not searched — they often
contain negations ("does not run a shell"), comparisons, or incidental
words ("matching the query") that are not capability claims.
"""

from __future__ import annotations

import re
from typing import Iterable

from mcpaegis.core.models import DeclaredCapability, ToolMetadata
from mcpaegis.core.taxonomy import Capability

TokenSpec = tuple[Capability, tuple[str, ...], float]

# Later rules can override earlier ones for the same capability (evidence accumulates).
# Keep tokens specific: generic words that are common argument names ("query")
# must not imply a privileged capability by themselves.
KEYWORD_RULES: list[TokenSpec] = [
    (
        Capability.FS_READ,
        ("read file", "read_file", "filesystem read", "cat ", "open file", "file path", "filepath"),
        0.85,
    ),
    (Capability.FS_READ, ("file", "path", "dir", "directory", "folder", "glob"), 0.55),
    (
        Capability.FS_WRITE,
        ("write file", "write_file", "overwrite", "delete file", "unlink", "mkdir", "rmdir", "save file"),
        0.85,
    ),
    (Capability.FS_WRITE, ("write", "delete", "remove", "modify", "create file"), 0.5),
    (
        Capability.SHELL_EXEC,
        ("shell", "subprocess", "os.system", "bash", "powershell", "command injection"),
        0.9,
    ),
    (Capability.SHELL_EXEC, ("exec", "execute", "run command", "run_cmd", "command", "spawn", "process"), 0.7),
    (Capability.NET_OUTBOUND, ("fetch", "http", "https", "request", "url", "webhook", "api call", "endpoint"), 0.75),
    (Capability.NET_INBOUND, ("listen", "bind", "webhook receiver", "incoming request", "server port"), 0.7),
    (
        Capability.DB_ACCESS,
        ("sql", "database", "postgres", "mysql", "sqlite", "mongodb", "orm"),
        0.8,
    ),
    (
        Capability.CREDENTIAL_HANDLING,
        ("token", "api key", "apikey", "secret", "password", "credential", "auth header", "bearer"),
        0.85,
    ),
    (Capability.BROWSER_AUTOMATION, ("browser", "playwright", "puppeteer", "selenium", "page", "click", "screenshot"), 0.8),
    (Capability.CLOUD_SAAS, ("aws", "gcp", "azure", "s3", "lambda", "cloudflare", "saas", "stripe"), 0.75),
    (Capability.CODE_REPO, ("git", "github", "gitlab", "repo", "commit", "pull request", "clone"), 0.8),
    (Capability.PROMPT_PROVIDING, ("prompt", "template", "system message", "few-shot"), 0.7),
]


def classify(tools: Iterable[ToolMetadata]) -> list[DeclaredCapability]:
    results: list[DeclaredCapability] = []
    for tool in tools:
        results.extend(classify_tool(tool))
    return results


def classify_tool(tool: ToolMetadata) -> list[DeclaredCapability]:
    """Public per-tool keyword fallback used when the advertisement LLM fails."""
    return _classify_tool(tool)


def _classify_tool(tool: ToolMetadata) -> list[DeclaredCapability]:
    blob = _search_blob(tool)
    found: dict[Capability, list[str]] = {}
    conf: dict[Capability, float] = {}
    for capability, keywords, weight in KEYWORD_RULES:
        hits = [kw for kw in keywords if _contains(blob, kw)]
        if not hits:
            continue
        found.setdefault(capability, []).extend(hits)
        conf[capability] = max(conf.get(capability, 0.0), weight)

    if not found:
        return [
            DeclaredCapability(
                tool_name=tool.name,
                capability=Capability.BENIGN_UTILITY,
                confidence=0.4,
                evidence=["no privileged keywords matched"],
            )
        ]

    out: list[DeclaredCapability] = []
    for capability, evidence in found.items():
        out.append(
            DeclaredCapability(
                tool_name=tool.name,
                capability=capability,
                confidence=round(conf.get(capability, 0.5), 3),
                evidence=sorted(set(evidence)),
            )
        )
    return out


def _search_blob(tool: ToolMetadata) -> str:
    """Name + argument identifiers/text — not the tool's free-text description."""
    parts = [tool.name.replace("_", " ").replace("-", " ")]
    _collect_argument_text(tool.input_schema or {}, parts)
    return " ".join(parts).lower()


def _collect_argument_text(node: object, parts: list[str]) -> None:
    if not isinstance(node, dict):
        return
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, spec in properties.items():
            parts.append(str(name).replace("_", " ").replace("-", " "))
            if isinstance(spec, dict):
                for key in ("title", "description", "name"):
                    value = spec.get(key)
                    if isinstance(value, str):
                        parts.append(value)
                _collect_argument_text(spec, parts)
    items = node.get("items")
    if isinstance(items, dict):
        _collect_argument_text(items, parts)
    for combo in ("anyOf", "oneOf", "allOf"):
        alt = node.get(combo)
        if isinstance(alt, list):
            for item in alt:
                _collect_argument_text(item, parts)


def _contains(blob: str, keyword: str) -> bool:
    kw = keyword.lower()
    if " " in kw or "." in kw:
        return kw in blob
    return re.search(rf"\b{re.escape(kw)}\b", blob) is not None
