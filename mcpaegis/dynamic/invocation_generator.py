"""Schema-guided auto args, user test-script loader, risk ranking, --max-calls."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from mcpaegis.core.models import CanarySeed, ExpectedBehaviorProfile, ToolMetadata

PATH_FIELD_TOKENS = (
    "path",
    "file",
    "filename",
    "filepath",
    "dir",
    "directory",
    "folder",
)
RISK_TOKENS = (
    "cmd",
    "command",
    "exec",
    "shell",
    "path",
    "file",
    "token",
    "secret",
    "password",
    "credential",
    "query",
    "sql",
    "url",
    "uri",
    "host",
    "fetch",
    "http",
)


@dataclass
class PlannedInvocation:
    tool_name: str
    arguments: dict[str, Any]
    canaries: list[CanarySeed] = field(default_factory=list)
    source: str = "auto"
    risk_score: int = 0
    schema: dict[str, Any] = field(default_factory=dict)
    description: str = ""


def generate(
    tools: Sequence[ToolMetadata] | None = None,
    *,
    profiles: Sequence[ExpectedBehaviorProfile] | None = None,
    test_script: Path | str | None = None,
    max_calls: int | None = None,
    canary_dir: Path | str | None = None,
) -> list[PlannedInvocation]:
    """Build a ranked, budgeted list of tool invocations.

    ``canary_dir`` is accepted for callers but unused: the bait file is planted
    in the pipeline, never passed as a tool argument.
    """
    _ = canary_dir
    tool_list = list(tools or [])
    by_name = {t.name: t for t in tool_list}
    if profiles:
        for profile in profiles:
            if profile.tool_name not in by_name:
                by_name[profile.tool_name] = ToolMetadata(
                    name=profile.tool_name,
                    description="",
                    input_schema={},
                )

    script_invocations = load_test_script(test_script) if test_script else []
    script_by_tool: dict[str, list[PlannedInvocation]] = {}
    for item in script_invocations:
        script_by_tool.setdefault(item.tool_name, []).append(item)

    planned: list[PlannedInvocation] = []
    seen_script_tools: set[str] = set()
    for name, tool in by_name.items():
        if name in script_by_tool:
            for inv in script_by_tool[name]:
                inv.schema = tool.input_schema or {}
                inv.description = tool.description or ""
                inv.risk_score = risk_score(tool, inv.arguments)
                planned.append(inv)
            seen_script_tools.add(name)
        else:
            planned.append(_auto_for_tool(tool))

    for name, extras in script_by_tool.items():
        if name in seen_script_tools:
            continue
        for inv in extras:
            inv.risk_score = risk_score(
                ToolMetadata(name=name, description="", input_schema={}),
                inv.arguments,
            )
            planned.append(inv)

    planned.sort(key=lambda item: item.risk_score, reverse=True)
    if max_calls is not None and max_calls >= 0:
        planned = planned[:max_calls]
    return planned


def load_test_script(path: Path | str) -> list[PlannedInvocation]:
    script_path = Path(path)
    text = script_path.read_text(encoding="utf-8")
    data: Any
    if script_path.suffix.lower() in {".yaml", ".yml"}:
        data = _load_yaml(text, script_path)
    else:
        data = json.loads(text)
    entries = _script_entries(data)
    invocations: list[PlannedInvocation] = []
    for entry in entries:
        name = str(entry.get("tool_name") or entry.get("name") or "")
        if not name:
            continue
        arguments = entry.get("arguments") or entry.get("args") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        invocations.append(
            PlannedInvocation(
                tool_name=name,
                arguments=dict(arguments),
                canaries=[],
                source="test-script",
            )
        )
    return invocations


def risk_score(tool: ToolMetadata, arguments: Mapping[str, Any] | None = None) -> int:
    blob = " ".join(
        [
            tool.name,
            tool.description or "",
            json.dumps(tool.input_schema or {}, default=str),
            json.dumps(dict(arguments or {}), default=str),
        ]
    ).lower()
    score = 0
    for token in RISK_TOKENS:
        if token in blob:
            score += 3
    return score


PATH_PLACEHOLDER = "/tmp/mcpaegis-placeholder-path"


def fill_from_schema(
    schema: Mapping[str, Any] | None,
    *,
    canary_dir: Path | None = None,
    prefix: str = "",
) -> tuple[dict[str, Any], list[CanarySeed]]:
    schema = dict(schema or {})
    if schema.get("type") == "object" or "properties" in schema:
        properties = schema.get("properties") or {}
        required = list(schema.get("required") or [])
        args: dict[str, Any] = {}
        ordered = list(required) + [n for n in properties if n not in required]
        for name in ordered:
            prop = properties.get(name) or {}
            value, _nested = _value_for_property(name, prop if isinstance(prop, dict) else {})
            args[name] = value
        return args, []
    value, _seeds = _value_for_property(prefix or "input", schema)
    return {"value": value} if prefix == "" else {prefix: value}, []


def _auto_for_tool(tool: ToolMetadata) -> PlannedInvocation:
    args, _seeds = fill_from_schema(tool.input_schema)
    return PlannedInvocation(
        tool_name=tool.name,
        arguments=args,
        canaries=[],
        source="auto",
        risk_score=risk_score(tool, args),
        schema=tool.input_schema or {},
        description=tool.description or "",
    )


def _value_for_property(
    name: str,
    schema: Mapping[str, Any],
) -> tuple[Any, list[CanarySeed]]:
    schema_type = schema.get("type")
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0], []
    if schema_type == "boolean":
        return True, []
    if schema_type in {"integer", "number"}:
        return 1 if schema_type == "integer" else 1.0, []
    if schema_type == "array":
        item_schema = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        value, seeds = _value_for_property(name, item_schema or {})
        return [value], seeds
    if schema_type == "object" or "properties" in schema:
        nested, seeds = fill_from_schema(schema, prefix=name)
        return nested, seeds
    if any(token in name.lower() for token in PATH_FIELD_TOKENS):
        # Dummy path — never the planted bait file (out/canaries/secret.canary).
        return PATH_PLACEHOLDER, []
    return "mcpaegis-placeholder", []


def _script_entries(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("invocations", "calls", "tools", "tests"):
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
        if "tool_name" in data or "name" in data:
            return [data]
    return []


def _load_yaml(text: str, path: Path) -> Any:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return _minimal_yaml(text, path)
    return yaml.safe_load(text)


def _minimal_yaml(text: str, path: Path) -> Any:
    """Tiny YAML subset: list of {tool_name, arguments} mappings."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_args = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if current:
                items.append(current)
            current = {}
            in_args = False
            rest = stripped[2:].strip()
            if rest and ":" in rest:
                key, value = rest.split(":", 1)
                current[key.strip()] = _scalar(value.strip())
            continue
        if current is None:
            continue
        if stripped.endswith(":") and stripped.rstrip(":").strip() == "arguments":
            current["arguments"] = {}
            in_args = True
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = _scalar(value.strip())
            if in_args:
                args = current.setdefault("arguments", {})
                if not isinstance(args, dict):
                    args = {}
                    current["arguments"] = args
                args[key] = value
            else:
                current[key] = value
                in_args = key == "arguments"
    if current:
        items.append(current)
    if not items:
        raise ValueError(
            f"cannot parse test script {path}; install PyYAML or use JSON "
            "with a list of {tool_name, arguments} objects"
        )
    return items


def _scalar(value: str) -> Any:
    if value.lower() in {"true", "yes"}:
        return True
    if value.lower() in {"false", "no"}:
        return False
    if value.lower() in {"null", "none", "~", ""}:
        return value if value == "" else None
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value
