"""Generic JSON writer: any Pydantic model (or report JSON) <-> pretty JSON."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from mcpaegis.core.models import CombinedReport, DynamicReport, StaticReport

ReportModel = StaticReport | DynamicReport | CombinedReport


def to_jsonable(model: BaseModel | Sequence[BaseModel] | dict[str, Any] | list[Any]) -> Any:
    """Convert a Pydantic model, list of models, or already-plain data to JSON types."""
    if isinstance(model, BaseModel):
        return model.model_dump(mode="json")
    if isinstance(model, Sequence) and not isinstance(model, (str, bytes, dict)):
        return [to_jsonable(item) for item in model]  # type: ignore[arg-type]
    return model


def dumps(
    model: BaseModel | Sequence[BaseModel] | dict[str, Any] | list[Any],
    *,
    indent: int = 2,
) -> str:
    """Serialize any Pydantic model (or list of models) to pretty JSON."""
    if isinstance(model, BaseModel):
        return model.model_dump_json(indent=indent)
    return json.dumps(to_jsonable(model), indent=indent, ensure_ascii=False)


def write(
    model: BaseModel | Sequence[BaseModel] | dict[str, Any] | list[Any],
    path: str | Path,
    *,
    indent: int = 2,
) -> Path:
    """Write pretty JSON to ``path``, creating parent directories as needed."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = dumps(model, indent=indent)
    if not text.endswith("\n"):
        text += "\n"
    destination.write_text(text, encoding="utf-8")
    return destination


def load_json(path: str | Path) -> Any:
    """Load raw JSON from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def detect_report_type(data: dict[str, Any]) -> type[ReportModel]:
    """Infer which report model a results JSON object is."""
    if "poisoning_flags" in data or "expected_behavior_profiles" in data:
        return StaticReport
    if "runtime_findings" in data or "tool_behavior_trees" in data:
        return DynamicReport
    if "static_report_ref" in data or ("tools" in data and "generated_at" in data):
        return CombinedReport
    raise ValueError(
        "unrecognized report JSON: expected a StaticReport, DynamicReport, or CombinedReport object"
    )


def load_report(path: str | Path) -> ReportModel:
    """Parse ``static-report.json``, ``runtime-report.json``, or a combined report."""
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("report JSON must be an object")
    model_cls = detect_report_type(data)
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"invalid {model_cls.__name__} JSON: {exc}") from exc
