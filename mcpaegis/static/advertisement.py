"""Lane A: LLM (or regex fallback) for W1 poisoning + declared capabilities."""

from __future__ import annotations

import logging
from typing import Any, Optional

from mcpaegis.core.models import DeclaredCapability, PoisoningFlag, ToolMetadata
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Capability
from mcpaegis.static import capability_classifier, metadata_classifier

logger = logging.getLogger(__name__)

_CAP_BY_VALUE = {item.value: item for item in Capability}
_CAP_BY_NAME = {item.name: item for item in Capability}


def classify(
    tools: list[ToolMetadata],
    *,
    session: AuditSession | None = None,
) -> tuple[list[PoisoningFlag], list[DeclaredCapability]]:
    """W1 + declared caps. LLM when a key is set; regex/keywords otherwise.

    A bad or partial model reply for one tool falls back to fast rules /
    ``KEYWORD_RULES`` for that tool only.
    """
    client = _client(session)
    if client is None:
        return (
            metadata_classifier.poisoning_fast(tools),
            capability_classifier.classify(tools),
        )

    poisoning: list[PoisoningFlag] = []
    declared: list[DeclaredCapability] = []
    for tool in tools:
        parsed = _ask_tool(client, tool)
        if parsed is None:
            poisoning.extend(metadata_classifier.poisoning_fast([tool]))
            declared.extend(capability_classifier.classify_tool(tool))
            continue
        flag, caps = parsed
        if flag is not None:
            poisoning.append(flag)
        declared.extend(caps if caps else capability_classifier.classify_tool(tool))
    return poisoning, declared


def _client(session: AuditSession | None) -> Any | None:
    if session is None or not session.llm.enabled:
        return None
    try:
        from mcpaegis.llm.client import LLMClient
    except ImportError:
        return None
    try:
        return LLMClient.from_session(session)
    except Exception:
        return None


def _ask_tool(client: Any, tool: ToolMetadata) -> Optional[tuple[PoisoningFlag | None, list[DeclaredCapability]]]:
    from mcpaegis.llm.prompts import build_advertisement_prompt

    prompt = build_advertisement_prompt(
        tool_name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
    )
    try:
        raw = client.complete_json(prompt=prompt)
    except Exception:
        logger.warning("advertisement LLM failed for %s; using regex fallback", tool.name)
        return None
    if not isinstance(raw, dict):
        return None
    return _parse_payload(tool, raw)


def _parse_payload(
    tool: ToolMetadata, data: dict[str, Any]
) -> tuple[PoisoningFlag | None, list[DeclaredCapability]]:
    flag = _parse_poisoning(tool.name, data.get("poisoning"))
    caps = _parse_declared(tool.name, data.get("declared_capabilities"))
    return flag, caps


def _parse_poisoning(tool_name: str, raw: Any) -> PoisoningFlag | None:
    if not isinstance(raw, dict) or not raw.get("poisoned"):
        return None
    severity = str(raw.get("severity") or "MEDIUM").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH"}:
        severity = "MEDIUM"
    pattern = str(raw.get("pattern_matched") or raw.get("reason") or "llm_semantic")
    return PoisoningFlag(
        tool_name=tool_name,
        weakness_id="W1",
        pattern_matched=pattern,
        detection_tier="llm_semantic",
        severity=severity,  # type: ignore[arg-type]
        snippet=metadata_classifier.clip_text(str(raw.get("snippet") or "")),
        confidence=float(raw.get("confidence") or 0.7),
    )


def _parse_declared(tool_name: str, raw: Any) -> list[DeclaredCapability]:
    if not isinstance(raw, list) or not raw:
        return []
    out: list[DeclaredCapability] = []
    seen: set[Capability] = set()
    for item in raw:
        cap: Capability | None = None
        reason = ""
        if isinstance(item, str):
            cap = _capability(item)
        elif isinstance(item, dict):
            cap = _capability(item.get("id") or item.get("capability"))
            reason = str(item.get("reason") or "")
        if cap is None or cap in seen:
            continue
        seen.add(cap)
        out.append(
            DeclaredCapability(
                tool_name=tool_name,
                capability=cap,
                confidence=0.7,
                evidence=[reason] if reason else ["llm_advertisement"],
            )
        )
    return out


def _capability(value: Any) -> Capability | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in _CAP_BY_VALUE:
        return _CAP_BY_VALUE[text]
    upper = text.upper().replace(" ", "_")
    if upper in _CAP_BY_NAME:
        return _CAP_BY_NAME[upper]
    return None
