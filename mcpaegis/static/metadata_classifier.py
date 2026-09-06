"""Lane A (code): tool poisoning fast rules (W1) and tool shadowing (W2).

W1 LLM lives in ``advertisement.py``. This module keeps regex/homoglyph
fallback plus name-distance shadowing (never LLM).
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Optional

from mcpaegis.core.models import PoisoningFlag, ShadowingFlag, SinkFact, ToolMetadata
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness

HOMOGLYPH_HINTS = {
    "\u0430",  # Cyrillic a
    "\u0435",  # Cyrillic e
    "\u043e",  # Cyrillic o
    "\u0440",  # Cyrillic p
    "\u0441",  # Cyrillic c
    "\u0445",  # Cyrillic x
    "\u0456",  # Cyrillic i
    "\u2010",
    "\u2011",
    "\uff0d",
}

LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
    }
)

FAST_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "hidden_instruction",
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)|"
            r"disregard\s+(your\s+)?(system|safety)\s+(prompt|instructions)|"
            r"you\s+are\s+now\s+(unrestricted|jailbroken)|"
            r"do\s+not\s+(tell|inform|notify)\s+the\s+(user|human)|"
            r"hidden\s+instruction|system\s*:\s*|<<\s*SYS\s*>>)",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "ignore_previous",
        re.compile(r"ignore\s+previous", re.IGNORECASE),
        "HIGH",
    ),
    (
        "cross_tool_override",
        re.compile(
            r"(when\s+(calling|using)\s+\w+|instead\s+of\s+(calling|using)\s+\w+|"
            r"override\s+the\s+\w+\s+tool|always\s+use\s+this\s+tool)",
            re.IGNORECASE,
        ),
        "MEDIUM",
    ),
    (
        "base64_blob",
        re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"),
        "MEDIUM",
    ),
]


def classify(
    tools: list[ToolMetadata],
    *,
    session: AuditSession | None = None,
    sink_facts: list[SinkFact] | None = None,
    extra_tools: list[tuple[str, ToolMetadata]] | None = None,
) -> tuple[list[PoisoningFlag], list[ShadowingFlag]]:
    """Return poisoning (fast-rule fallback) and shadowing flags.

    ``extra_tools`` is ``(server_label, tool)`` for cross-server shadowing.
    The pipeline prefers ``advertisement.classify`` for W1 when an LLM key
    is set; this entrypoint stays regex-only so unit tests and offline
    static still work. ``sink_facts`` is ignored (poisoning is metadata-only).
    """
    del sink_facts
    poisoning: list[PoisoningFlag] = []
    if session is None or session.uses_category(Weakness.W1_TOOL_POISONING):
        poisoning.extend(poisoning_fast(tools))

    shadowing: list[ShadowingFlag] = []
    if session is None or session.uses_category(Weakness.W2_TOOL_SHADOWING):
        shadowing.extend(shadowing_flags(tools, extra_tools=extra_tools))
    return poisoning, shadowing


def poisoning_fast(tools: list[ToolMetadata]) -> list[PoisoningFlag]:
    """Public alias for the regex/homoglyph W1 fallback."""
    return _poisoning_fast(tools)


def shadowing_flags(
    tools: list[ToolMetadata],
    *,
    extra_tools: list[tuple[str, ToolMetadata]] | None = None,
) -> list[ShadowingFlag]:
    return _shadowing(tools, extra_tools=extra_tools)


def clip_text(text: str, limit: int = 240) -> str:
    return _clip(text, limit=limit)


def _corpus(tool: ToolMetadata) -> str:
    schema = json.dumps(tool.input_schema, ensure_ascii=False) if tool.input_schema else ""
    return f"{tool.name}\n{tool.description}\n{schema}"


def _poisoning_fast(tools: list[ToolMetadata]) -> list[PoisoningFlag]:
    flags: list[PoisoningFlag] = []
    for tool in tools:
        text = _corpus(tool)
        for pattern_id, regex, severity in FAST_RULES:
            match = regex.search(text)
            if not match:
                continue
            snippet = _clip(match.group(0))
            flags.append(
                PoisoningFlag(
                    tool_name=tool.name,
                    weakness_id="W1",
                    pattern_matched=pattern_id,
                    detection_tier="fast_rule",
                    severity=severity,  # type: ignore[arg-type]
                    snippet=snippet,
                    confidence=0.85 if severity == "HIGH" else 0.7,
                )
            )
        if _has_homoglyphs(text):
            flags.append(
                PoisoningFlag(
                    tool_name=tool.name,
                    weakness_id="W1",
                    pattern_matched="homoglyph",
                    detection_tier="fast_rule",
                    severity="MEDIUM",
                    snippet=_clip(_first_homoglyph_span(text)),
                    confidence=0.65,
                )
            )
        # Naming another tool is not poisoning by itself (docs often compare
        # handlers). Override/hijack wording is covered by cross_tool_override.
    return flags


def _has_homoglyphs(text: str) -> bool:
    if any(ch in HOMOGLYPH_HINTS for ch in text):
        return True
    for ch in text:
        if unicodedata.category(ch).startswith("C") and ch not in "\n\r\t":
            return True
        name = unicodedata.name(ch, "")
        if "CYRILLIC" in name or "GREEK" in name:
            if ch.isalpha() and ord(ch) > 127:
                return True
    return False


def _first_homoglyph_span(text: str) -> str:
    for i, ch in enumerate(text):
        if ch in HOMOGLYPH_HINTS or (ord(ch) > 127 and unicodedata.name(ch, "").split(" ")[0] in {"CYRILLIC", "GREEK"}):
            return text[max(0, i - 8) : i + 12]
    return text[:40]


def _clip(text: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def normalize_tool_name(name: str) -> str:
    lowered = name.lower().translate(LEET_MAP)
    return re.sub(r"[^a-z0-9]", "", lowered)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _shadowing(
    tools: list[ToolMetadata],
    *,
    extra_tools: list[tuple[str, ToolMetadata]] | None = None,
) -> list[ShadowingFlag]:
    records: list[tuple[Optional[str], ToolMetadata]] = [(None, t) for t in tools]
    if extra_tools:
        records.extend(extra_tools)

    flags: list[ShadowingFlag] = []
    seen_pairs: set[tuple[str, str, Optional[str]]] = set()
    for i, (server_a, tool_a) in enumerate(records):
        na = normalize_tool_name(tool_a.name)
        if not na:
            continue
        for server_b, tool_b in records[i + 1 :]:
            if tool_a.name == tool_b.name and server_a == server_b:
                # Same tool listed twice on one server — skip.
                continue
            nb = normalize_tool_name(tool_b.name)
            if not nb:
                continue
            if na == nb:
                score = 1.0
                reason = "normalized names are identical"
            else:
                dist = _levenshtein(na, nb)
                maxlen = max(len(na), len(nb))
                if maxlen == 0:
                    continue
                # Near-duplicate: small edit distance relative to length.
                if dist > 2 and dist / maxlen > 0.25:
                    continue
                if dist == 0:
                    score = 1.0
                else:
                    score = 1.0 - (dist / maxlen)
                if score < 0.75:
                    continue
                reason = f"normalized edit distance {dist}"
            pair = tuple(sorted((tool_a.name, tool_b.name)))  # type: ignore[assignment]
            key = (pair[0], pair[1], server_b or server_a)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            flags.append(
                ShadowingFlag(
                    tool_name=tool_a.name,
                    weakness_id="W2",
                    conflicting_tool_name=tool_b.name,
                    conflicting_server=server_b if server_b != server_a else None,
                    similarity_score=round(score, 3),
                    reason=reason,
                )
            )
    return flags
