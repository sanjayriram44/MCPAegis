"""Stage 5: extract MCP response fields and match planted canaries."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from mcpaegis.core.models import CanarySeed, SinkWitness
from mcpaegis.dynamic.canary import match_text

PROMPTISH_KEYS = {
    "prompt",
    "prompts",
    "message",
    "messages",
    "content",
    "text",
    "instruction",
    "instructions",
    "system",
    "input",
}
METADATA_KEYS = {
    "id",
    "jsonrpc",
    "iserror",
    "is_error",
    "type",
    "role",
    "index",
    "name",
    "uri",
    "mime",
    "mimetype",
    "mime_type",
}


def inspect(
    response: Mapping[str, Any] | None,
    seeds: Sequence[CanarySeed],
    *,
    call_id: str,
) -> list[SinkWitness]:
    """Match env/file canaries against MCP response strings (W15). Argument seeds are ignored."""
    if not response or not seeds:
        return []
    leak_seeds = [s for s in seeds if s.type in {"env", "file"}]
    if not leak_seeds:
        return []
    regions = extract_sink_regions(response)
    witnesses: list[SinkWitness] = []
    seen: set[tuple[str, str, str]] = set()
    for location, text in regions:
        for seed in leak_seeds:
            hit = match_text(text, seed)
            if not hit:
                continue
            match_type, snippet, confidence = hit
            key = (seed.value, location, match_type)
            if key in seen:
                continue
            seen.add(key)
            witnesses.append(
                SinkWitness(
                    call_id=call_id,
                    canary_ref=seed.value,
                    sink_location=location,
                    match_type=match_type,
                    confidence=confidence,
                    matched_snippet=snippet[:240],
                )
            )
    return witnesses


def extract_sink_regions(
    payload: Any,
    prefix: str = "$",
) -> list[tuple[str, str]]:
    """JSONPath-ish leaf strings, preferring prompt/message content."""
    regions: list[tuple[str, str]] = []
    _walk(payload, prefix, regions)
    return regions


def classify_witness(witness: SinkWitness, seeds: Iterable[CanarySeed]) -> str:
    """Env/file canary in the MCP response is W15. Argument echoes are not findings."""
    seed_by_value = {s.value: s for s in seeds}
    seed = seed_by_value.get(witness.canary_ref)
    if seed is not None and seed.type not in {"env", "file"}:
        return ""
    return "W15"


def _walk(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, str):
        if _keep_string(path, node):
            out.append((path, node))
        return
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_s = str(key)
            child = f"{path}.{key_s}"
            if key_s.lower() in METADATA_KEYS and isinstance(value, (int, float, bool)):
                continue
            _walk(value, child, out)
        return
    if isinstance(node, Sequence) and not isinstance(node, (bytes, bytearray)):
        for idx, item in enumerate(node):
            _walk(item, f"{path}[{idx}]", out)


def _keep_string(path: str, text: str) -> bool:
    if not text or not text.strip():
        return False
    leaf = path.rsplit(".", 1)[-1].lower()
    if leaf in METADATA_KEYS and len(text) < 24:
        return False
    if len(text.strip()) < 4 and leaf not in PROMPTISH_KEYS:
        return False
    return True
