"""Canary seed generation and matching (exact/prefix/suffix/decoded)."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Literal, Optional

from mcpaegis.core.models import CanarySeed
from mcpaegis.core.session import CANARY_PREFIX

__all__ = [
    "CANARY_PREFIX",
    "FILE_CANARY_NAME",
    "GUEST_FILE_CANARY",
    "MatchType",
    "candidates",
    "make_value",
    "match_any",
    "match_text",
    "plant",
    "plant_arg",
    "plant_env",
    "plant_file",
]

# Bait file in the run's canary dir (out/canaries/). Never passed as a tool argument.
FILE_CANARY_NAME = "secret.canary"
GUEST_FILE_CANARY = FILE_CANARY_NAME

MatchType = Literal[
    "exact",
    "prefix",
    "suffix",
    "separator_normalized",
    "base64",
    "hex",
    "rot13",
]

WINDOW = 24


def make_value() -> str:
    return f"{CANARY_PREFIX}{uuid.uuid4().hex}"


def plant(
    *,
    kind: Literal["env", "file", "arg"] = "arg",
    key: str,
    value: str | None = None,
    planted_at: datetime | None = None,
    file_path: Path | None = None,
) -> CanarySeed:
    """Create a canary seed; optionally write a file canary to disk."""
    marker = value or make_value()
    if kind == "file" and file_path is not None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(marker + "\n", encoding="utf-8")
    return CanarySeed(
        type=kind,
        key=key,
        value=marker,
        planted_at=planted_at or datetime.now(timezone.utc),
    )


def plant_env(key: str, value: str | None = None) -> CanarySeed:
    return plant(kind="env", key=key, value=value)


def plant_arg(key: str, value: str | None = None) -> CanarySeed:
    return plant(kind="arg", key=key, value=value)


def plant_file(path: Path, key: str | None = None, value: str | None = None) -> CanarySeed:
    return plant(kind="file", key=key or str(path), value=value, file_path=path)


def normalize_separators(text: str) -> str:
    return re.sub(r"[\s_\-.:/\\]+", "", text)


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def candidates(value: str) -> list[tuple[MatchType, str]]:
    """Generate match forms for a canary value."""
    forms: list[tuple[MatchType, str]] = [("exact", value)]
    if len(value) >= 8:
        forms.append(("prefix", value[:WINDOW] if len(value) > WINDOW else value))
        forms.append(("suffix", value[-WINDOW:] if len(value) > WINDOW else value))
    forms.append(("separator_normalized", normalize_separators(value)))
    forms.append(("base64", base64.b64encode(value.encode("utf-8")).decode("ascii")))
    forms.append(("hex", binascii.hexlify(value.encode("utf-8")).decode("ascii")))
    forms.append(("rot13", _rot13(value)))
    return forms


def match_text(haystack: str, seed: CanarySeed) -> Optional[tuple[MatchType, str, float]]:
    """Return (match_type, snippet, confidence) if ``seed`` appears in ``haystack``."""
    if not haystack:
        return None
    exact = seed.value
    if exact in haystack:
        return "exact", _snippet(haystack, exact), 1.0

    prefix = exact[:WINDOW] if len(exact) > WINDOW else exact
    suffix = exact[-WINDOW:] if len(exact) > WINDOW else exact
    if len(exact) >= 8 and prefix and prefix in haystack and prefix != exact:
        return "prefix", _snippet(haystack, prefix), 0.85
    if len(exact) >= 8 and suffix and suffix in haystack and suffix != exact:
        return "suffix", _snippet(haystack, suffix), 0.85

    mid = exact[len(exact) // 4 : len(exact) // 4 + WINDOW] if len(exact) > WINDOW else ""
    if mid and mid in haystack:
        return "prefix", _snippet(haystack, mid), 0.7

    norm_h = normalize_separators(haystack)
    norm_v = normalize_separators(exact)
    if norm_v and norm_v in norm_h:
        return "separator_normalized", exact[:64], 0.8

    b64 = base64.b64encode(exact.encode("utf-8")).decode("ascii")
    if b64 in haystack:
        return "base64", _snippet(haystack, b64), 0.9
    try:
        decoded = _scan_base64(haystack, exact)
        if decoded:
            return "base64", decoded, 0.85
    except Exception:
        pass

    hx = binascii.hexlify(exact.encode("utf-8")).decode("ascii")
    if hx in haystack.lower():
        return "hex", _snippet(haystack.lower(), hx), 0.9

    rot = _rot13(exact)
    if rot in haystack:
        return "rot13", _snippet(haystack, rot), 0.85
    return None


def match_any(haystack: str, seeds: Iterable[CanarySeed]) -> list[tuple[CanarySeed, MatchType, str, float]]:
    hits: list[tuple[CanarySeed, MatchType, str, float]] = []
    for seed in seeds:
        found = match_text(haystack, seed)
        if found:
            match_type, snippet, confidence = found
            hits.append((seed, match_type, snippet, confidence))
    return hits


def _snippet(haystack: str, needle: str, radius: int = 24) -> str:
    idx = haystack.find(needle)
    if idx < 0:
        return needle[:80]
    start = max(0, idx - radius)
    end = min(len(haystack), idx + len(needle) + radius)
    return haystack[start:end]


def _scan_base64(haystack: str, expected: str) -> Optional[str]:
    blobs = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", haystack)
    for blob in blobs:
        pad = (-len(blob)) % 4
        try:
            decoded = base64.b64decode(blob + ("=" * pad)).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if expected in decoded:
            return blob[:80]
    return None
