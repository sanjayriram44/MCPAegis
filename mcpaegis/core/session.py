"""Shared audit session: output settings, category filter, LLM config, color."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from mcpaegis.core.taxonomy import Weakness

CANARY_PREFIX = "MCPAEGIS_CANARY_"

LLM_API_KEY_ENV = "MCPAEGIS_LLM_API_KEY"
LLM_BASE_URL_ENV = "MCPAEGIS_LLM_BASE_URL"
LLM_MODEL_ENV = "MCPAEGIS_LLM_MODEL"


@dataclass(frozen=True)
class LLMConfig:
    """OpenAI-compatible LLM settings. Missing API key disables semantic stages."""

    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    @classmethod
    def from_env(cls) -> LLMConfig:
        return cls(
            api_key=os.environ.get(LLM_API_KEY_ENV) or None,
            base_url=os.environ.get(LLM_BASE_URL_ENV) or None,
            model=os.environ.get(LLM_MODEL_ENV) or None,
        )


def parse_categories(raw: str | None) -> frozenset[Weakness] | None:
    """Parse a comma-separated weakness filter (`W1,W4`) into enum values."""
    if raw is None or not raw.strip():
        return None

    by_value = {item.value: item for item in Weakness}
    parsed: list[Weakness] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if token in by_value:
            parsed.append(by_value[token])
            continue
        try:
            parsed.append(Weakness[token])
        except KeyError as exc:
            known = ", ".join(item.value for item in Weakness)
            raise ValueError(f"unknown weakness category {token!r}; expected one of: {known}") from exc
    return frozenset(parsed)


@dataclass
class AuditSession:
    """Holds config and shared state across static/dynamic/combine stages."""

    output_dir: Path
    output_format: str = "json"
    categories: frozenset[Weakness] | None = None
    color: bool = True
    llm: LLMConfig = field(default_factory=LLMConfig.from_env)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)

    def uses_category(self, weakness: Weakness | str) -> bool:
        if self.categories is None:
            return True
        if isinstance(weakness, Weakness):
            return weakness in self.categories
        return any(item.value == weakness for item in self.categories)

    @classmethod
    def from_cli(
        cls,
        *,
        output: Path | str | None = None,
        format: str = "json",
        categories: str | None = None,
        no_color: bool = False,
        llm: LLMConfig | None = None,
    ) -> AuditSession:
        output_dir = Path(output) if output is not None else Path.cwd() / "mcpaegis-out"
        color = False if no_color else sys.stdout.isatty()
        return cls(
            output_dir=output_dir,
            output_format=format,
            categories=parse_categories(categories),
            color=color,
            llm=llm if llm is not None else LLMConfig.from_env(),
        )
