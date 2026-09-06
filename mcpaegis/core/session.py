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

_ENV_LOADED = False


def _strip_env_value(raw: str) -> str:
    value = raw.strip()
    if "#" in value:
        in_quote = False
        quote = ""
        chars: list[str] = []
        for ch in value:
            if ch in {'"', "'"}:
                if not in_quote:
                    in_quote = True
                    quote = ch
                elif ch == quote:
                    in_quote = False
                    quote = ""
            if ch == "#" and not in_quote:
                break
            chars.append(ch)
        value = "".join(chars).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.strip()


def load_dotenv(*, override: bool = False) -> None:
    """Load ``.env`` from repo root then cwd. Process env wins; cwd beats repo."""
    global _ENV_LOADED
    if _ENV_LOADED and not override:
        return
    preexisting = set(os.environ) if not override else set()
    repo = Path(__file__).resolve().parents[2]
    roots = [repo]
    cwd = Path.cwd()
    if cwd != repo:
        roots.append(cwd)
    collected: dict[str, str] = {}
    for root in roots:
        collected.update(_parse_dotenv(root / ".env"))
    for key, value in collected.items():
        if key not in preexisting:
            os.environ[key] = value
    _ENV_LOADED = True


def _parse_dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        key, _, rest = stripped.partition("=")
        key = key.strip()
        if not key or any(ch.isspace() for ch in key):
            continue
        parsed[key] = _strip_env_value(rest)
    return parsed


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
    def from_env(
        cls,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> LLMConfig:
        """Read LLM settings from env; explicit kwargs override.

        ``MCPAEGIS_LLM_MODEL`` selects the Chat Completions model id
        (OpenAI-compatible). The client falls back to ``gpt-4o-mini``
        when neither the CLI nor the env var sets a model.
        """
        load_dotenv()
        return cls(
            api_key=api_key if api_key is not None else (os.environ.get(LLM_API_KEY_ENV) or None),
            base_url=base_url if base_url is not None else (os.environ.get(LLM_BASE_URL_ENV) or None),
            model=model if model is not None else (os.environ.get(LLM_MODEL_ENV) or None),
        )


def parse_categories(raw: str | None) -> frozenset[Weakness] | None:
    """Parse a comma-separated weakness filter (`W1,W3`) into enum values."""
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
        llm_model: str | None = None,
        llm_base_url: str | None = None,
    ) -> AuditSession:
        output_dir = Path(output) if output is not None else Path.cwd() / "mcpaegis-out"
        color = False if no_color else sys.stdout.isatty()
        if llm is None:
            llm = LLMConfig.from_env(model=llm_model, base_url=llm_base_url)
        return cls(
            output_dir=output_dir,
            output_format=format,
            categories=parse_categories(categories),
            color=color,
            llm=llm,
        )
