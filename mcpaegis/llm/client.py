"""OpenAI-compatible LLM client. Missing API key skips semantic stages."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urljoin

from mcpaegis.core.session import LLMConfig
from mcpaegis.llm.prompts import PromptPair

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT_SEC = 30.0


class LLMUnavailable(Exception):
    """Raised only when the caller opts into hard failures (not used by static)."""


class LLMClient:
    """Thin Chat Completions wrapper.

    Configuration (via :class:`~mcpaegis.core.session.LLMConfig` / env):
    - ``MCPAEGIS_LLM_API_KEY`` — required to enable semantic stages
    - ``MCPAEGIS_LLM_BASE_URL`` — optional OpenAI-compatible base (default OpenAI)
    - ``MCPAEGIS_LLM_MODEL`` — optional model id (default ``gpt-4o-mini``)

    If no API key is set, :meth:`complete` / :meth:`complete_json` return
    ``None`` and log a skip. Network/API errors also return ``None`` unless
    ``raise_on_error=True``. Static analysis must never fail because of LLM.
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config if config is not None else LLMConfig.from_env()

    @classmethod
    def from_session(cls, session: Any) -> LLMClient:
        """Build from an :class:`~mcpaegis.core.session.AuditSession` (uses ``session.llm``)."""
        llm = getattr(session, "llm", None)
        if isinstance(llm, LLMConfig):
            return cls(llm)
        return cls()

    @classmethod
    def from_env(cls) -> LLMClient:
        return cls(LLMConfig.from_env())

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def complete(
        self,
        system: str | None = None,
        user: str | None = None,
        *,
        prompt: PromptPair | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        temperature: float = 0.0,
        raise_on_error: bool = False,
    ) -> str | None:
        """Run a chat completion. Returns ``None`` when skipped or on soft failure."""
        if prompt is not None:
            system = prompt.system if system is None else system
            user = prompt.user if user is None else user
        if not system or not user:
            raise ValueError("complete() requires system+user strings or a PromptPair")

        if not self.enabled:
            logger.info("LLM semantic stage skipped: %s is not set", "MCPAEGIS_LLM_API_KEY")
            return None

        model_name = model or self.config.model or DEFAULT_MODEL
        base = (self.config.base_url or DEFAULT_BASE_URL).rstrip("/") + "/"
        url = urljoin(base, "chat/completions")
        payload = {
            "model": model_name,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("LLM request failed; skipping semantic stage: %s", exc)
            if raise_on_error:
                raise LLMUnavailable(str(exc)) from exc
            return None

        try:
            data = json.loads(raw)
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            logger.warning("LLM response missing message content; skipping: %s", exc)
            if raise_on_error:
                raise LLMUnavailable(str(exc)) from exc
            return None
        if not isinstance(content, str):
            logger.warning("LLM content was not a string; skipping semantic stage")
            return None
        return content.strip()

    def complete_stream(
        self,
        system: str | None = None,
        user: str | None = None,
        *,
        prompt: PromptPair | None = None,
        model: str | None = None,
        timeout: float = 90.0,
        temperature: float = 0.0,
        raise_on_error: bool = False,
        on_delta: Callable[[str], None] | None = None,
    ) -> str | None:
        """Stream a chat completion. Falls back to :meth:`complete` if SSE fails."""
        if prompt is not None:
            system = prompt.system if system is None else system
            user = prompt.user if user is None else user
        if not system or not user:
            raise ValueError("complete_stream() requires system+user strings or a PromptPair")
        if not self.enabled:
            logger.info("LLM semantic stage skipped: %s is not set", "MCPAEGIS_LLM_API_KEY")
            return None

        model_name = model or self.config.model or DEFAULT_MODEL
        base = (self.config.base_url or DEFAULT_BASE_URL).rstrip("/") + "/"
        url = urljoin(base, "chat/completions")
        payload = {
            "model": model_name,
            "temperature": temperature,
            "stream": True,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
        )
        pieces: list[str] = []
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                for delta in _iter_sse_deltas(response):
                    pieces.append(delta)
                    if on_delta is not None:
                        on_delta(delta)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            logger.warning("LLM stream failed; falling back to complete: %s", exc)
            if raise_on_error:
                raise LLMUnavailable(str(exc)) from exc
            text = self.complete(
                system,
                user,
                model=model,
                timeout=timeout,
                temperature=temperature,
                raise_on_error=raise_on_error,
            )
            if text and on_delta is not None:
                on_delta(text)
            return text
        joined = "".join(pieces).strip()
        return joined or None

    def complete_json(
        self,
        system: str | None = None,
        user: str | None = None,
        *,
        prompt: PromptPair | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        temperature: float = 0.0,
        raise_on_error: bool = False,
    ) -> dict[str, Any] | None:
        """Like :meth:`complete`, but parse a JSON object (markdown fences stripped)."""
        text = self.complete(
            system,
            user,
            prompt=prompt,
            model=model,
            timeout=timeout,
            temperature=temperature,
            raise_on_error=raise_on_error,
        )
        if text is None:
            return None
        parsed = _parse_json_object(text)
        if parsed is None:
            logger.warning("LLM returned non-JSON content; skipping semantic stage")
            if raise_on_error:
                raise LLMUnavailable("LLM returned non-JSON content")
        return parsed


def _delta_from_sse_line(line: str) -> str | None:
    """Extract chat content from one SSE ``data:`` line. ``None`` means ignore / done."""
    stripped = line.strip()
    if not stripped or stripped.startswith(":"):
        return None
    if stripped.startswith("data:"):
        stripped = stripped[5:].strip()
    if not stripped or stripped == "[DONE]":
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    try:
        delta = data["choices"][0].get("delta") or {}
        content = delta.get("content")
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    return content if isinstance(content, str) and content else None


def _iter_sse_deltas(response: Any) -> Iterator[str]:
    while True:
        raw = response.readline()
        if not raw:
            break
        if isinstance(raw, bytes):
            line = raw.decode("utf-8", errors="replace")
        else:
            line = str(raw)
        delta = _delta_from_sse_line(line)
        if delta:
            yield delta


def _parse_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            value = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return None
    return value if isinstance(value, dict) else None
