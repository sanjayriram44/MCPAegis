"""TUI model toggle and report polish helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcpaegis.core.session import LLMConfig
from mcpaegis.llm.client import DEFAULT_MODEL, _delta_from_sse_line
from mcpaegis.lima.orchestrate import RunResult
from mcpaegis.tui.app import (
    WELCOME_TEXT,
    ModeScreen,
    ModelScreen,
    WizardApp,
    bullet,
    default_llm_on,
    env_model_id,
    fallback_tui_report,
    llm_for_choice,
    polish_report,
    strip_dashes,
)


def test_env_model_id_reads_env(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "qwen/qwen3.8-27b")
    assert env_model_id() == "qwen/qwen3.8-27b"


def test_env_model_id_falls_back(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "")
    assert env_model_id() == DEFAULT_MODEL


def test_default_llm_on_requires_key(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "")
    assert default_llm_on() is False
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-test")
    assert default_llm_on() is True


def test_llm_for_choice_off_disables(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "qwen/qwen3.8-27b")
    cfg = llm_for_choice(False)
    assert cfg.api_key is None
    assert not cfg.enabled
    assert cfg.model == "qwen/qwen3.8-27b"


def test_llm_for_choice_on_keeps_env_model(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("MCPAEGIS_LLM_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "qwen/qwen3.8-27b")
    cfg = llm_for_choice(True)
    assert cfg.enabled
    assert cfg.model == "qwen/qwen3.8-27b"
    assert cfg.base_url == "https://openrouter.ai/api/v1"


def test_strip_dashes_replaces_em_and_en():
    assert strip_dashes("a — b – c") == "a - b - c"


def test_polish_report_off_returns_stripped():
    cfg = LLMConfig(api_key=None, model="qwen/qwen3.8-27b")
    assert polish_report("hello — world", cfg) == "hello - world"


def test_bullet_fills_selected():
    assert bullet(True, "full").startswith("●")
    assert bullet(False, "static").startswith("○")


def test_fallback_tui_report_uses_w_heading():
    result = RunResult(
        mode="static",
        server_path=Path("/tmp/server"),
        output_dir=Path("/tmp/out"),
        markdown="- **HIGH** `W5` Command / SQL Injection tool `run_cmd`\n  shell exec",
    )
    text = fallback_tui_report(result)
    assert "Reports:" in text


def test_sse_delta_extracts_content():
    line = 'data: {"choices":[{"delta":{"content":"**W5"}}]}'
    assert _delta_from_sse_line(line) == "**W5"
    assert _delta_from_sse_line("data: [DONE]") is None
    assert _delta_from_sse_line(": ping") is None


def test_polish_report_uses_llm(monkeypatch):
    from mcpaegis.tui import app as tui_app

    monkeypatch.setattr(
        tui_app.LLMClient,
        "complete_stream",
        lambda self, **_kwargs: "# Report\n\n**W5 (Command / SQL Injection)**\n\nrun_cmd — confirmed",
    )
    cfg = LLMConfig(api_key="sk-test", model="qwen/qwen3.8-27b")
    out = polish_report("raw findings", cfg)
    assert "W5 (Command / SQL Injection)" in out
    assert "—" not in out


def test_welcome_text_content():
    assert "Welcome to MCPAegis" in WELCOME_TEXT
    assert "security analysis" in WELCOME_TEXT
    assert "Enter to continue" in WELCOME_TEXT


def test_tui_opening_screen_welcome_and_top_alignment():
    async def _run():
        app = WizardApp()
        async with app.run_test(size=(80, 24)) as pilot:
            assert isinstance(app.screen, ModeScreen)
            welcome = app.screen.query_one("#welcome")
            assert str(welcome.render()) == WELCOME_TEXT
            assert "Welcome to MCPAegis" in str(welcome.render())

            list_node = app.screen.query_one("#list")
            initial_y = list_node.region.y
            # Bullet list should stick close to the top
            assert initial_y <= 12

            # Expanding terminal height should keep the bullet list aligned to the top
            await pilot.resize_terminal(80, 60)
            await pilot.pause()
            assert list_node.region.y == initial_y

            await pilot.resize_terminal(120, 100)
            await pilot.pause()
            assert list_node.region.y == initial_y

    asyncio.run(_run())


def test_tui_model_screen_top_alignment_on_expand():
    async def _run():
        app = WizardApp()
        async with app.run_test(size=(80, 24)) as pilot:
            # Advance to ModelScreen
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ModelScreen)

            list_node = app.screen.query_one("#list")
            initial_y = list_node.region.y
            assert initial_y <= 10

            # Expanding terminal should keep model bullet choices at the top
            await pilot.resize_terminal(80, 60)
            await pilot.pause()
            assert list_node.region.y == initial_y

            await pilot.resize_terminal(120, 100)
            await pilot.pause()
            assert list_node.region.y == initial_y

    asyncio.run(_run())
