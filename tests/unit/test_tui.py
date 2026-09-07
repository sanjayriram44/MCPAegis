"""TUI model toggle and report polish helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcpaegis.core.session import LLMConfig
from mcpaegis.llm.client import DEFAULT_MODEL, _delta_from_sse_line
from mcpaegis.lima.orchestrate import RunResult
from mcpaegis.core.models import InjectionFinding
from mcpaegis.core.taxonomy import SinkType
from mcpaegis.tui.app import (
    BRAND,
    FOOTER_START,
    LLM_TEXT,
    PATH_TEXT,
    REPORT_CYCLE_S,
    REPORT_INTRO,
    SCRIPT_TEXT,
    SCRIPT_TYPE_CHAR_MS,
    SCRIPT_TYPE_LINE_PAUSE,
    TYPE_CHAR_MS,
    TYPE_LINE_PAUSE,
    SHIELD_ART,
    STATUS_CYCLE_S,
    STATUS_CYCLES,
    WELCOME_TEXT,
    ModeScreen,
    ModelScreen,
    WizardApp,
    bullet,
    cycle_phrase,
    default_llm_on,
    phrase_due,
    phrase_hold,
    env_model_id,
    fallback_tui_report,
    llm_for_choice,
    looks_like_mcp_server,
    looks_like_test_script,
    polish_report,
    progress_line,
    resolve_user_path,
    status_sentence,
    status_stage,
    strip_dashes,
)
from tests.unit.helpers import static_report


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
    assert text.startswith(REPORT_INTRO)
    assert "Reports:" in text
    assert "CRITICAL" in text
    assert "HIGH" in text


def test_fallback_tui_report_explains_weakness():
    report = static_report(
        injection_findings=[
            InjectionFinding(
                tool_name="run_cmd",
                weakness_id="W5",
                sink_ref="subprocess",
                sink_type=SinkType.SHELL_EXEC,
                file="server.py",
                line=12,
                snippet="os.system(cmd)",
            )
        ]
    )
    result = RunResult(
        mode="static",
        server_path=Path("/tmp/server"),
        output_dir=Path("/tmp/out"),
        static_report=report,
    )
    text = fallback_tui_report(result)
    assert text.startswith(REPORT_INTRO)
    assert "then the findings" in text
    assert "**W5 (Command / SQL Injection)**" in text
    assert "Untrusted tool input reaches a command" in text
    assert "run_cmd" in text
    assert "CRITICAL means" in text
    assert "—" not in text


def test_status_sentence_maps_lima_lines():
    assert status_stage("First start downloads Ubuntu (~600MB)") == "download_ubuntu"
    assert status_sentence("First start downloads Ubuntu (~600MB)") == "Downloading Ubuntu..."
    assert status_sentence("Starting stopped Lima instance 'mcpaegis'…") == "Starting Lima..."
    assert status_sentence("Installing MCPAegis from shared checkout") == "Installing guest venv..."
    assert status_sentence("Running static analysis on this host…") == "Running static..."
    assert status_sentence("guest runtime: sudo -n -E mcpaegis") == "Running runtime..."
    assert status_sentence("Stopping Lima to free host resources…") == "Stopping Lima..."
    assert status_sentence("unrelated chatter") is None


def test_cycle_phrase_starts_plain_then_wraps():
    first, nxt = cycle_phrase("static", 0)
    assert first == STATUS_CYCLES["static"][0]
    assert first == "Running static..."
    second, nxt2 = cycle_phrase("static", nxt)
    assert second == STATUS_CYCLES["static"][1]
    last_index = len(STATUS_CYCLES["report"]) - 1
    last, wrapped = cycle_phrase("report", last_index)
    assert last == STATUS_CYCLES["report"][-1]
    assert wrapped == 0
    assert len(STATUS_CYCLES["report"]) >= 5


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
    assert "Hi, I am MCPAegis." in WELCOME_TEXT
    assert "OpenRouter" in WELCOME_TEXT
    assert WELCOME_TEXT.index("OpenRouter") < WELCOME_TEXT.index("three modes")
    assert "MCPAEGIS_LLM_API_KEY" in WELCOME_TEXT
    assert "https://openrouter.ai/api/v1" in WELCOME_TEXT
    assert "MCPAEGIS_LLM_MODEL" in WELCOME_TEXT
    assert "First is static" in WELCOME_TEXT
    assert "Second is runtime" in WELCOME_TEXT
    assert "Third is full" in WELCOME_TEXT
    assert "arrow keys" in WELCOME_TEXT
    assert "1-3" not in WELCOME_TEXT


def test_llm_path_script_copy():
    assert LLM_TEXT.startswith("Great choice.")
    assert "Do you want to use an LLM?" in LLM_TEXT
    assert "heuristics defined in my README" in LLM_TEXT
    assert "relative or absolute" in PATH_TEXT.lower()
    assert "launched me from" in PATH_TEXT
    assert "~/mcpaegis-servers/" in PATH_TEXT
    assert "auto-args" in SCRIPT_TEXT
    assert "Leave this blank" in SCRIPT_TEXT
    assert "tool_name: run_cmd" in SCRIPT_TEXT
    assert "command: echo hello" in SCRIPT_TEXT
    assert "either a relative or an absolute path" in SCRIPT_TEXT
    assert SCRIPT_TYPE_CHAR_MS > TYPE_CHAR_MS
    assert SCRIPT_TYPE_LINE_PAUSE > TYPE_LINE_PAUSE


def test_report_status_is_much_slower_than_live_stages():
    assert REPORT_CYCLE_S == 20.0
    assert REPORT_CYCLE_S >= STATUS_CYCLE_S * 4
    assert phrase_hold("report") == 20.0
    assert phrase_hold("static") == STATUS_CYCLE_S
    assert phrase_due(0.0, 19.9, REPORT_CYCLE_S) is False
    assert phrase_due(0.0, 20.0, REPORT_CYCLE_S) is True
    assert phrase_due(0.0, 1.9, STATUS_CYCLE_S) is False
    assert phrase_due(0.0, 2.0, STATUS_CYCLE_S) is True


def test_progress_line_fills_in_order():
    from mcpaegis.tui.app import progress_labels

    first = progress_line(1)
    assert first.count("●") == 1
    assert first.count("○") == 4
    assert first.index("●") < first.index("○")
    assert progress_line(3).count("●") == 3
    assert progress_line(5).count("●") == 5
    assert progress_line(5).count("○") == 0
    labels = progress_labels(2)
    assert "mode" in labels
    assert "llm" in labels
    assert labels.index("#2dd4bf") < labels.rindex("#6b8f89")


def test_resolve_user_path_relative_and_absolute(tmp_path: Path, monkeypatch):
    launch = tmp_path / "launch"
    launch.mkdir()
    server = launch / "my-mcp"
    server.mkdir()
    monkeypatch.chdir(launch)
    relative = resolve_user_path("my-mcp", cwd=launch)
    assert relative == server.resolve()
    absolute = resolve_user_path(str(server), cwd=tmp_path / "elsewhere")
    assert absolute == server.resolve()
    homeish = resolve_user_path("~/does-not-need-to-exist")
    assert homeish.is_absolute()


def test_looks_like_mcp_server_accepts_fixture():
    root = Path(__file__).resolve().parents[1] / "fixtures" / "command_injection"
    assert looks_like_mcp_server(root) is None
    assert looks_like_mcp_server(root / "server.py") is None


def test_looks_like_mcp_server_rejects_empty(tmp_path: Path):
    empty = tmp_path / "not-a-server"
    empty.mkdir()
    (empty / "notes.txt").write_text("hello", encoding="utf-8")
    assert looks_like_mcp_server(empty) is not None
    assert looks_like_mcp_server(tmp_path / "missing") is not None


def test_looks_like_test_script_blank_is_ok(tmp_path: Path):
    server = tmp_path / "srv"
    server.mkdir()
    assert looks_like_test_script("", str(server)) is None


def test_looks_like_test_script_accepts_yaml(tmp_path: Path):
    server = tmp_path / "srv"
    server.mkdir()
    script = server / "runtime.yaml"
    script.write_text("- tool_name: run_cmd\n  arguments:\n    command: echo hi\n", encoding="utf-8")
    assert looks_like_test_script("runtime.yaml", str(server)) is None
    assert looks_like_test_script(str(script), str(server)) is None


def test_looks_like_test_script_rejects_garbage(tmp_path: Path):
    server = tmp_path / "srv"
    server.mkdir()
    junk = server / "notes.txt"
    junk.write_text("not a script", encoding="utf-8")
    assert looks_like_test_script(str(junk), str(server)) is not None
    assert looks_like_test_script("missing.yaml", str(server)) is not None


def test_brand_and_footer_say_quit():
    assert BRAND == "MCPAegis"
    assert "type quit to quit" in FOOTER_START
    assert "type q to quit" not in FOOTER_START


def test_tui_opening_screen_welcome_and_top_alignment():
    async def _run():
        app = WizardApp()
        app.intro_played = True
        async with app.run_test(size=(80, 24)) as pilot:
            assert isinstance(app.screen, ModeScreen)
            shield = app.screen.query_one("#shield")
            rendered = str(shield.render())
            assert "||" in rendered
            assert "________" in rendered
            assert "🛡" not in rendered
            assert "<==(||)==>" not in rendered
            welcome = app.screen.query_one("#welcome")
            assert str(welcome.render()) == WELCOME_TEXT
            assert "Hi, I am MCPAegis." in str(welcome.render())
            footer = str(app.screen.query_one("#footer").render())
            assert footer == FOOTER_START
            assert "type quit to quit" in footer
            bar = str(app.screen.query_one("#progress").render())
            assert "●" in bar
            assert bar.count("●") == 1
            brand = str(app.screen.query_one(".brand").render())
            assert brand == "MCPAegis"
            assert len(app.screen.query(".title")) == 0

            list_node = app.screen.query_one("#list")
            initial_y = list_node.region.y
            # Bullet list should stick close to the top (ASCII shield + welcome)
            assert initial_y <= 32

            await pilot.resize_terminal(80, 60)
            await pilot.pause()
            assert list_node.region.y <= initial_y

            await pilot.resize_terminal(120, 100)
            await pilot.pause()
            assert list_node.region.y <= 32

    asyncio.run(_run())


def test_digit_keys_do_not_change_mode():
    async def _run():
        app = WizardApp()
        app.intro_played = True
        async with app.run_test(size=(80, 24)) as pilot:
            assert app.mode == "full"
            await pilot.press("1")
            await pilot.pause()
            assert app.mode == "full"
            await pilot.press("2")
            await pilot.pause()
            assert app.mode == "full"
            await pilot.press("up")
            await pilot.pause()
            assert app.mode == "runtime"
            await pilot.press("q")
            await pilot.pause()
            assert app.is_running

    asyncio.run(_run())


def test_intro_types_once_then_shows_full():
    async def _run():
        app = WizardApp()
        async with app.run_test(size=(80, 24)) as pilot:
            welcome = app.screen.query_one("#welcome")
            first = str(welcome.render())
            assert first != WELCOME_TEXT
            app.intro_played = True
            app.push_screen(ModeScreen())
            await pilot.pause()
            second = str(app.screen.query_one("#welcome").render())
            assert second == WELCOME_TEXT

    asyncio.run(_run())


def test_tui_model_screen_top_alignment_on_expand():
    async def _run():
        app = WizardApp()
        app.intro_played = True
        app.llm_intro_played = True
        async with app.run_test(size=(80, 24)) as pilot:
            # Advance to ModelScreen
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ModelScreen)
            yes = str(app.screen.query_one("#llm-on").render())
            no = str(app.screen.query_one("#llm-off").render())
            assert "yes" in yes
            assert "no" in no
            welcome = str(app.screen.query_one("#welcome").render())
            assert welcome == LLM_TEXT
            footer = str(app.screen.query_one("#footer").render())
            assert "esc back" in footer
            assert "type quit to quit" in footer
            bar = str(app.screen.query_one("#progress").render())
            assert bar.count("●") == 2
            wrap = app.screen.query_one("#progress-wrap")
            assert wrap.region.x >= 20
            started = app.llm_on
            await pilot.press("down")
            await pilot.pause()
            assert app.llm_on is (not started)
            await pilot.press("down")
            await pilot.pause()
            assert app.llm_on is started

            list_node = app.screen.query_one("#list")
            initial_y = list_node.region.y
            assert initial_y <= 12

            # Expanding terminal should keep model bullet choices at the top
            await pilot.resize_terminal(80, 60)
            await pilot.pause()
            assert list_node.region.y == initial_y

            await pilot.resize_terminal(120, 100)
            await pilot.pause()
            assert list_node.region.y == initial_y

            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, ModeScreen)
            back = str(app.screen.query_one("#progress").render())
            assert back.count("●") == 1

    asyncio.run(_run())
