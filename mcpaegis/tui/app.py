"""Minimal teal wizard: mode → model on/off → path → script → run."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from mcpaegis.core.session import LLM_MODEL_ENV, AuditSession, LLMConfig, load_dotenv
from mcpaegis.lima.orchestrate import Mode, RunResult, run_analysis
from mcpaegis.lima.paths import default_output_dir
from mcpaegis.llm.client import DEFAULT_MODEL, LLMClient
from mcpaegis.llm.prompts import build_tui_report_prompt
from mcpaegis.output.findings import collect_findings, sort_findings, weakness_title
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, Log, Markdown, Static

CSS = """
Screen {
    background: #041210;
    color: #e8f5f2;
    align: left top;
}

.chrome {
    dock: top;
    height: 3;
    padding: 1 3 0 3;
}

.brand {
    color: #2dd4bf;
    text-style: bold;
}

.hint {
    color: #6b8f89;
}

#body {
    padding: 1 3;
    align: left top;
}

.welcome {
    color: #99f6e4;
    height: auto;
    margin-bottom: 1;
}

.title {
    color: #e8f5f2;
    text-style: bold;
    height: 1;
    margin-bottom: 1;
}

.sub {
    color: #6b8f89;
    height: auto;
    margin-bottom: 1;
}

#list {
    height: auto;
    width: auto;
    align: left top;
}

.choice {
    height: 1;
    width: auto;
    color: #5eead4;
    background: transparent;
    margin-bottom: 1;
}

.choice.-on {
    color: #2dd4bf;
    text-style: bold;
}

#field {
    width: 100%;
    max-width: 88;
    background: #0a1f1c;
    color: #e8f5f2;
    border: tall #134e4a;
    padding: 0 1;
}

#field:focus {
    border: tall #2dd4bf;
}

#error {
    color: #f87171;
    height: auto;
    margin-top: 1;
}

#stage {
    height: 1fr;
}

#log {
    height: 1fr;
    background: #041210;
    color: #99f6e4;
    border: none;
    padding: 0 3;
    scrollbar-background: #041210;
    scrollbar-color: #134e4a;
}

#findings-body {
    height: 1fr;
    padding: 0 3 1 3;
    scrollbar-background: #041210;
    scrollbar-color: #134e4a;
}

#footer {
    dock: bottom;
    height: 1;
    background: #041210;
    color: #6b8f89;
    padding: 0 3;
}
"""

MODES: tuple[tuple[Mode, str], ...] = (
    ("static", "static"),
    ("runtime", "runtime"),
    ("full", "full"),
)


def env_model_id() -> str:
    return (os.environ.get(LLM_MODEL_ENV) or "").strip() or DEFAULT_MODEL


def default_llm_on() -> bool:
    return bool((os.environ.get("MCPAEGIS_LLM_API_KEY") or "").strip())


def llm_for_choice(on: bool) -> LLMConfig:
    """On uses the env model (MCPAEGIS_LLM_MODEL). Off clears the key."""
    base = LLMConfig.from_env()
    if not on:
        return LLMConfig(api_key=None, base_url=base.base_url, model=base.model)
    return LLMConfig(api_key=base.api_key, base_url=base.base_url, model=base.model or env_model_id())


def strip_dashes(text: str) -> str:
    for dash in ("\u2014", "\u2013"):
        text = text.replace(f" {dash} ", " - ").replace(dash, " - ")
    return text


def bullet(selected: bool, label: str) -> str:
    mark = "●" if selected else "○"
    return f"{mark}  {label}"


def fallback_tui_report(result: RunResult) -> str:
    """Local W5 (title) + paragraph layout when the LLM is off or fails."""
    source = result.combined_report or result.dynamic_report or result.static_report
    extra = f"Reports: `{result.output_dir}`"
    if source is None:
        raw = strip_dashes(result.markdown or "_No findings._")
        return raw if "Reports:" in raw else f"{raw}\n\n{extra}"
    records = sort_findings(collect_findings(source))
    if not records:
        return f"_No findings._\n\n{extra}"
    parts: list[str] = []
    for rec in records:
        title = weakness_title(rec.weakness_id)
        parts.append(f"**{rec.weakness_id} ({title})**")
        bits = [rec.severity]
        if rec.tool_name:
            bits.append(f"tool `{rec.tool_name}`")
        if rec.confidence:
            bits.append(rec.confidence)
        para = rec.message.strip()
        where = ""
        if rec.file:
            loc = rec.file if rec.line is None else f"{rec.file}:{rec.line}"
            where = f" Evidence at `{loc}`."
        parts.append(f"{', '.join(bits)}. {para}{where}")
        parts.append("")
    parts.append(extra)
    return strip_dashes("\n".join(parts).strip())


def polish_report(
    markdown: str,
    config: LLMConfig,
    *,
    on_text: Callable[[str], None] | None = None,
) -> str:
    """Rewrite the report for the TUI. Streams tokens when ``on_text`` is set."""
    raw = strip_dashes(markdown or "")
    if not raw.strip() or not config.enabled:
        if on_text is not None:
            on_text(raw)
        return raw
    buf: list[str] = []
    last = 0.0

    def handle(delta: str) -> None:
        nonlocal last
        buf.append(delta)
        if on_text is None:
            return
        now = time.monotonic()
        if "\n" in delta or now - last >= 0.08:
            last = now
            on_text(strip_dashes("".join(buf)))

    text = LLMClient(config).complete_stream(
        prompt=build_tui_report_prompt(report=raw),
        timeout=90.0,
        on_delta=handle,
    )
    final = strip_dashes(text) if text else raw
    if on_text is not None:
        on_text(final)
    return final


WELCOME_TEXT = (
    "Welcome to MCPAegis, a security analysis tool for local MCP servers.\n"
    "Select an audit mode below using ↑/↓ or 1-3, then press Enter to continue."
)


class _Chrome(Vertical):
    def __init__(self, hint: str) -> None:
        super().__init__(classes="chrome")
        self._hint = hint

    def compose(self) -> ComposeResult:
        yield Static("mcpaegis", classes="brand")
        yield Static(self._hint, classes="hint")

    def set_hint(self, hint: str) -> None:
        self.query_one(".hint", Static).update(hint)


class ModeScreen(Screen[None]):
    BINDINGS = [
        Binding("enter", "next", "continue", show=True, priority=True),
        Binding("escape", "app.quit", "quit", show=False),
        Binding("1", "pick_static", "static", show=False),
        Binding("2", "pick_runtime", "runtime", show=False),
        Binding("3", "pick_full", "full", show=False),
        Binding("up", "mode_prev", "prev", show=False),
        Binding("down", "mode_next", "next", show=False),
        Binding("left", "mode_prev", "prev", show=False),
        Binding("right", "mode_next", "next", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome("enter continue  ·  q quit")
        with Vertical(id="body"):
            yield Static(WELCOME_TEXT, id="welcome", classes="welcome")
            yield Static("mode", classes="title")
            yield Static("what to run  ·  ↑ ↓", classes="sub")
            with Vertical(id="list"):
                for key, label in MODES:
                    item = Static(bullet(False, label), id=f"mode-{key}", classes="choice")
                    item.can_focus = False
                    yield item
        yield Static("1 static  ·  2 runtime  ·  3 full", id="footer")

    def on_mount(self) -> None:
        self._paint()

    def _paint(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        for key, label in MODES:
            node = self.query_one(f"#mode-{key}", Static)
            on = key == app.mode
            node.update(bullet(on, label))
            node.set_class(on, "-on")

    def on_click(self, event) -> None:
        target = event.widget
        wid = getattr(target, "id", None) or ""
        if wid.startswith("mode-"):
            self._set_mode(wid.removeprefix("mode-"))  # type: ignore[arg-type]

    def action_pick_static(self) -> None:
        self._set_mode("static")

    def action_pick_runtime(self) -> None:
        self._set_mode("runtime")

    def action_pick_full(self) -> None:
        self._set_mode("full")

    def action_mode_prev(self) -> None:
        self._nudge(-1)

    def action_mode_next(self) -> None:
        self._nudge(1)

    def _nudge(self, delta: int) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        keys = [key for key, _ in MODES]
        idx = (keys.index(app.mode) + delta) % len(keys)
        self._set_mode(keys[idx])

    def _set_mode(self, mode: Mode) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        app.mode = mode
        self._paint()

    def action_next(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        app.go_model()


class ModelScreen(Screen[None]):
    BINDINGS = [
        Binding("enter", "next", "continue", show=True, priority=True),
        Binding("escape", "back", "back", show=True),
        Binding("up", "off", "off", show=False),
        Binding("down", "on", "on", show=False),
        Binding("left", "off", "off", show=False),
        Binding("right", "on", "on", show=False),
        Binding("o", "on", "on", show=False),
        Binding("f", "off", "off", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome("enter continue  ·  esc back  ·  q quit")
        with Vertical(id="body"):
            yield Static("model", classes="title")
            yield Static(f"{env_model_id()}  ·  ↑ off  ↓ on", classes="sub")
            with Vertical(id="list"):
                off = Static(bullet(False, "off"), id="llm-off", classes="choice")
                on = Static(bullet(False, "on"), id="llm-on", classes="choice")
                off.can_focus = False
                on.can_focus = False
                yield off
                yield on
        yield Static("", id="footer")

    def on_mount(self) -> None:
        self._paint()

    def _paint(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        off_node = self.query_one("#llm-off", Static)
        on_node = self.query_one("#llm-on", Static)
        off_node.update(bullet(not app.llm_on, "off"))
        on_node.update(bullet(app.llm_on, "on"))
        off_node.set_class(not app.llm_on, "-on")
        on_node.set_class(app.llm_on, "-on")

    def on_click(self, event) -> None:
        wid = getattr(event.widget, "id", None) or ""
        if wid == "llm-on":
            self._set(True)
        elif wid == "llm-off":
            self._set(False)

    def action_on(self) -> None:
        self._set(True)

    def action_off(self) -> None:
        self._set(False)

    def _set(self, on: bool) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        app.llm_on = on
        self._paint()

    def action_next(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        app.go_path()

    def action_back(self) -> None:
        self.app.pop_screen()


class PathScreen(Screen[None]):
    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome("enter continue  ·  esc back  ·  q quit")
        with Vertical(id="body"):
            yield Static("server path", classes="title")
            yield Static("mcp server directory or file  ·  under ~ for runtime/full", classes="sub")
            yield Input(placeholder="/Users/you/src/my-mcp-server", id="field")
            yield Static("", id="error")
        yield Static("", id="footer")

    def on_mount(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        field = self.query_one("#field", Input)
        if app.server_path:
            field.value = app.server_path
        field.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._advance(event.value)

    def action_back(self) -> None:
        self.app.pop_screen()

    def _advance(self, raw: str) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        path = raw.strip()
        if not path:
            self.query_one("#error", Static).update("enter a path")
            return
        app.server_path = path
        app.go_script()


class ScriptScreen(Screen[None]):
    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome("enter run  ·  esc back  ·  q quit")
        with Vertical(id="body"):
            yield Static("test script", classes="title")
            yield Static("empty = auto args  ·  or a path to runtime.yaml / .txt", classes="sub")
            yield Input(placeholder="runtime.yaml", id="field")
            yield Static("", id="error")
        yield Static("", id="footer")

    def on_mount(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        field = self.query_one("#field", Input)
        if app.test_script:
            field.value = app.test_script
        field.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        app.test_script = event.value.strip()
        app.start_run()

    def action_back(self) -> None:
        self.app.pop_screen()


class RunScreen(Screen[None]):
    BINDINGS = [
        Binding("enter", "again", "again", show=False, priority=True),
        Binding("escape", "again", "again", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._ready = False

    def compose(self) -> ComposeResult:
        app = self.app
        assert isinstance(app, WizardApp)
        yield _Chrome(f"{app.mode}  ·  {app.server_path}")
        with Vertical(id="stage"):
            yield Log(id="log", highlight=False, auto_scroll=True)
            with VerticalScroll(id="findings-body"):
                yield Markdown("", id="findings-md")
        yield Static("running…", id="footer")

    def on_mount(self) -> None:
        self.query_one("#findings-body").display = False
        app = self.app
        assert isinstance(app, WizardApp)
        model = env_model_id() if app.llm_on else "off"
        self.append_log(f"starting {app.mode}")
        self.append_log(f"model {model}")
        self.append_log(f"path  {app.server_path}")
        if app.test_script.strip():
            self.append_log(f"script {app.test_script}")
        else:
            self.append_log("script auto")

    def append_log(self, line: str) -> None:
        self.query_one("#log", Log).write_line(line)

    def open_report(self, *, error: bool) -> None:
        self.query_one("#log").display = False
        body = self.query_one("#findings-body")
        body.display = True
        self.query_one("#findings-md", Markdown).update("")
        self.query_one(_Chrome).set_hint("error" if error else "writing…")
        self.query_one("#footer", Static).update("generating report…")

    def set_report(self, markdown: str) -> None:
        body = self.query_one("#findings-body")
        if not body.display:
            self.open_report(error=False)
        self.query_one("#findings-md", Markdown).update(markdown)
        self.call_after_refresh(lambda: body.scroll_end(animate=False))

    def finish_report(self, markdown: str, *, error: bool) -> None:
        self.set_report(markdown)
        self.query_one(_Chrome).set_hint("error" if error else "done")
        self.query_one("#footer", Static).update("enter new run  ·  q quit")
        self._ready = True

    def action_again(self) -> None:
        if not self._ready:
            return
        app = self.app
        assert isinstance(app, WizardApp)
        app.reset_wizard()


class WizardApp(App[None]):
    CSS = CSS
    TITLE = "mcpaegis"
    BINDINGS = [
        Binding("q", "quit", "quit", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.mode: Mode = "full"
        self.llm_on = default_llm_on()
        self.server_path = ""
        self.test_script = ""
        self._cancel = threading.Event()
        self._busy = False

    def on_mount(self) -> None:
        self.push_screen(ModeScreen())

    def action_quit(self) -> None:
        self._cancel.set()
        self.exit()

    def go_model(self) -> None:
        self.push_screen(ModelScreen())

    def go_path(self) -> None:
        self.push_screen(PathScreen())

    def go_script(self) -> None:
        self.push_screen(ScriptScreen())

    def start_run(self) -> None:
        if self._busy:
            return
        path = self.server_path.strip()
        if not path:
            return
        self._busy = True
        self._cancel.clear()
        self.push_screen(RunScreen())
        script = self.test_script.strip() or None
        threading.Thread(target=self._worker, args=(path, script), daemon=True).start()

    def _append_log(self, line: str) -> None:
        try:
            screen = self.screen
            if isinstance(screen, RunScreen):
                screen.append_log(line)
        except Exception:  # noqa: BLE001
            return

    def _set_report(self, markdown: str) -> None:
        try:
            screen = self.screen
            if isinstance(screen, RunScreen):
                screen.set_report(markdown)
        except Exception:  # noqa: BLE001
            return

    def _worker(self, path: str, script: str | None) -> None:
        def on_log(message: str) -> None:
            self.call_from_thread(self._append_log, message)

        last_ui = 0.0

        def on_report(text: str) -> None:
            nonlocal last_ui
            extra = ""
            if "Reports:" not in text:
                extra = f"\n\nReports: `{session.output_dir}`"
            now = time.monotonic()
            if now - last_ui < 0.12:
                return
            last_ui = now
            self.call_from_thread(self._set_report, text + extra)

        server = Path(path).expanduser()
        llm = llm_for_choice(self.llm_on)
        session = AuditSession.from_cli(
            output=default_output_dir(server),
            format="json",
            no_color=True,
            llm=llm,
        )
        result = run_analysis(
            self.mode,
            path,
            output=session.output_dir,
            test_script=script,
            log=on_log,
            cancel=self._cancel.is_set,
            session=session,
        )
        extra = f"\n\nReports: `{result.output_dir}`"
        if result.error:
            body = f"**error**\n\n{result.error}"
        elif llm.enabled:
            on_log("writing report…")
            self.call_from_thread(self._open_report, False)
            md = result.markdown or "_No findings._"
            polished = polish_report(md, llm, on_text=on_report)
            body = polished if "Reports:" in polished else polished + extra
            if not polished.strip():
                body = fallback_tui_report(result)
        else:
            self.call_from_thread(self._open_report, False)
            body = fallback_tui_report(result)
            self.call_from_thread(self._set_report, body)
        self.call_from_thread(self._finish, result, body)

    def _open_report(self, error: bool) -> None:
        screen = self.screen
        if isinstance(screen, RunScreen):
            screen.open_report(error=error)

    def _finish(self, result: RunResult, body: str) -> None:
        screen = self.screen
        if isinstance(screen, RunScreen):
            screen.finish_report(body, error=bool(result.error))
        self._busy = False

    def reset_wizard(self) -> None:
        self._busy = False
        while not isinstance(self.screen, ModeScreen):
            if len(self.screen_stack) <= 1:
                self.push_screen(ModeScreen())
                break
            self.pop_screen()


def run_tui() -> None:
    """Launch the interactive wizard (requires a TTY)."""
    load_dotenv()
    WizardApp().run()
