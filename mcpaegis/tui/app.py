"""Minimal teal wizard: mode → model on/off → path → script → run."""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from mcpaegis.core.session import LLM_MODEL_ENV, AuditSession, LLMConfig, load_dotenv
from mcpaegis.dynamic.invocation_generator import load_test_script
from mcpaegis.lima.orchestrate import Mode, RunResult, run_analysis
from mcpaegis.lima.paths import default_output_dir, resolve_test_script
from mcpaegis.llm.client import DEFAULT_MODEL, LLMClient
from mcpaegis.llm.prompts import build_tui_report_prompt
from mcpaegis.output.findings import collect_findings, sort_findings, weakness_title
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Key
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
    height: 4;
    layout: horizontal;
    padding: 1 3 0 3;
}

.brand {
    color: #2dd4bf;
    text-style: bold;
    height: 2;
    width: 1fr;
}

#progress-wrap {
    width: auto;
    height: 2;
    align: right top;
}

#progress {
    height: 1;
    width: auto;
    text-align: right;
}

#progress-labels {
    height: 1;
    width: auto;
    text-align: right;
}

.hint {
    color: #6b8f89;
}

#body {
    padding: 1 3;
    align: left top;
}

#shield {
    color: #2dd4bf;
    height: auto;
    width: auto;
    margin-bottom: 1;
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

.title.quiet {
    color: #6b8f89;
    text-style: none;
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

#status-box {
    height: 2;
    padding: 0 3;
    color: #5eead4;
    text-style: bold;
    border: none;
}

#log {
    height: 12;
    background: #041210;
    color: #99f6e4;
    border: tall #134e4a;
    margin: 0 3 1 3;
    padding: 0 1;
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


def resolve_user_path(raw: str, *, cwd: Path | None = None) -> Path:
    """Resolve a relative or absolute user path against ``cwd`` (launch directory)."""
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    return path.resolve()


_MCP_MARKERS = (
    "FastMCP",
    "MCPServer",
    "McpServer",
    "@mcp.tool",
    "@server.tool",
    "from mcp",
    "import mcp",
    "mcp.server",
    "mcp.tool(",
    "server.tool(",
    '"mcp"',
    "'mcp'",
)

_SKIP_SCAN = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".tox"}
)


def _text_looks_like_mcp(text: str) -> bool:
    lower = text.lower()
    return any(marker.lower() in lower for marker in _MCP_MARKERS)


def _scan_file_for_mcp(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        return _text_looks_like_mcp(path.read_text(encoding="utf-8", errors="replace")[:80_000])
    except OSError:
        return False


def looks_like_mcp_server(path: Path) -> str | None:
    """Return an error if ``path`` does not look like a local MCP server tree."""
    if not path.exists():
        return "that path does not exist"
    root = path.parent if path.is_file() else path
    if path.is_file():
        if _scan_file_for_mcp(path):
            return None
        return "that file does not look like an MCP server. point at the server root or a server.py / index.js"
    if not root.is_dir():
        return "that path is not a file or directory"
    named = (
        "server.py",
        "main.py",
        "mcp_server.py",
        "app.py",
        "index.js",
        "index.ts",
        "src/index.js",
        "src/index.ts",
        "package.json",
        "pyproject.toml",
    )
    for name in named:
        candidate = root / name
        if _scan_file_for_mcp(candidate):
            return None
    scanned = 0
    for pattern in ("*.py", "*.js", "*.ts", "*.mjs"):
        for file in root.rglob(pattern):
            if any(part in _SKIP_SCAN for part in file.parts):
                continue
            scanned += 1
            if scanned > 80:
                break
            if _scan_file_for_mcp(file):
                return None
        if scanned > 80:
            break
    return "I could not find an MCP server there. point at a tree with FastMCP, mcp.tool, or the mcp SDK"


def looks_like_test_script(raw: str, server_path: str, *, cwd: Path | None = None) -> str | None:
    """Return an error if a non-empty script path is missing or not tool calls."""
    text = raw.strip()
    if not text:
        return None
    server = Path(server_path) if server_path else (cwd or Path.cwd())
    try:
        found = resolve_test_script(server, text)
    except FileNotFoundError:
        return "that test script does not exist. use a relative or absolute path, or leave blank for auto-args"
    if found is None:
        return None
    try:
        invocations = load_test_script(found)
    except Exception:  # noqa: BLE001
        return "that file is not a test script. use yaml/json with tool_name and arguments, or leave blank"
    if not invocations:
        return "that script has no tool calls. add tool_name entries, or leave blank for auto-args"
    return None


REPORT_INTRO = (
    "Analysis is done. Here are the severity levels used in this report, then the findings."
)

SEVERITY_LEGEND = """\
**Severity**

CRITICAL means the MCP tool can take over the host or steal high-value secrets with little extra work.

HIGH means a real exploit path is present (injection, traversal, SSRF, leaked credentials) and should be fixed before this server is trusted.

MEDIUM means a meaningful weakness exists but needs a specific setup or extra step to abuse.

LOW means a hygiene or over-declaration issue that is worth tracking but is not an immediate exploit.
"""

FINDINGS_INTRO = "Each item below is a weakness we found. The first line says what it is. The next paragraph says what we saw and why it matters."

WEAKNESS_EXPLAINERS: dict[str, str] = {
    "W1": "Hidden or adversarial instructions in a tool description that can steer the host agent.",
    "W2": "A tool name or description that impersonates another tool so the agent calls the wrong one.",
    "W3": "Declared capabilities do not match what the code can actually do.",
    "W4": "A dependency of the MCP server is known-vulnerable.",
    "W5": "Untrusted tool input reaches a command, SQL, or similar interpreter.",
    "W6": "Untrusted input is used as a filesystem path and can escape the intended directory.",
    "W7": "Untrusted input is used as a URL so the server fetches attacker-controlled hosts.",
    "W8": "A sensitive tool runs without checking who called it.",
    "W9": "The agent is steered into calling a tool in a way the user did not intend.",
    "W10": "Secrets are hardcoded or leaked in the server tree.",
}

STATUS_CYCLES: dict[str, tuple[str, ...]] = {
    "starting": (
        "starting...",
        "Opening the notebook...",
        "Getting the audit in order...",
    ),
    "install_lima": (
        "Installing Lima...",
        "Fetching the hypervisor toolkit...",
        "Teaching the Mac to host Ubuntu...",
    ),
    "download_ubuntu": (
        "Downloading Ubuntu...",
        "Catching a cloud image...",
        "Pulling a guest OS across the wire...",
    ),
    "start_lima": (
        "Starting Lima...",
        "Waking the shared guest...",
        "Booting the same disk, not a new one...",
    ),
    "guest_venv": (
        "Installing guest venv...",
        "Putting MCPAegis in the guest...",
        "Warming the Ubuntu toolchain...",
    ),
    "copy_server": (
        "Copying MCP server...",
        "Staging a home-visible copy...",
        "Making Lima a map of your tree...",
    ),
    "static": (
        "Running static...",
        "Reading the code without running it...",
        "Walking tools, schemas, and sinks...",
    ),
    "runtime": (
        "Running runtime...",
        "Watching the server while it works...",
        "eBPF is listening for trouble...",
    ),
    "merge": (
        "Merging reports...",
        "Folding static and runtime into one story...",
        "Lining up the same tools across both halves...",
    ),
    "stop_lima": (
        "Stopping Lima...",
        "Giving RAM back to the Mac...",
        "Parking the guest, keeping the disk...",
    ),
    "report": (
        "writing report...",
        "summarizing findings...",
        "translating jargon into plain English...",
        "lining up severity, then the why...",
        "checking we did not drop a weakness...",
        "polishing the last paragraph...",
        "almost ready to show you the map...",
    ),
}

_STATUS_RULES: tuple[tuple[str, str], ...] = (
    ("Installing Lima", "install_lima"),
    ("brew install lima", "install_lima"),
    ("Creating Lima", "install_lima"),
    ("First start downloads Ubuntu", "download_ubuntu"),
    ("Downloading", "download_ubuntu"),
    ("Starting stopped Lima", "start_lima"),
    ("Ensuring Lima", "start_lima"),
    ("Starting Lima", "start_lima"),
    ("Installing MCPAegis", "guest_venv"),
    ("copying package", "guest_venv"),
    ("Guest venv already", "guest_venv"),
    ("Guest venv", "guest_venv"),
    ("copied MCP server", "copy_server"),
    ("Running static", "static"),
    ("Static analysis", "static"),
    ("guest runtime", "runtime"),
    ("Linux host", "runtime"),
    ("Runtime analysis", "runtime"),
    ("Merging", "merge"),
    ("Stopping Lima", "stop_lima"),
    ("writing report", "report"),
)


def status_stage(line: str) -> str | None:
    """Map a live log line to a status stage key."""
    text = line.strip()
    if not text:
        return None
    lower = text.lower()
    for needle, stage in _STATUS_RULES:
        if needle.lower() in lower:
            return stage
    return None


def status_sentence(line: str) -> str | None:
    """Plain first phrase for a log line, or None."""
    stage = status_stage(line)
    if stage is None:
        return None
    phrases = STATUS_CYCLES.get(stage)
    if not phrases:
        return None
    return phrases[0]


def cycle_phrase(stage: str, index: int) -> tuple[str, int]:
    """Return the phrase at ``index`` and the next index (wraps)."""
    phrases = STATUS_CYCLES.get(stage) or ("...",)
    idx = index % len(phrases)
    return phrases[idx], (idx + 1) % len(phrases)


def phrase_hold(stage: str) -> float:
    return REPORT_CYCLE_S if stage == "report" else STATUS_CYCLE_S


def phrase_due(started: float, now: float, hold: float) -> bool:
    """True when ``hold`` seconds have elapsed since ``started``."""
    return now - started >= hold


def fallback_tui_report(result: RunResult) -> str:
    """Local W5 (title) + explainer + reasoning when the LLM is off or fails."""
    source = result.combined_report or result.dynamic_report or result.static_report
    extra = f"Reports: `{result.output_dir}`"
    parts: list[str] = [REPORT_INTRO, "", SEVERITY_LEGEND.strip(), "", FINDINGS_INTRO, ""]
    if source is None:
        raw = strip_dashes(result.markdown or "_No findings._")
        parts.append(raw)
        if "Reports:" not in raw:
            parts.append("")
            parts.append(extra)
        return strip_dashes("\n".join(parts).strip())
    records = sort_findings(collect_findings(source))
    if not records:
        parts.append("_No findings._")
        parts.append("")
        parts.append(extra)
        return strip_dashes("\n".join(parts).strip())
    for rec in records:
        title = weakness_title(rec.weakness_id)
        parts.append(f"**{rec.weakness_id} ({title})**")
        explainer = WEAKNESS_EXPLAINERS.get(rec.weakness_id, title)
        parts.append(explainer)
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
    "Hi, I am MCPAegis.\n"
    "I analyze local MCP servers for security issues.\n"
    "If you have not set up your .env yet, put these OpenRouter settings in a .env file in the current directory or the repo root:\n"
    "MCPAEGIS_LLM_API_KEY (your OpenRouter API key)\n"
    "MCPAEGIS_LLM_BASE_URL=https://openrouter.ai/api/v1\n"
    "MCPAEGIS_LLM_MODEL (an OpenRouter model id)\n"
    "I have three modes of operation to analyze the MCP server.\n"
    "First is static: I read the code without running it.\n"
    "Second is runtime: I watch the server while it runs.\n"
    "Third is full: I run both.\n"
    "Choose one of these modes of analysis using the arrow keys, then hit enter."
)

LLM_TEXT = (
    "Great choice.\n"
    "Do you want to use an LLM?\n"
    "If you do not, I will fall back to the heuristics defined in my README."
)

PATH_TEXT = (
    "Enter the path to your local MCP server. Relative or absolute both work.\n"
    "Relative paths are from the directory you launched me from. Absolute paths start with / or ~.\n"
    "If the path is already under your home directory I use it as-is.\n"
    "If it is outside home I copy it to ~/mcpaegis-servers/ so Lima can see it. Static still scans the original path.\n"
    "Hit enter to continue."
)

SCRIPT_TEXT = (
    "This is optional. A test script is a runtime.yaml or a text file of tool calls I should send.\n"
    "Leave this blank and hit enter to use auto-args: I fill each tool with placeholder strings.\n"
    "To drive the tools yourself, enter either a relative or an absolute path to a yaml or txt file.\n"
    "Example yaml:\n"
    "- tool_name: run_cmd\n"
    "  arguments:\n"
    "    command: echo hello\n"
    "Hit enter to run."
)

STATUS_CYCLE_S = 2.0
REPORT_CYCLE_S = 20.0
FADE_TICK_S = 0.08
REPORT_TYPE_MS = 0.004
REPORT_TYPE_CHUNK = 8

WIZARD_STEPS: tuple[str, ...] = ("mode", "llm", "path", "script", "run")

SHIELD_ART = """\
 ______________
/      ||      \\
|      ||      |
 \\     ||     /
  \\    ||    /
   \\   ||   /
    \\  ||  /
     \\ || /
      \\||/
       \\/"""

TYPE_CHAR_MS = 0.008
TYPE_LINE_PAUSE = 0.10
TYPE_CHUNK = 2
SCRIPT_TYPE_CHAR_MS = 0.04
SCRIPT_TYPE_LINE_PAUSE = 0.80
SCRIPT_TYPE_CHUNK = 1

FOOTER_START = "enter continue  ·  type quit to quit"
FOOTER_WIZARD = "enter continue  ·  esc back  ·  type quit to quit"
FOOTER_RUN = "type quit to quit"
FOOTER_DONE = "enter new run  ·  type quit to quit"
BRAND = "MCPAegis"


PROGRESS_GAP = "──────────"
PROGRESS_ON = "#2dd4bf"
PROGRESS_OFF = "#6b8f89"


def _progress_col_width() -> int:
    return 1 + len(PROGRESS_GAP)


def progress_line(step: int) -> str:
    """Longer teal step bar. ``step`` is 1-based (1 = mode, 5 = run)."""
    width = _progress_col_width()
    parts: list[str] = []
    for i in range(len(WIZARD_STEPS)):
        on = i < step
        color = PROGRESS_ON if on else PROGRESS_OFF
        mark = "●" if on else "○"
        cell = mark + (PROGRESS_GAP if i < len(WIZARD_STEPS) - 1 else "")
        parts.append(f"[{color}]{cell.ljust(width)}[/]")
    return "".join(parts)


def progress_labels(step: int) -> str:
    """Labels lined up under each dot. Teal for current and completed steps."""
    width = _progress_col_width()
    parts: list[str] = []
    for i, name in enumerate(WIZARD_STEPS):
        color = PROGRESS_ON if i < step else PROGRESS_OFF
        parts.append(f"[{color}]{name.ljust(width)}[/]")
    return "".join(parts)


async def type_into(
    node: Static,
    text: str,
    *,
    char_ms: float | None = None,
    line_pause: float | None = None,
    chunk: int | None = None,
) -> None:
    char_ms = TYPE_CHAR_MS if char_ms is None else char_ms
    line_pause = TYPE_LINE_PAUSE if line_pause is None else line_pause
    chunk = TYPE_CHUNK if chunk is None else chunk
    shown: list[str] = []
    for line in text.split("\n"):
        buf = ""
        i = 0
        while i < len(line):
            buf += line[i : i + chunk]
            i += chunk
            node.update("\n".join([*shown, buf]))
            await asyncio.sleep(char_ms)
        shown.append(line)
        node.update("\n".join(shown))
        await asyncio.sleep(line_pause)


class _Progress(Vertical):
    def __init__(self, step: int) -> None:
        super().__init__(id="progress-wrap")
        self._step = step

    def compose(self) -> ComposeResult:
        yield Static(progress_line(self._step), id="progress", markup=True)
        yield Static(progress_labels(self._step), id="progress-labels", markup=True)


class _Chrome(Horizontal):
    def __init__(self, step: int = 1) -> None:
        super().__init__(classes="chrome")
        self._step = step

    def compose(self) -> ComposeResult:
        yield Static(BRAND, classes="brand")
        yield _Progress(self._step)


class ModeScreen(Screen[None]):
    BINDINGS = [
        Binding("enter", "next", "continue", show=True, priority=True),
        Binding("escape", "app.quit", "quit", show=False),
        Binding("up", "mode_prev", "prev", show=False),
        Binding("down", "mode_next", "next", show=False),
        Binding("left", "mode_prev", "prev", show=False),
        Binding("right", "mode_next", "next", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome(1)
        with Vertical(id="body"):
            yield Static(SHIELD_ART, id="shield")
            yield Static("", id="welcome", classes="welcome")
            with Vertical(id="list"):
                for key, label in MODES:
                    item = Static(bullet(False, label), id=f"mode-{key}", classes="choice")
                    item.can_focus = False
                    yield item
        yield Static(FOOTER_START, id="footer")

    def on_mount(self) -> None:
        self._paint()
        app = self.app
        assert isinstance(app, WizardApp)
        if app.intro_played:
            self.query_one("#welcome", Static).update(WELCOME_TEXT)
            return
        self.run_worker(self._type_intro(), exclusive=True, name="intro")

    async def _type_intro(self) -> None:
        await type_into(self.query_one("#welcome", Static), WELCOME_TEXT)
        app = self.app
        assert isinstance(app, WizardApp)
        app.intro_played = True

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
        Binding("up", "toggle", "toggle", show=False),
        Binding("down", "toggle", "toggle", show=False),
        Binding("left", "toggle", "toggle", show=False),
        Binding("right", "toggle", "toggle", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome(2)
        with Vertical(id="body"):
            yield Static("", id="welcome", classes="welcome")
            with Vertical(id="list"):
                yes = Static(bullet(False, "yes"), id="llm-on", classes="choice")
                no = Static(bullet(False, "no"), id="llm-off", classes="choice")
                yes.can_focus = False
                no.can_focus = False
                yield yes
                yield no
        yield Static(FOOTER_WIZARD, id="footer")

    def on_mount(self) -> None:
        self._paint()
        app = self.app
        assert isinstance(app, WizardApp)
        if app.llm_intro_played:
            self.query_one("#welcome", Static).update(LLM_TEXT)
            return
        self.run_worker(self._type_intro(), exclusive=True, name="llm-intro")

    async def _type_intro(self) -> None:
        await type_into(self.query_one("#welcome", Static), LLM_TEXT)
        app = self.app
        assert isinstance(app, WizardApp)
        app.llm_intro_played = True

    def _paint(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        off_node = self.query_one("#llm-off", Static)
        on_node = self.query_one("#llm-on", Static)
        off_node.update(bullet(not app.llm_on, "no"))
        on_node.update(bullet(app.llm_on, "yes"))
        off_node.set_class(not app.llm_on, "-on")
        on_node.set_class(app.llm_on, "-on")

    def on_click(self, event) -> None:
        wid = getattr(event.widget, "id", None) or ""
        if wid == "llm-on":
            self._set(True)
        elif wid == "llm-off":
            self._set(False)

    def action_toggle(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        self._set(not app.llm_on)

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
        yield _Chrome(3)
        with Vertical(id="body"):
            yield Static("", id="welcome", classes="welcome")
            yield Input(placeholder="/Users/you/src/my-mcp-server", id="field")
            yield Static("", id="error")
        yield Static(FOOTER_WIZARD, id="footer")

    def on_mount(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        field = self.query_one("#field", Input)
        if app.server_path:
            field.value = app.server_path
        field.focus()
        if app.path_intro_played:
            self.query_one("#welcome", Static).update(PATH_TEXT)
            return
        self.run_worker(self._type_intro(), exclusive=True, name="path-intro")

    async def _type_intro(self) -> None:
        await type_into(self.query_one("#welcome", Static), PATH_TEXT)
        app = self.app
        assert isinstance(app, WizardApp)
        app.path_intro_played = True

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._advance(event.value)

    def action_back(self) -> None:
        self.app.pop_screen()

    def _advance(self, raw: str) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        path = raw.strip()
        err = self.query_one("#error", Static)
        if not path:
            err.update("enter a path")
            return
        resolved = resolve_user_path(path)
        problem = looks_like_mcp_server(resolved)
        if problem:
            err.update(problem)
            return
        if resolved.is_file():
            resolved = resolved.parent
        err.update("")
        app.server_path = str(resolved)
        app.go_script()


class ScriptScreen(Screen[None]):
    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield _Chrome(4)
        with Vertical(id="body"):
            yield Static("", id="welcome", classes="welcome")
            yield Input(placeholder="runtime.yaml", id="field")
            yield Static("", id="error")
        yield Static("enter run  ·  esc back  ·  type quit to quit", id="footer")

    def on_mount(self) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        field = self.query_one("#field", Input)
        if app.test_script:
            field.value = app.test_script
        field.focus()
        if app.script_intro_played:
            self.query_one("#welcome", Static).update(SCRIPT_TEXT)
            return
        self.run_worker(self._type_intro(), exclusive=True, name="script-intro")

    async def _type_intro(self) -> None:
        await type_into(
            self.query_one("#welcome", Static),
            SCRIPT_TEXT,
            char_ms=SCRIPT_TYPE_CHAR_MS,
            line_pause=SCRIPT_TYPE_LINE_PAUSE,
            chunk=SCRIPT_TYPE_CHUNK,
        )
        app = self.app
        assert isinstance(app, WizardApp)
        app.script_intro_played = True

    def on_input_submitted(self, event: Input.Submitted) -> None:
        app = self.app
        assert isinstance(app, WizardApp)
        raw = event.value.strip()
        problem = looks_like_test_script(raw, app.server_path)
        err = self.query_one("#error", Static)
        if problem:
            err.update(problem)
            return
        err.update("")
        app.test_script = raw
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
        self._reporting = False
        self._stage = "starting"
        self._phrase_index = 0
        self._phrase_started = 0.0
        self._cycling = True
        self._cycle_timer = None
        self._report_shown = ""
        self._report_target = ""
        self._report_done = False
        self._error = False

    def compose(self) -> ComposeResult:
        app = self.app
        assert isinstance(app, WizardApp)
        yield _Chrome(5)
        yield Static(STATUS_CYCLES["starting"][0], id="status-box")
        with Vertical(id="stage"):
            yield Log(id="log", highlight=False, auto_scroll=True)
            with VerticalScroll(id="findings-body"):
                yield Markdown("", id="findings-md")
        yield Static(FOOTER_RUN, id="footer")

    def on_mount(self) -> None:
        self.query_one("#findings-body").display = False
        self._phrase_index = 1 % max(len(STATUS_CYCLES.get(self._stage, ("...",))), 1)
        self._phrase_started = time.monotonic()
        self._cycle_timer = self.set_interval(0.25, self._cycle)
        self.run_worker(self._fade_status(), exclusive=True, name="status-fade")
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

    async def _fade_status(self) -> None:
        """Breathing opacity only. Never changes the phrase or its 20s clock."""
        box = self.query_one("#status-box")
        opacity = 1.0
        direction = -1.0
        while not self._ready:
            if self._cycling and box.display:
                opacity += direction * 0.035
                if opacity <= 0.4:
                    opacity = 0.4
                    direction = 1.0
                elif opacity >= 1.0:
                    opacity = 1.0
                    direction = -1.0
                box.styles.text_opacity = opacity
            await asyncio.sleep(FADE_TICK_S)

    def _cycle(self) -> None:
        if self._ready or not self._cycling:
            return
        box = self.query_one("#status-box", Static)
        if not box.display:
            return
        hold = phrase_hold(self._stage)
        if not phrase_due(self._phrase_started, time.monotonic(), hold):
            return
        phrase, self._phrase_index = cycle_phrase(self._stage, self._phrase_index)
        box.update(phrase)
        self._phrase_started = time.monotonic()

    def set_stage(self, stage: str) -> None:
        if stage == self._stage:
            return
        self._stage = stage
        self._phrase_index = 0
        self._cycling = True
        box = self.query_one("#status-box", Static)
        if box.display:
            box.update(STATUS_CYCLES.get(stage, ("...",))[0])
            self._phrase_index = 1 % max(len(STATUS_CYCLES.get(stage, ("...",))), 1)
        self._phrase_started = time.monotonic()

    def append_log(self, line: str) -> None:
        self.query_one("#log", Log).write_line(line)
        mapped = status_stage(line)
        if mapped:
            self.set_stage(mapped)

    def hide_status(self) -> None:
        self._cycling = False
        box = self.query_one("#status-box")
        box.display = False
        box.styles.text_opacity = 1.0

    def open_report(self, *, error: bool) -> None:
        self._reporting = True
        self._error = error
        status = self.query_one("#status-box", Static)
        status.display = True
        if error:
            self._cycling = False
            status.styles.text_opacity = 1.0
            status.update("error")
            self.query_one("#log").display = True
        else:
            self.query_one("#log").display = False
            self.set_stage("report")
        body = self.query_one("#findings-body")
        body.display = True
        self.query_one("#findings-md", Markdown).update("")
        self.query_one("#footer", Static).update(FOOTER_RUN)

    def set_report(self, markdown: str) -> None:
        body = self.query_one("#findings-body")
        if not body.display:
            self.open_report(error=self._error)
        self._report_target = markdown
        if self._error:
            self._cycling = False
            status = self.query_one("#status-box", Static)
            status.display = True
            status.styles.text_opacity = 1.0
            status.update("error")
            self.query_one("#findings-md", Markdown).update(markdown)
            self.call_after_refresh(lambda: body.scroll_end(animate=False))
            return
        if markdown.strip():
            self.hide_status()
        self.run_worker(self._type_report(), exclusive=True, name="report-type")

    async def _type_report(self) -> None:
        md = self.query_one("#findings-md", Markdown)
        body = self.query_one("#findings-body")
        while True:
            target = self._report_target
            if self._report_shown == target:
                if self._report_done:
                    break
                await asyncio.sleep(0.04)
                continue
            if target.startswith(self._report_shown):
                self._report_shown = target[: len(self._report_shown) + REPORT_TYPE_CHUNK]
            else:
                self._report_shown = target[: max(REPORT_TYPE_CHUNK, min(len(target), len(self._report_shown) + REPORT_TYPE_CHUNK))]
            md.update(self._report_shown)
            body.scroll_end(animate=False)
            await asyncio.sleep(REPORT_TYPE_MS)
        self.query_one("#footer", Static).update(FOOTER_DONE)
        self._ready = True

    def finish_report(self, markdown: str, *, error: bool) -> None:
        self._error = error
        self._report_done = True
        self.set_report(markdown)
        if error:
            self._cycling = False
            status = self.query_one("#status-box", Static)
            status.display = True
            status.styles.text_opacity = 1.0
            status.update("error")
            self.query_one("#log").display = True
            self.query_one("#footer", Static).update(FOOTER_DONE)
            self._ready = True
        else:
            self.hide_status()

    def action_again(self) -> None:
        if not self._ready:
            return
        app = self.app
        assert isinstance(app, WizardApp)
        app.reset_wizard()


class WizardApp(App[None]):
    CSS = CSS
    TITLE = "MCPAegis"
    BINDINGS = []

    def __init__(self) -> None:
        super().__init__()
        self.mode: Mode = "full"
        self.llm_on = default_llm_on()
        self.server_path = ""
        self.test_script = ""
        self.intro_played = False
        self.llm_intro_played = False
        self.path_intro_played = False
        self.script_intro_played = False
        self._quit_buf = ""
        self._cancel = threading.Event()
        self._busy = False

    def on_mount(self) -> None:
        self.push_screen(ModeScreen())

    def action_quit(self) -> None:
        self._cancel.set()
        self.exit()

    def on_key(self, event: Key) -> None:
        focused = self.focused
        if isinstance(focused, Input):
            self._quit_buf = ""
            return
        char = event.character or ""
        if len(char) != 1 or not char.isalpha():
            self._quit_buf = ""
            return
        self._quit_buf = (self._quit_buf + char.lower())[-4:]
        if self._quit_buf == "quit":
            event.prevent_default()
            event.stop()
            self.action_quit()

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
        session: AuditSession | None = None

        def on_report(text: str) -> None:
            nonlocal last_ui
            extra = ""
            if session is not None and "Reports:" not in text:
                extra = f"\n\nReports: `{session.output_dir}`"
            now = time.monotonic()
            if now - last_ui < 0.12:
                return
            last_ui = now
            self.call_from_thread(self._set_report, text + extra)

        try:
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
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            result = RunResult(mode=self.mode, server_path=Path(path), output_dir=Path("."), error=message)
            self.call_from_thread(self._append_log, f"error {message}")
            self.call_from_thread(self._open_report, True)
            body = f"**error**\n\n{message}"
            self.call_from_thread(self._set_report, body)
            self.call_from_thread(self._finish, result, body)
            return
        extra = f"\n\nReports: `{result.output_dir}`"
        if result.error:
            self.call_from_thread(self._append_log, f"error {result.error}")
            self.call_from_thread(self._open_report, True)
            body = f"**error**\n\n{result.error}"
            self.call_from_thread(self._set_report, body)
        elif llm.enabled:
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
