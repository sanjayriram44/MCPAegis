from pathlib import Path

from mcpaegis.core.models import SourceLocation, ToolMetadata
from mcpaegis.core.taxonomy import Capability, SinkType
from mcpaegis.static.taint.call_graph import build_python_call_graph, function_at, reverse_paths
from mcpaegis.static.taint.semgrep_runner import (
    _handler_taint_yaml,
    _merge_facts,
    _semgrep_json,
    _sink_snippet,
    max_confidence_by_tool_capability,
)
from tests.unit.helpers import sink


def test_merge_facts_direct_wins_on_same_tool_and_line():
    prox = sink(id="p", tool_name="run", file="a.py", line=10, confidence="proximate")
    direct = sink(id="d", tool_name="run", file="a.py", line=10, confidence="direct")
    merged = _merge_facts([prox], [direct])
    assert len(merged) == 1
    assert merged[0].confidence == "direct"
    assert merged[0].id == "d"


def test_merge_facts_keeps_distinct_tools_on_shared_sink():
    prox = sink(id="p", tool_name="export", file="a.py", line=10, confidence="proximate")
    direct = sink(id="d", tool_name="search", file="a.py", line=10, confidence="direct")
    merged = _merge_facts([prox], [direct])
    assert len(merged) == 2
    by_tool = {f.tool_name: f.confidence for f in merged}
    assert by_tool == {"export": "proximate", "search": "direct"}


def test_merge_facts_keeps_distinct_lines():
    a = sink(id="a", file="a.py", line=10, confidence="proximate")
    b = sink(id="b", file="a.py", line=11, confidence="direct")
    merged = _merge_facts([a], [b])
    assert {f.id for f in merged} == {"a", "b"}


def test_max_confidence_prefers_direct():
    mapping = max_confidence_by_tool_capability(
        [
            sink(tool_name="run", sink_type=SinkType.SHELL_EXEC, confidence="proximate"),
            sink(id="s2", tool_name="run", sink_type=SinkType.SHELL_EXEC, line=11, confidence="direct"),
        ]
    )
    assert mapping[("run", Capability.SHELL_EXEC)] == "direct"


def test_handler_taint_yaml_scopes_sources_to_handler_file():
    tools = [
        ToolMetadata(
            name="search_docs",
            description="",
            input_schema={},
            source_location=SourceLocation(
                file="/tmp/server/handlers.py",
                line=10,
                function_name="search",
            ),
        )
    ]
    yaml_text = _handler_taint_yaml(tools, language="python")
    assert yaml_text is not None
    assert "def search(...):" in yaml_text
    assert "paths:" in yaml_text
    assert "/tmp/server/handlers.py" in yaml_text
    assert "mode: taint" in yaml_text
    assert "sink_type: shell_exec" in yaml_text
    assert "pattern-sanitizers:" in yaml_text
    assert "shlex.quote(...)" in yaml_text
    assert "open($PATH, ...)" in yaml_text


def test_name_collision_fixture_sources_only_handler_file():
    root = Path(__file__).resolve().parents[1] / "fixtures" / "name_collision"
    tools = [
        ToolMetadata(
            name="search",
            description="",
            input_schema={},
            source_location=SourceLocation(
                file=str(root / "tool.py"),
                line=16,
                function_name="search",
            ),
        )
    ]
    yaml_text = _handler_taint_yaml(tools, language="python")
    assert yaml_text is not None
    assert "tool.py" in yaml_text
    assert "other.py" not in yaml_text


def test_same_function_name_in_other_file_is_not_a_source(tmp_path: Path):
    handler = tmp_path / "tool.py"
    helper = tmp_path / "other.py"
    handler.write_text(
        "def search(query: str) -> str:\n    return query\n",
        encoding="utf-8",
    )
    helper.write_text(
        "def search(query: str) -> str:\n    import os\n    os.system(query)\n    return query\n",
        encoding="utf-8",
    )
    tools = [
        ToolMetadata(
            name="search",
            description="",
            input_schema={},
            source_location=SourceLocation(file=str(handler), line=1, function_name="search"),
        )
    ]
    yaml_text = _handler_taint_yaml(tools, language="python")
    assert yaml_text is not None
    assert str(handler) in yaml_text
    assert str(helper) not in yaml_text


def test_shared_helper_attributes_to_every_reaching_tool(tmp_path: Path):
    src = tmp_path / "server.py"
    src.write_text(
        "import subprocess\n"
        "CLEANUP = 'rm -rf /tmp/x'\n"
        "\n"
        "def _shared():\n"
        "    subprocess.run(CLEANUP, shell=True)\n"
        "\n"
        "def search_docs(query: str) -> str:\n"
        "    _shared()\n"
        "    return query\n"
        "\n"
        "def export_docs(name: str) -> str:\n"
        "    _shared()\n"
        "    return name\n",
        encoding="utf-8",
    )
    graph = build_python_call_graph(tmp_path)
    helper = function_at(graph, src, 5)
    assert helper is not None
    entrypoints = {
        f"{src.resolve()}:search_docs": "search_docs",
        f"{src.resolve()}:export_docs": "export_docs",
    }
    hits = reverse_paths(graph, helper, entrypoints, max_hops=10)
    tools = {name for name, _path in hits}
    assert tools == {"search_docs", "export_docs"}


def test_sink_snippet_uses_source_line_not_semgrep_window(tmp_path: Path):
    src = tmp_path / "server.py"
    src.write_text(
        "def run(command: str) -> str:\n"
        "    # requires login\n"
        "    return eval(command)\n",
        encoding="utf-8",
    )
    snippet = _sink_snippet(src, 3, {"lines": "requires login\n    return eval(command)"})
    assert snippet == "return eval(command)"
    assert "requires login" not in snippet


def test_semgrep_cmd_uses_python_module_when_path_empty(monkeypatch, tmp_path):
    from mcpaegis.static.taint import semgrep_runner as runner

    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    monkeypatch.setattr(runner, "_python_module_works", lambda python, module: python.endswith("python") and module == "semgrep")
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("PATH", "")
    assert runner._semgrep_cmd() == [str(tmp_path / "python"), "-m", "semgrep"]


def test_semgrep_json_scans_untracked_test_fixtures():
    import shutil

    if shutil.which("semgrep") is None:
        return
    root = Path(__file__).resolve().parents[1] / "fixtures" / "eval_format"
    rules = Path(__file__).resolve().parents[2] / "mcpaegis" / "static" / "taint" / "rules" / "python.yaml"
    results = _semgrep_json([str(rules)], root)
    assert results, "Semgrep should not skip tests/fixtures via default .semgrepignore"
