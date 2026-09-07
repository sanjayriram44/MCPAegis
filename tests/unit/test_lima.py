"""Lima doctor parsing, path sharing, and guest argv — no live VM."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpaegis.lima.doctor import DoctorReport, LimaInstance, instance_named, parse_limactl_list
from mcpaegis.lima.errors import PathNotSharedError
from mcpaegis.core.session import LLMConfig
from mcpaegis.lima.guest import llm_env_from_config, llm_env_from_os, redact_argv, runtime_argv
from mcpaegis.lima.orchestrate import prepare_paths
from mcpaegis.lima.paths import is_under_home, lima_yaml_path, require_under_home, stage_under_home


def test_parse_limactl_list_json_array():
    raw = """
    [{"name": "mcpaegis", "status": "Running", "vmType": "vz", "arch": "aarch64"}]
    """
    items = parse_limactl_list(raw)
    assert len(items) == 1
    assert items[0].name == "mcpaegis"
    assert items[0].running
    assert items[0].vm_type == "vz"
    assert items[0].arch == "aarch64"


def test_parse_limactl_list_jsonl():
    raw = (
        '{"name":"default","status":"Stopped","vmType":"vz","arch":"aarch64"}\n'
        '{"name":"mcpaegis","status":"Running","vmType":"vz","arch":"aarch64"}\n'
    )
    items = parse_limactl_list(raw)
    found = instance_named(items)
    assert found is not None
    assert found.running


def test_parse_limactl_list_table():
    raw = """NAME       STATUS    SSH                VMTYPE    ARCH       CPUS    MEMORY    DISK     DIR
mcpaegis   Running   127.0.0.1:49999    vz        aarch64    4       8GiB      40GiB    ~/.lima/mcpaegis
"""
    items = parse_limactl_list(raw)
    assert items[0].name == "mcpaegis"
    assert items[0].status == "Running"
    assert items[0].vm_type == "vz"


def test_doctor_header_missing_lima():
    report = DoctorReport(
        system="Darwin",
        machine="arm64",
        apple_silicon=True,
        limactl=None,
        instance=None,
    )
    assert "Lima: missing" in report.header_line()


def test_doctor_header_running_venv():
    report = DoctorReport(
        system="Darwin",
        machine="arm64",
        apple_silicon=True,
        limactl="/opt/homebrew/bin/limactl",
        instance=LimaInstance(name="mcpaegis", status="Running", vm_type="vz"),
        venv_ok=True,
        bcc_ok=True,
    )
    line = report.header_line()
    assert "Lima: running" in line
    assert "venv: ok" in line
    assert "BPF: ok" in line


def test_require_under_home_ok(tmp_path: Path):
    home = tmp_path / "Users" / "me"
    target = home / "src" / "server"
    target.mkdir(parents=True)
    resolved = require_under_home(target, home=home, what="MCP server path")
    assert resolved == target.resolve()
    assert is_under_home(target, home)


def test_require_under_home_rejects_outside(tmp_path: Path):
    home = tmp_path / "Users" / "me"
    home.mkdir(parents=True)
    outside = tmp_path / "opt" / "server"
    outside.mkdir(parents=True)
    with pytest.raises(PathNotSharedError, match="outside"):
        require_under_home(outside, home=home, what="MCP server path")


def test_stage_under_home_copies_outside_and_skips_venv(tmp_path: Path):
    home = tmp_path / "Users" / "me"
    home.mkdir(parents=True)
    src = tmp_path / "opt" / "myserver"
    src.mkdir(parents=True)
    (src / "server.py").write_text("print(1)\n", encoding="utf-8")
    (src / ".venv").mkdir()
    (src / ".venv" / "x").write_text("skip\n", encoding="utf-8")
    (src / "node_modules").mkdir()
    dest = stage_under_home(src, home=home)
    assert dest == (home / "mcpaegis-servers" / "myserver").resolve()
    assert (dest / "server.py").is_file()
    assert not (dest / ".venv").exists()
    assert not (dest / "node_modules").exists()


def test_stage_under_home_keeps_path_already_under_home(tmp_path: Path):
    home = tmp_path / "Users" / "me"
    server = home / "src" / "myserver"
    server.mkdir(parents=True)
    assert stage_under_home(server, home=home) == server.resolve()


def test_prepare_paths_runtime_darwin_copies_outside(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("mcpaegis.lima.orchestrate.platform.system", lambda: "Darwin")
    home = tmp_path / "Users" / "me"
    home.mkdir(parents=True)
    outside = tmp_path / "elsewhere" / "server"
    outside.mkdir(parents=True)
    (outside / "server.py").write_text("print(1)\n", encoding="utf-8")
    prepared = prepare_paths(outside, None, None, mode="runtime", home=home)
    assert prepared.copied
    assert prepared.original == outside.resolve()
    assert prepared.runtime == (home / "mcpaegis-servers" / "server").resolve()
    assert prepared.output == (home / "mcpaegis-out" / "server").resolve()
    assert (prepared.runtime / "server.py").is_file()


def test_prepare_paths_runtime_darwin_accepts_home(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("mcpaegis.lima.orchestrate.platform.system", lambda: "Darwin")
    home = tmp_path / "Users" / "me"
    server = home / "src" / "myserver"
    server.mkdir(parents=True)
    out = home / "mcpaegis-out" / "myserver"
    script = home / "src" / "myserver" / "runtime.yaml"
    script.write_text("- tool_name: echo\n  arguments: {}\n", encoding="utf-8")
    prepared = prepare_paths(server, out, script, mode="full", home=home)
    assert not prepared.copied
    assert prepared.original == server.resolve()
    assert prepared.runtime == server.resolve()
    assert prepared.output == out.resolve()
    assert prepared.script == script.resolve()
    assert prepared.output.is_dir()


def test_prepare_paths_copies_outside_script(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("mcpaegis.lima.orchestrate.platform.system", lambda: "Darwin")
    home = tmp_path / "Users" / "me"
    server = home / "src" / "myserver"
    server.mkdir(parents=True)
    script = tmp_path / "scratch" / "runtime.yaml"
    script.parent.mkdir(parents=True)
    script.write_text("- tool_name: echo\n  arguments: {}\n", encoding="utf-8")
    prepared = prepare_paths(server, None, script, mode="runtime", home=home)
    assert prepared.script == (home / "mcpaegis-servers" / "_scripts" / "runtime.yaml").resolve()
    assert prepared.script.is_file()
    assert not prepared.copied


def test_runtime_argv_forwards_llm_env():
    argv = runtime_argv(
        server_path="/Users/me/src/server",
        output_dir="/Users/me/mcpaegis-out/server",
        test_script="/Users/me/src/server/runtime.yaml",
        timeout=30,
        extra_env={"MCPAEGIS_LLM_API_KEY": "sk-secret", "MCPAEGIS_LLM_MODEL": "gpt-4o-mini"},
        mcpaegis_bin="/home/me.linux/mcpaegis-venv/bin/mcpaegis",
    )
    assert argv[:2] == ["env", "MCPAEGIS_LLM_API_KEY=sk-secret"]
    assert "MCPAEGIS_LLM_MODEL=gpt-4o-mini" in argv
    sudo_at = argv.index("sudo")
    assert argv[sudo_at : sudo_at + 4] == [
        "sudo",
        "-n",
        "-E",
        "/home/me.linux/mcpaegis-venv/bin/mcpaegis",
    ]
    assert "runtime" in argv
    assert "--test-script" in argv
    preview = redact_argv(argv)
    assert "MCPAEGIS_LLM_API_KEY=***" in preview
    assert "sk-secret" not in " ".join(preview)


def test_llm_env_from_os_filters(monkeypatch):
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-a")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-b")
    monkeypatch.delenv("MCPAEGIS_LLM_MODEL", raising=False)
    env = llm_env_from_os()
    assert env["MCPAEGIS_LLM_API_KEY"] == "sk-a"
    assert env["OPENAI_API_KEY"] == "sk-b"
    assert "MCPAEGIS_LLM_MODEL" not in env


def test_llm_env_from_config_off_skips_keys():
    env = llm_env_from_config(LLMConfig(api_key=None, base_url="https://example", model="gpt-4o-mini"))
    assert env == {}


def test_llm_env_from_config_forwards_session_model():
    env = llm_env_from_config(
        LLMConfig(api_key="sk-a", base_url="https://openrouter.ai/api/v1", model="qwen/qwen3.8-27b")
    )
    assert env == {
        "MCPAEGIS_LLM_API_KEY": "sk-a",
        "MCPAEGIS_LLM_BASE_URL": "https://openrouter.ai/api/v1",
        "MCPAEGIS_LLM_MODEL": "qwen/qwen3.8-27b",
    }


def test_stop_instance_uses_yes_flag(monkeypatch):
    from mcpaegis.lima import vm as vm_mod
    from mcpaegis.lima.doctor import LimaInstance

    captured: list[list[str]] = []

    monkeypatch.setattr(
        vm_mod,
        "list_instances",
        lambda _b: [LimaInstance(name="mcpaegis", status="Running", vm_type="vz", arch="aarch64")],
    )

    def fake_stream(argv, **_kwargs):
        captured.append(list(argv))
        return 0

    monkeypatch.setattr(vm_mod, "run_streaming", fake_stream)
    vm_mod.stop_instance(limactl="/opt/homebrew/bin/limactl")
    assert captured
    assert captured[0][:4] == ["/opt/homebrew/bin/limactl", "stop", "-y", "mcpaegis"]


def test_ensure_instance_uses_yes_flag(monkeypatch, tmp_path: Path):
    from mcpaegis.lima import vm as vm_mod
    from mcpaegis.lima.doctor import LimaInstance

    yaml = tmp_path / "lima.yaml"
    yaml.write_text("vmType: vz\n", encoding="utf-8")
    captured: list[list[str]] = []
    calls = {"n": 0}

    def fake_list(_b):
        calls["n"] += 1
        if calls["n"] == 1:
            return []
        return [LimaInstance(name="mcpaegis", status="Running", vm_type="vz", arch="aarch64")]

    monkeypatch.setattr(vm_mod, "list_instances", fake_list)
    monkeypatch.setattr(vm_mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(vm_mod.platform, "machine", lambda: "arm64")

    def fake_stream(argv, **_kwargs):
        captured.append(list(argv))
        return 0

    monkeypatch.setattr(vm_mod, "run_streaming", fake_stream)
    inst = vm_mod.ensure_instance(limactl="/opt/homebrew/bin/limactl", yaml_path=yaml)
    assert inst.running
    assert captured
    assert "-y" in captured[0]
    assert "--name=mcpaegis" in captured[0]


def test_run_streaming_emits_cr_progress(tmp_path: Path):
    import sys

    from mcpaegis.lima.vm import run_streaming

    script = tmp_path / "prog.py"
    script.write_text(
        "import sys, time\n"
        "sys.stdout.write('Downloading 10%\\r')\n"
        "sys.stdout.flush()\n"
        "sys.stdout.write('Downloading 100%\\r\\n')\n"
        "sys.stdout.flush()\n"
        "print('done')\n",
        encoding="utf-8",
    )
    lines: list[str] = []
    code = run_streaming([sys.executable, str(script)], log=lines.append)
    assert code == 0
    joined = "\n".join(lines)
    assert "Downloading" in joined
    assert "done" in joined


def test_split_stream_treats_cr_as_line():
    from mcpaegis.lima.stream import split_stream

    lines, rest = split_stream(b"Downloading 10%\rDownloading 50%\rDownloading 100%\nDone\npartial")
    assert "Downloading 10%" in lines
    assert "Downloading 50%" in lines
    assert "Downloading 100%" in lines
    assert "Done" in lines
    assert rest == b"partial"


def test_resolve_test_script_relative_next_to_server(tmp_path: Path):
    from mcpaegis.lima.paths import resolve_test_script

    server = tmp_path / "srv"
    server.mkdir()
    yaml = server / "runtime.yaml"
    yaml.write_text("- tool_name: x\n  arguments: {}\n", encoding="utf-8")
    got = resolve_test_script(server, "runtime.yaml")
    assert got == yaml.resolve()


def test_resolve_test_script_placeholder_is_none(tmp_path: Path):
    from mcpaegis.lima.paths import resolve_test_script

    server = tmp_path / "srv"
    server.mkdir()
    assert resolve_test_script(server, None) is None
    assert resolve_test_script(server, "") is None
    assert resolve_test_script(server, "runtime.yaml  — optional") is None


def test_prepare_paths_relative_script_darwin(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("mcpaegis.lima.orchestrate.platform.system", lambda: "Darwin")
    home = tmp_path / "Users" / "me"
    server = home / "src" / "myserver"
    server.mkdir(parents=True)
    (server / "runtime.yaml").write_text("- tool_name: echo\n  arguments: {}\n", encoding="utf-8")
    out = home / "mcpaegis-out" / "myserver"
    prepared = prepare_paths(server, out, "runtime.yaml", mode="full", home=home)
    assert prepared.script == (server / "runtime.yaml").resolve()


def test_lima_yaml_is_packaged():
    path = lima_yaml_path()
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "vmType: vz" in text
    assert "aarch64" in text


def test_bare_cli_without_tty_does_not_launch_tui(monkeypatch):
    from typer.testing import CliRunner

    from mcpaegis.cli import app

    monkeypatch.setattr("mcpaegis.cli.sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("mcpaegis.cli.sys.stdout.isatty", lambda: False)
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 1
    assert "mcpaegis static|runtime|full" in (result.output or result.stdout or "")


def test_cli_static_help_still_works():
    from typer.testing import CliRunner

    from mcpaegis.cli import app

    result = CliRunner().invoke(app, ["static", "--help"])
    assert result.exit_code == 0
    assert "local MCP server" in result.output
