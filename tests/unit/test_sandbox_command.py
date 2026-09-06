from pathlib import Path

from mcpaegis.dynamic.sandbox.process_provider import resolve_launch_command
from mcpaegis.static.discovery import detect_entrypoint


def test_resolve_uses_current_interpreter_for_python(monkeypatch):
    monkeypatch.setattr(
        "mcpaegis.dynamic.sandbox.process_provider.sys.executable",
        "/home/user/mcpaegis-venv/bin/python3",
    )
    root = Path("/Users/sanjaysriram/Documents/MCPAegis/tests/fixtures/command_injection")
    cmd = resolve_launch_command(f"python {root / 'server.py'}", "python", workspace=root)
    assert cmd[0] == "/home/user/mcpaegis-venv/bin/python3"
    assert cmd[1] == str(root / "server.py")


def test_resolve_leaves_module_launches_alone(monkeypatch):
    monkeypatch.setattr(
        "mcpaegis.dynamic.sandbox.process_provider.sys.executable",
        "/usr/bin/python3",
    )
    root = Path("/tmp/mcp-server")
    cmd = resolve_launch_command("python3 -m pkg.server", "python", workspace=root)
    assert cmd == ["/usr/bin/python3", "-m", "pkg.server"]


def test_fixture_entrypoint_is_an_absolute_python_path():
    root = Path(__file__).resolve().parents[1] / "fixtures" / "command_injection"
    entrypoint, cmd = detect_entrypoint(root, "python")
    assert cmd[0] in {"python", "python3"}
    assert Path(cmd[-1]).is_absolute()
    assert Path(cmd[-1]).name == "server.py"
    assert "server.py" in entrypoint
