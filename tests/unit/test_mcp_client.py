"""Handshake must fail fast when the child never speaks MCP."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from mcpaegis.core.mcp_client import McpClientError, handshake


def test_handshake_times_out_on_silent_server(tmp_path: Path):
    script = tmp_path / "hang.py"
    script.write_text("import time\nwhile True:\n    time.sleep(30)\n", encoding="utf-8")
    start = time.monotonic()
    with pytest.raises(McpClientError):
        handshake([sys.executable, str(script)], cwd=tmp_path, timeout=1.0)
    assert time.monotonic() - start < 5.0


def test_handshake_with_eval_format_fixture():
    pytest.importorskip("mcp.server.fastmcp")
    root = Path(__file__).resolve().parents[1] / "fixtures" / "eval_format"
    start = time.monotonic()
    result = handshake([sys.executable, str(root / "server.py")], cwd=root, timeout=8.0)
    assert any(t.get("name") == "get_qotd" for t in result.tools)
    assert time.monotonic() - start < 8.0
