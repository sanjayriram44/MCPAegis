"""Fixture MCP server: naive path join + unsandboxed code exec (W6 + W5).

Lab analogue: Appsecco ``vulnerable-mcp-server-filesystem-workspace-actions``.
That server required a workspace argv and would refuse to start without it.
This stub uses a dummy prefix so stdio handshake always works.

Bugs kept in source:
- ``os.path.join(WORKSPACE, path)`` then ``open`` / write (no realpath / prefix check)
- ``execute_code`` → ``eval(code)``

Do not call the tools during a scan; discovery only lists them.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None

# Dummy prefix — not created at import. Lab required this as argv.
WORKSPACE = "/tmp/mcpaegis-workspace-fixture"


def _build():
    mcp = FastMCP("workspace-actions")

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a file relative to the workspace root.

        Joins ``path`` onto the workspace with ``os.path.join`` and opens it.
        There is no ``realpath`` check, so ``../`` escapes the prefix.
        """
        # VULNERABILITY: naive join, then open of caller-controlled path.
        full = os.path.join(WORKSPACE, path)
        with open(full, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Write ``content`` to a workspace-relative path.

        Same naive join as ``read_file``. Overwrites without confirmation.
        """
        full = os.path.join(WORKSPACE, path)
        Path(full).write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes"

    @mcp.tool()
    def execute_code(code: str) -> str:
        """Evaluate a Python expression in the server process.

        Advertised as a workspace helper (snippets, calculators). No sandbox,
        no timeout, no AST allowlist.
        """
        # VULNERABILITY: user-controlled code is eval'd.
        return str(eval(code))

    return mcp


if FastMCP is None:
    mcp = None
    if __name__ == "__main__":
        raise SystemExit(
            "FastMCP is missing. Pin the SDK: pip install 'mcp>=1.2,<2' "
            "(mcp 2.x renamed FastMCP to MCPServer)."
        )
else:
    mcp = _build()
    if __name__ == "__main__":
        mcp.run()
