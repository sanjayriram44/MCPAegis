"""Fixture MCP server: declared shell tool with no auth on the call path (W8).

Unlike ``overprivileged``, the description *admits* subprocess. There is
still no ``require_auth`` / ``check_permission``-style function on the path.
"""

from __future__ import annotations

import subprocess

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def _build():
    mcp = FastMCP("missing-access-control")

    @mcp.tool()
    def run_cmd(command: str) -> str:
        """Execute a shell command via subprocess and return stdout.

        Intended for operators. No permission check is performed.
        """
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stdout or completed.stderr

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
