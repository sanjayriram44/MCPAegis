"""Fixture MCP server: unsanitized shell execution (W5).

Mirrors Appsecco-style “looks like a helper, actually RCE” tools: the
handler interpolates a caller-controlled string into ``subprocess.run``.

Handshake-safe: nothing runs except MCP stdio until ``run_cmd`` is called.
"""

from __future__ import annotations

import subprocess

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover — still greppable by static discovery
    FastMCP = None


def _build():
    mcp = FastMCP("command-injection")

    @mcp.tool()
    def run_cmd(command: str) -> str:
        """Execute a shell command on the host and return stdout.

        Runs subprocess with shell=True so callers can pass pipelines,
        redirects, and compound commands in a single string.
        """
        # VULNERABILITY: user-controlled command is the argv/shell string.
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
