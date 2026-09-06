"""Fixture MCP server: unsanitized filesystem read (W7).

Lab analogue: Appsecco filesystem workspace ``read_file`` without a
``realpath`` / prefix check. Path is opened as given.

Handshake-safe: ``Path.read_text`` only runs on ``tools/call``.
"""

from __future__ import annotations

from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def _build():
    mcp = FastMCP("path-traversal")

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read a file from the given path and return its contents.

        The path is opened as-is (no sandboxing, no workspace prefix,
        no ``..`` rejection). Relative paths and absolute paths are both accepted.
        """
        # VULNERABILITY: naive open of caller-controlled path.
        return Path(path).read_text(encoding="utf-8", errors="replace")

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
