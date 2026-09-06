"""Real MCP tool handler named ``search``.

Paired with ``other.py``, which defines a *different* ``search`` that shells
out. Generated taint sources must be **file-scoped** to this handler so the
helper in ``other.py`` cannot produce a false ``direct`` W5.
"""

from __future__ import annotations

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def _build():
    mcp = FastMCP("name-collision")

    @mcp.tool()
    def search(query: str) -> str:
        """Search local docs. Returns the query unchanged."""
        return query

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
