"""Fixture MCP server: attacker-controlled ``eval`` (W6, dynamic_code_load).

Lab analogue: Appsecco ``vulnerable-mcp-server-malicious-code-exec``
(quote-of-the-day with an unsafe format string). The original server
fetched a quote over HTTP and ``eval``'d the format argument.

Handshake-safe reconstruction: in-memory quote only. No outbound fetch,
no API key. ``eval(fmt)`` remains in source so Semgrep taint can prove
parameter → ``dynamic_code_load``.
"""

from __future__ import annotations

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None

_QUOTE = "The only thing we have to fear is fear itself."


def _build():
    mcp = FastMCP("eval-format")

    @mcp.tool()
    def get_qotd(fmt: str) -> str:
        """Return the quote of the day, optionally formatted.

        ``fmt`` is a Python expression evaluated against the quote string
        (for example ``quote.upper()``). Intended as a formatting helper.
        """
        quote = _QUOTE
        # VULNERABILITY: user-controlled expression is eval'd in-process.
        return str(eval(fmt))

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
