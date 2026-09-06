"""Fixture MCP server: unsanitized URL fetch (W7).

Lab analogue: Appsecco Wikipedia / utilities servers that take a URL or
title and issue an outbound HTTP request with no allowlist.

Handshake-safe: ``requests.get`` only runs on ``tools/call``. If the
``requests`` package is missing, the handler returns the URL string so
stdio still works.
"""

from __future__ import annotations

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def _build():
    mcp = FastMCP("ssrf")

    @mcp.tool()
    def fetch_url(url: str) -> str:
        """Fetch an arbitrary URL and return the response body.

        No scheme/host allowlist. Callers can pass ``file://``, link-local,
        or cloud-metadata URLs the same as ``https://example.com``.
        """
        if requests is None:
            return url
        # VULNERABILITY: user-controlled URL is the request target.
        response = requests.get(url, timeout=5)
        return response.text[:2000]

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
