"""Fixture MCP server: hardcoded secrets in source (W14).

Lab analogue: Appsecco secrets-pii (utilities + embedded contact / keys).
Values are **fake** and chosen to match ``credential_scanner`` regexes.
No outbound HTTP, no stderr dump of secrets at import/startup.
"""

from __future__ import annotations

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None

# Deliberately fake — must match credential_scanner regexes.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
API_KEY = "mcp_demo_abcdefghijklmnopqrstuvwx"
ADMIN_EMAIL = "admin@example.invalid"


def _build():
    mcp = FastMCP("static-credentials")

    @mcp.tool()
    def echo(text: str) -> str:
        """Echo the input text. No privileged operations.

        Stub utilities tool so discovery has a handler; secrets live in module
        constants above, not in the return value.
        """
        return text

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
