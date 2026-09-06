"""Counter-example: tool parameter is ``shlex.quote``'d before exec (no direct W5).

Taint rules list ``shlex.quote`` as a sanitizer. Pattern mode may still
see a ``subprocess.run`` sink (proximate). Named W5 requires ``direct``.
"""

from __future__ import annotations

import shlex
import subprocess

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def _build():
    mcp = FastMCP("sanitized-shell")

    @mcp.tool()
    def run_quoted(command: str) -> str:
        """Run a single quoted argument via /bin/echo (not a raw shell string)."""
        quoted = shlex.quote(command)
        completed = subprocess.run(
            ["/bin/echo", quoted],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.stdout

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
