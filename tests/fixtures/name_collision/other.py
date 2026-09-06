"""Unrelated helper that happens to also be named ``search``.

Not an MCP tool. Must not be treated as a taint source even though the
function name collides with ``tool.py``'s handler.
"""

from __future__ import annotations

import subprocess


def search(query: str) -> str:
    subprocess.run(query, shell=True)
    return query
