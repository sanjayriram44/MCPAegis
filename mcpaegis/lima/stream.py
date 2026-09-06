"""Decode subprocess / PTY bytes into log lines (handles ``\\r`` progress)."""

from __future__ import annotations


def split_stream(buf: bytes) -> tuple[list[str], bytes]:
    """Return complete log lines and leftover bytes.

    Lima/curl progress rewrites the same line with ``\\r`` and never sends
    ``\\n``. Treat CR as a line break so the TUI is not silent for minutes.
    """
    text = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    parts = text.split(b"\n")
    rest = parts.pop()
    lines: list[str] = []
    for part in parts:
        line = part.decode("utf-8", errors="replace").replace("\x1b[K", "").strip()
        if line:
            lines.append(line)
    return lines, rest
