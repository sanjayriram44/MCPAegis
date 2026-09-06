"""Errors for Lima orchestration and shared-path checks."""

from __future__ import annotations


class LimaError(RuntimeError):
    """Host or guest Lima automation failed."""


class PathNotSharedError(LimaError):
    """Path is outside the Mac home directory (Lima only mounts ``~``)."""
