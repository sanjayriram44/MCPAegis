"""Errors for the dynamic (runtime) pipeline.

CLI should catch ``RuntimeUnavailableError`` when Linux, cgroup v2, or eBPF/BCC
cannot support runtime detonation.
"""

from __future__ import annotations


class DynamicPipelineError(Exception):
    """Generic dynamic-pipeline failure (server launch, MCP handshake, etc.)."""


class RuntimeUnavailableError(DynamicPipelineError):
    """Raised when Linux, cgroup v2, or eBPF/BCC is missing or unusable.

    Message is intended to be printed as-is by the CLI.
    """
