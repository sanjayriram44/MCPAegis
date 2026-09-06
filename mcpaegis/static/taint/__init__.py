"""Stage 3 taint analysis backends."""

from mcpaegis.static.taint.codeql_runner import run as run_codeql
from mcpaegis.static.taint.semgrep_runner import derive_code_capabilities, run as run_semgrep

__all__ = ["derive_code_capabilities", "run_codeql", "run_semgrep"]
