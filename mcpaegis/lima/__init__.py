"""Lima VM automation for Apple Silicon runtime analysis."""

from mcpaegis.lima.errors import LimaError, PathNotSharedError
from mcpaegis.lima.paths import INSTANCE_NAME, require_under_home, stage_under_home

__all__ = [
    "INSTANCE_NAME",
    "LimaError",
    "PathNotSharedError",
    "require_under_home",
    "stage_under_home",
]
