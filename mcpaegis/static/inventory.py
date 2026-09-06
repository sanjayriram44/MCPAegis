"""Lane C: supply-chain (W4) + static credential (W10) inventory."""

from __future__ import annotations

from pathlib import Path

from mcpaegis.core.models import DependencyFinding, StaticCredentialFinding
from mcpaegis.core.session import AuditSession
from mcpaegis.core.taxonomy import Weakness
from mcpaegis.static import credential_scanner, sca_scan


def scan(
    root: Path | str,
    session: AuditSession | None = None,
) -> tuple[list[StaticCredentialFinding], list[DependencyFinding]]:
    """Walk the tree for hardcoded secrets and wrap SCA CLIs.

    Missing audit tools yield empty W4 rows (not a failure). Category filters
    skip the matching half.
    """
    root = Path(root)
    cred: list[StaticCredentialFinding] = []
    deps: list[DependencyFinding] = []
    if session is None or session.uses_category(Weakness.W10_CREDENTIAL_EXPOSURE):
        cred = credential_scanner.scan(root)
    if session is None or session.uses_category(Weakness.W4_SUPPLY_CHAIN):
        deps = sca_scan.scan(root)
    return cred, deps
