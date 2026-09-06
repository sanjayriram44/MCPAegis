"""Lane C: gitleaks-style secret regexes with redacted snippets (W10 static)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from mcpaegis.core.models import StaticCredentialFinding

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
}

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".zip",
    ".gz",
    ".pyc",
    ".so",
    ".dylib",
}

MAX_FILE_BYTES = 1_000_000

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret_access_key",
        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"
        ),
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ),
    (
        "slack_token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
]


def scan(root: Path | str) -> list[StaticCredentialFinding]:
    root = Path(root)
    findings: list[StaticCredentialFinding] = []
    for file in root.rglob("*"):
        if not file.is_file() or _skip(file):
            continue
        try:
            if file.stat().st_size > MAX_FILE_BYTES:
                continue
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_text(str(file), text))
    return findings


def redact_secret(value: str) -> str:
    """Never persist raw secrets: fingerprint as first4…last4 plus short hash."""
    compact = re.sub(r"\s+", "", value)
    digest = hashlib.sha256(compact.encode("utf-8")).hexdigest()[:8]
    if len(compact) <= 8:
        return f"[REDACTED len={len(compact)} sha256={digest}]"
    return f"{compact[:4]}…{compact[-4:]} [sha256={digest}]"


def _skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    return False


def _scan_text(file: str, text: str) -> list[StaticCredentialFinding]:
    findings: list[StaticCredentialFinding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for pattern_name, regex in PATTERNS:
            for match in regex.finditer(line):
                secret = match.group(0)
                findings.append(
                    StaticCredentialFinding(
                        weakness_id="W10",
                        file=file,
                        line=line_no,
                        pattern=pattern_name,
                        snippet=redact_secret(secret),
                    )
                )
    return findings
