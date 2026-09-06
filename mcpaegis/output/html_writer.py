"""HTML summary writer used by ``mcpaegis report --format html``."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from mcpaegis.core.taxonomy import Weakness
from mcpaegis.output.findings import FindingLike, FindingRecord, ReportLike
from mcpaegis.output.markdown_writer import render_html, write_html

__all__ = ["dumps", "render_html", "write", "write_html"]


def dumps(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
) -> str:
    return render_html(source, categories=categories)


def write(
    source: ReportLike | Sequence[FindingLike | FindingRecord] | FindingLike | FindingRecord,
    path: str | Path,
    *,
    categories: frozenset[Weakness] | Iterable[str] | None = None,
) -> Path:
    return write_html(source, path, categories=categories)
