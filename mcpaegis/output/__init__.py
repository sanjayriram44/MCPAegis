"""Report writers: JSON, SARIF 2.1.0, markdown/terminal, and HTML."""

from mcpaegis.output.html_writer import render_html, write_html
from mcpaegis.output.json_writer import dumps as dumps_json
from mcpaegis.output.json_writer import load_report, write as write_json
from mcpaegis.output.markdown_writer import print_report, render_markdown, render_terminal
from mcpaegis.output.markdown_writer import write as write_markdown
from mcpaegis.output.sarif_writer import to_sarif
from mcpaegis.output.sarif_writer import write as write_sarif

__all__ = [
    "dumps_json",
    "load_report",
    "print_report",
    "render_html",
    "render_markdown",
    "render_terminal",
    "to_sarif",
    "write_html",
    "write_json",
    "write_markdown",
    "write_sarif",
]
