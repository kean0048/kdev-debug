"""Render plugin: the self-contained, print-ready --html report."""

from __future__ import annotations

from pathlib import Path

from ..report_html import render_html
from . import register


@register("render", name="html", order=10,
          description="self-contained print/PDF-ready HTML report (--html PATH)")
def html(ctx) -> str:
    html_text = render_html(
        ctx.result, ctx.bundle, ctx.summary, ctx.blocks, ctx.lines,
        raw_text=ctx.answer, prefetch_used=bool(ctx.prefetch_text),
        deep_used=ctx.deep_used, scan_used=bool(ctx.scan_text),
        scan_text=ctx.scan_text, changes_text=ctx.changes_text,
        source_text=ctx.source_text, srcmap_version=ctx.srcmap_version)
    Path(ctx.args.html).write_text(html_text + "\n", encoding="utf-8")
    ctx.html_written = True
    return str(ctx.args.html)
