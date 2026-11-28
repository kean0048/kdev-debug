"""Collect plugin: extra files extracted from an offline package."""

from __future__ import annotations

from ..collectors.packages import render_offline_sources
from . import register


@register("collect", order=40,
          description="journal/messages/collected command output from an offline package")
def offline_sources(ctx) -> None:
    if not ctx.offline_sources:
        return
    text = render_offline_sources(ctx.offline_sources)
    if not text:
        return
    ctx.scan_text = (ctx.scan_text + "\n\n" + text).strip() if ctx.scan_text else text
    for _label, body in ctx.offline_sources:
        ctx.scan_lines.extend(body.splitlines())
    ctx.log("[3/5]", f"offline sources: {len(ctx.offline_sources)} extra file(s) "
                     "joined the evidence corpus")
