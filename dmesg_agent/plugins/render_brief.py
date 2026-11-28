"""Render plugin: the triage-sized --brief output."""

from __future__ import annotations

from ..report import render_brief
from . import register


@register("render", name="brief", order=10,
          description="verdict box + findings table + open questions only (--brief)")
def brief(ctx) -> str:
    return render_brief(ctx.result, ctx.bundle, ctx.summary)
