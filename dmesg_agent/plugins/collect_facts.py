"""Collect plugin: deterministic, rule-extracted facts."""

from __future__ import annotations

from ..facts import extract_facts, render_facts
from . import register


@register("collect", order=90,
          description="rule-extracted hard facts (OOM/hung/IO/SMART/NVRM/…) the model must not contradict")
def facts(ctx) -> None:
    ctx.facts = extract_facts(ctx.lines, [ctx.prefetch_text, ctx.scan_text])
    ctx.facts_text = render_facts(ctx.facts)
    if ctx.facts:
        ctx.log("[4/5]", f"deterministic facts: {len(ctx.facts)}")
