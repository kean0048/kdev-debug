"""Collect plugin: deterministic live prefetch routed by triage signatures."""

from __future__ import annotations

from ..playbooks import run_prefetch
from ..prompts import render_prefetch
from . import register


@register("collect", order=20,
          description="live prefetch of system state (unprivileged, signature-routed)")
def prefetch(ctx) -> None:
    if ctx.executor is None or ctx.args.no_prefetch:
        ctx.log("[3/5]", "skipping prefetch"
                + (" (no executor with --file)" if ctx.args.file else ""))
        return
    sig = {n for b in ctx.blocks for n in b.names}
    evs = run_prefetch(ctx.executor, sig)
    ctx.prefetch_text = render_prefetch(evs)
    ctx.log("[3/5]", f"prefetch: {sum(1 for e in evs if e.status == 'ok')} items")
