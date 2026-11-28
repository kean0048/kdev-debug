"""Collect plugin: live kernel data-structure forensics via drgn."""

from __future__ import annotations

from ..prompts import render_scan
from ..systemscan import run_live_probe
from . import register
from ._util import add_scan_evidence


@register("collect", order=12, description="live kernel forensics via drgn (--live-probe)")
def live_probe(ctx) -> None:
    if ctx.executor is None or not ctx.args.live_probe:
        return
    ctx.log("[3/5]", "live kernel probe via drgn")
    add_scan_evidence(ctx, run_live_probe(ctx.executor), render_scan)
