"""Collect plugin: correlate error-level kernel logs from previous boots."""

from __future__ import annotations

from ..prompts import render_scan
from ..systemscan import run_cross_boot
from . import register
from ._util import add_scan_evidence


@register("collect", order=13, description="previous N boots' error logs (--cross-boot)")
def cross_boot(ctx) -> None:
    if ctx.executor is None or not ctx.args.cross_boot:
        return
    ctx.log("[3/5]", f"cross-boot correlation: previous {ctx.args.cross_boot} boot(s)")
    add_scan_evidence(ctx, run_cross_boot(ctx.executor, ctx.args.cross_boot), render_scan)
