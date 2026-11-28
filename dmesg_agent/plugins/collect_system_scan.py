"""Collect plugin: proactive system scan for problems absent from dmesg."""

from __future__ import annotations

from ..prompts import render_scan
from ..systemscan import run_system_scan
from . import register
from ._util import add_scan_evidence


@register("collect", order=10,
          description="proactive system scan (failed units, crashes, disk, pressure, packages, net)")
def system_scan(ctx) -> None:
    if ctx.executor is None:
        return
    no_signal = len(ctx.blocks) == 1 and ctx.blocks[0].names == ["whole-log"]
    if not (ctx.args.scan or (no_signal and not ctx.args.no_scan)):
        return
    ctx.log("[3/5]", "proactive system scan (non-kernel-log problems)")
    add_scan_evidence(ctx, run_system_scan(ctx.executor), render_scan)
