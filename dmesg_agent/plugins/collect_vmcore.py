"""Collect plugin: vmcore post-mortem via the crash utility."""

from __future__ import annotations

import os

from ..prompts import render_scan
from ..vmcore import analyze_vmcore
from . import register
from ._util import add_scan_evidence


@register("collect", order=11, description="vmcore post-mortem via crash(8) (--vmcore)")
def vmcore(ctx) -> None:
    if ctx.executor is None or not ctx.args.vmcore:
        return
    ctx.log("[3/5]", f"vmcore analysis with crash ({ctx.args.vmcore})")
    vmlinux = ctx.args.vmlinux or os.environ.get("DMESG_AGENT_VMLINUX")
    add_scan_evidence(ctx, [analyze_vmcore(ctx.executor, ctx.args.vmcore, vmlinux)],
                      render_scan)
