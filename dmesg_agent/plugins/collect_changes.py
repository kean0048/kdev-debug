"""Collect plugin: system-change correlation around the first fault."""

from __future__ import annotations

from ..prompts import render_scan
from ..systemscan import run_system_changes
from ..triage import parse_first_error_time
from . import register


@register("collect", order=30,
          description="boots / kernel install / package / suspend correlation around the first fault")
def system_changes(ctx) -> None:
    if ctx.executor is None:
        return
    first_ts = parse_first_error_time(ctx.lines, ctx.blocks)
    evs = run_system_changes(ctx.executor, first_ts)
    ctx.changes_text = render_scan(evs)
    for ev in evs:
        ctx.scan_lines.extend(ev.output.splitlines())
    ok_count = sum(1 for e in evs if e.status == "ok")
    ctx.log("[3/5]", f"system-change correlation: {ok_count} item(s)"
            + (f" around {first_ts:%Y-%m-%d %H:%M}" if first_ts else
               " (no absolute timestamps in the log)"))
    if ctx.changes_text:
        ctx.prefetch_text = (
            ctx.prefetch_text
            + "\n\n[System changes around the first fault — whitelisted evidence]\n"
            + ctx.changes_text).strip()
