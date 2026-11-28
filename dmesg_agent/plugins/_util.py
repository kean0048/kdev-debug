"""Small helpers shared by plugin modules (leading underscore => not discovered)."""

from __future__ import annotations


def add_scan_evidence(ctx, evs, render) -> None:
    """Append collected evidence to the scan text and evidence corpus."""
    if not evs:
        return
    text = render(evs)
    ctx.scan_text = (ctx.scan_text + "\n\n" + text).strip() if ctx.scan_text else text
    for ev in evs:
        ctx.scan_lines.extend(ev.output.splitlines())
