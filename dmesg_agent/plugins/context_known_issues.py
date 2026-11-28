"""Context plugin: recall community known issues for this diagnosis (stage 4).

The store is the distilled lore / bug-tracker index built by `dmesg-agent
learn`. Matches are injected as clearly-marked external context — never as
evidence and never as instructions. Degrades to a no-op when the store is
absent (fresh install without `learn`).
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..knownissues import KnownIssueStore, classify_text, default_store_path
from ..prompts import render_known_issues
from . import register

_MAX_BLOCK_LINES = 4_000


@register("context", order=30,
          description="known-issue recall from the community store (not evidence)")
def known_issues(ctx) -> None:
    if getattr(ctx.args, "no_known_issues", False):
        return
    db = getattr(ctx.args, "known_issues_db", None) or default_store_path()
    if not Path(db).exists():
        return
    lines: list[str] = []
    for block in ctx.blocks:
        lines.extend(ctx.lines[block.start - 1:block.end])
        if len(lines) >= _MAX_BLOCK_LINES:
            break
    try:
        with KnownIssueStore(db) as store:
            cls = classify_text("", "\n".join(lines[:_MAX_BLOCK_LINES]))
            matches = store.search(
                fingerprint=cls.fingerprint, fault_classes=cls.fault_classes,
                subsystems=cls.subsystems, tokens=cls.tokens, limit=4)
    except Exception as e:  # a recall failure must not break diagnosis
        print(f"warning: known-issue recall failed ({e})", file=sys.stderr)
        return
    if not matches:
        return
    ctx.known_issues = matches
    ctx.known_issues_text = render_known_issues(matches)
    ids = ", ".join(f"#{m['id']}" for m in matches)
    ctx.log("[4/5]", f"known issues: {len(matches)} match(es) ({ids})")
