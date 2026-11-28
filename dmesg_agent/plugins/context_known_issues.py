"""Context plugin: recall community known issues for this diagnosis (stage 4).

The store is the distilled lore / bug-tracker index built by `dmesg-agent
learn`. Each suspicious block is classified on its own and matched separately,
so a firmware block cannot be lost behind an earlier thermal signal. Matches are
injected as clearly-marked external context — never as evidence and never as
instructions. Degrades to a no-op when the store is absent.

A post hook attaches the recall trace (store, matches, model usage) to the
result so the report can show whether the community store affected the
diagnosis at all.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..knownissues import KnownIssueStore, classify_text, default_store_path
from ..prompts import render_known_issues
from . import register

_MAX_BLOCK_CHARS = 20_000
_MAX_MATCHES = 4


@register("context", order=30,
          description="known-issue recall from the community store (not evidence)")
def known_issues(ctx) -> None:
    if getattr(ctx.args, "no_known_issues", False):
        ctx.known_issues_meta = {"status": "disabled"}
        return
    db = getattr(ctx.args, "known_issues_db", None) or default_store_path()
    if not Path(db).exists():
        ctx.known_issues_meta = {"status": "no-store", "store": str(db)}
        return
    try:
        with KnownIssueStore(db) as store:
            total = store.count()
            best: dict[int, dict] = {}
            for block in ctx.blocks:
                text = "\n".join(ctx.lines[block.start - 1:block.end])
                if not text.strip():
                    continue
                cls = classify_text("", text[:_MAX_BLOCK_CHARS])
                for match in store.search(
                        fingerprint=cls.fingerprint,
                        fault_classes=cls.fault_classes,
                        subsystems=cls.subsystems, tokens=cls.tokens,
                        limit=_MAX_MATCHES):
                    match = dict(match)
                    match["block"] = f"L{block.start}-{block.end}"
                    prev = best.get(match["id"])
                    if prev is None or match["score"] > prev["score"]:
                        best[match["id"]] = match
    except Exception as e:  # a recall failure must not break diagnosis
        ctx.known_issues_meta = {"status": "error", "store": str(db),
                                 "error": f"{type(e).__name__}: {e}"}
        print(f"warning: known-issue recall failed ({e})", file=sys.stderr)
        return
    matches = sorted(best.values(), key=lambda m: (m["score"], m["id"]),
                     reverse=True)[:_MAX_MATCHES]
    ctx.known_issues = matches
    ctx.known_issues_meta = {
        "status": "matched" if matches else "no-match",
        "store": str(db), "store_total": total, "matches": matches,
    }
    if not matches:
        ctx.log("[4/5]", f"known issues: 0 matches (store: {total} issues)")
        return
    ctx.known_issues_text = render_known_issues(matches)
    ids = ", ".join(f"#{m['id']}" for m in matches)
    ctx.log("[4/5]", f"known issues: {len(matches)} match(es) ({ids})")


@register("post", order=5,
          description="attach the known-issue recall trace to the result/report")
def known_issues_trace(ctx) -> None:
    meta = getattr(ctx, "known_issues_meta", None)
    if not isinstance(ctx.result, dict) or not meta \
            or meta.get("status") == "disabled":
        return
    meta = dict(meta)
    usage = ctx.result.get("known_issue_usage")
    if isinstance(usage, list):
        meta["usage"] = [u for u in usage if isinstance(u, dict)]
    ctx.result["known_issues"] = meta
