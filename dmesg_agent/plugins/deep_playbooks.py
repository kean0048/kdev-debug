"""Deep plugin: per-concern whitelisted collection and verdict (multi-round)."""

from __future__ import annotations

from ..analyze import deep_dive
from . import register


@register("deep", order=10,
          description="per-concern playbook collection → verdict, with follow-up rounds")
def deep(ctx) -> None:
    if ctx.result is None or not ctx.result.get("inconclusive_concerns"):
        return
    if ctx.args.no_deep or ctx.executor is None or ctx.known_cases:
        return
    n = len(ctx.result["inconclusive_concerns"])
    ctx.log("[5/5]", f"deep-verifying {min(n, ctx.args.max_verify)}/{n} open questions "
                     "(a password prompt may appear for root-level collection)")
    ctx.result, ctx.corpus = deep_dive(
        ctx.client, ctx.executor, ctx.result, ctx.lines, ctx.bundle,
        max_concerns=ctx.args.max_verify, extra_corpus=ctx.scan_lines,
        make_stream=ctx.make_stream, max_rounds=ctx.args.deep_rounds)
    ctx.deep_used = True
