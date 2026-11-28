"""Context plugin: per-host case history and the confirmed-case fast path."""

from __future__ import annotations

import sys

from ..knowledge import (KnowledgeError, find_confirmed_cases, host_history,
                         log_fingerprint, resolve_db_path)
from ..prompts import render_history
from . import register


@register("context", order=20,
          description="per-host case history + confirmed-case fast path (multi-case)")
def history(ctx) -> None:
    if ctx.args.no_knowledge:
        return
    db = resolve_db_path(ctx.args.knowledge_db)
    try:
        ctx.history_text = render_history(host_history(db, ctx.host))
    except KnowledgeError as e:
        print(f"warning: case history unavailable ({e})", file=sys.stderr)
    if ctx.history_text:
        ctx.log("[4/5]", f"prior case history: {ctx.history_text.count(chr(10)) + 1} line(s)")
    try:
        block_lines: list[str] = []
        for b in ctx.blocks:
            block_lines.extend(ctx.lines[b.start - 1:b.end])
        tokens = log_fingerprint(block_lines).tokens
        ctx.known_cases = find_confirmed_cases(db, ctx.host, tokens, log_lines=ctx.lines)
    except KnowledgeError as e:
        print(f"warning: confirmed-case lookup failed ({e})", file=sys.stderr)
    if not ctx.known_cases:
        return
    ctx.known_case = ctx.known_cases[0]
    parts = ["[Known confirmed cases on this host — prior verdicts, not evidence]"]
    for kc in ctx.known_cases[:5]:
        parts.append(
            f"### case #{kc['case_id']} (match: {kc['tier']}, score {kc['score']})\n"
            f"Title: {kc['title']}\n"
            f"Subsystem: {kc['subsystem'] or '?'}\n"
            f"Root cause: {str(kc['root_cause'])[:500]}\n"
            f"Previously confirmed x{kc['occurrences']} (last {kc['last_seen']}).")
    parts.append("Judge only the delta versus these known cases: are they the same "
                 "issues, and what changed? Report any NEW issue not covered here.")
    ctx.history_text = (ctx.history_text + "\n" + "\n".join(parts)).strip()
    ids = ", ".join(f"#{kc['case_id']}" for kc in ctx.known_cases)
    ctx.log("[4/5]", f"fast path: {len(ctx.known_cases)} confirmed case(s) matched "
                     f"({ids}); deep collection will be skipped")
