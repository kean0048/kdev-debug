"""Post plugin: per-host case library (shadow mode) + recurrence/diff."""

from __future__ import annotations

import sys

from ..knowledge import KnowledgeError, record_run, resolve_db_path
from . import register


@register("post", order=10,
          description="per-host case library recording, recurrence and run diff")
def knowledge(ctx) -> None:
    if ctx.args.no_knowledge or not isinstance(ctx.result, dict):
        return
    try:
        kb = record_run(resolve_db_path(ctx.args.knowledge_db), ctx.host, ctx.result,
                        kernel=ctx.bundle.kernel_version, source=ctx.bundle.source,
                        fuzzy_threshold=ctx.args.kmatch_threshold,
                        verified=(ctx.summary.passed, ctx.summary.total),
                        run_uuid=ctx.run_uuid)
        ctx.result["knowledge"] = kb
        if ctx.known_cases:
            kb["fast_path"] = ctx.known_case
            kb["fast_path_cases"] = [
                {"case_id": kc["case_id"], "title": kc["title"]}
                for kc in ctx.known_cases]
        ctx.log("[6/6]", f"case library (shadow): {len(kb['matches'])} finding(s), "
                         f"{kb['new_cases']} new, {kb['recurrences']} recurrence(s)")
    except KnowledgeError as e:
        print(f"warning: case library not updated ({e})", file=sys.stderr)
