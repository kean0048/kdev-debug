"""Post plugin: archive the run (full LLM I/O + evidence trail, replayable)."""

from __future__ import annotations

import sys

from ..archive import build_archive, write_run_archive
from . import register


@register("post", order=20,
          description="replayable run archive: prompts, LLM I/O, collected evidence, result")
def archive(ctx) -> None:
    try:
        ctx.archive_path = write_run_archive(build_archive(
            run_uuid=ctx.run_uuid, host=ctx.host, bundle=ctx.bundle, blocks=ctx.blocks,
            blocks_text=ctx.blocks_text, prefetch_text=ctx.prefetch_text,
            scan_text=ctx.scan_text, changes_text=ctx.changes_text,
            source_text=ctx.source_text, facts_text=ctx.facts_text,
            exchanges=ctx.client.exchanges, result=ctx.result,
            verify={"total": ctx.summary.total, "passed": ctx.summary.passed,
                    "line_mismatch": ctx.summary.line_mismatch},
            argv=ctx.argv, error=ctx.llm_error, base_url=ctx.cfg.base_url,
            model=ctx.client.last_model or ctx.cfg.model or ""))
        ctx.log("[6/6]", f"run archive: {ctx.archive_path}")
    except OSError as e:
        print(f"warning: run archive not written ({e})", file=sys.stderr)
