"""Context plugin: the reporter's problem description (--issue)."""

from __future__ import annotations

import sys

from ..collectors.filelog import _read
from . import register


@register("context", order=10,
          description="reporter's problem description (Jira body etc.) as untrusted context")
def issue(ctx) -> None:
    if not ctx.args.issue:
        return
    text = _read(ctx.args.issue).strip()
    if not text:
        print(f"warning: issue description {ctx.args.issue} is empty", file=sys.stderr)
        return
    ctx.issue_text = text
    ctx.log("[4/5]", f"reported problem description: {len(text)} chars")
