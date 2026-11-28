"""Collect plugin: call-trace → kernel source correlation."""

from __future__ import annotations

import os
import sys

from ..srcmap import SrcMap, extract_symbols
from . import register


@register("collect", order=50,
          description="call-trace source correlation + known-fix candidates (--kernel-src)")
def srcmap(ctx) -> None:
    src_path = ctx.args.kernel_src or os.environ.get("DMESG_AGENT_KERNEL_SRC")
    if not src_path or ctx.args.no_srcmap:
        return
    sm = SrcMap(src_path)
    if not sm.available:
        print(f"warning: kernel source tree unavailable ({src_path}); "
              f"skipping source correlation", file=sys.stderr)
        return
    syms = extract_symbols(ctx.lines)
    if not syms:
        ctx.log("[3.5]", "no Call Trace symbols in the log; skipping source correlation")
        return
    ctx.srcmap_version = sm.version
    ctx.log("[3.5]", f"source correlation: {len(syms)} trace functions @ {src_path}")
    try:
        sm.build_index(progress=lambda m: print(f"  {m}", file=sys.stderr))
        ctx.source_text, matched = sm.render(
            syms, running_kernel=ctx.bundle.kernel_version)
        ctx.log("[3.5]", f"correlated {len(matched)}/{len(syms)} functions")
    except Exception as e:
        print(f"warning: source correlation failed ({e}); continuing without sources",
              file=sys.stderr)
