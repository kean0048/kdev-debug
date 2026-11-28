"""Source plugin: sosreport tarballs, journalctl json/export, nvidia-bug-report."""

from __future__ import annotations

from ..collectors.packages import is_offline_package, load_offline_input
from . import register


@register("source", order=10,
          description="offline packages: sosreport tar, journalctl json/export, "
                      "nvidia-bug-report.log[.gz]")
def offline_packages(ctx) -> bool:
    path = ctx.args.file
    if not path or not is_offline_package(path):
        return False
    ctx.log("[1/5]", f"reading package {path}")
    pkg = load_offline_input(path, kernel=ctx.args.kernel, distro=ctx.args.distro)
    ctx.bundle = pkg.bundle
    ctx.offline_sources = pkg.extra_sources
    if pkg.note:
        ctx.log("[1/5]", pkg.note)
    return True
