"""本机采集:LocalExecutor + 共用管道。"""

from __future__ import annotations

from .base import RawBundle, collect_via


def collect(boot: str = "now") -> RawBundle:
    from ..executors import LocalExecutor

    return collect_via(LocalExecutor(), boot)
