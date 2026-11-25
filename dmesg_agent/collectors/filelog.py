"""离线日志文件:读入 dmesg/kern.log(支持 .gz 与 stdin)。"""

from __future__ import annotations

import gzip

from ..errors import CollectError
from .base import RawBundle


def _read(path: str) -> str:
    if path == "-":
        import sys
        return sys.stdin.read()
    try:
        with open(path, "rb") as f:
            head = f.read(2)
        opener = gzip.open if head == b"\x1f\x8b" else open
        with opener(path, "rt", errors="replace") as f:
            return f.read()
    except OSError as e:
        raise CollectError(f"无法读取日志文件 {path}: {e}") from e


def collect_file(path: str, kernel: str = "unknown", distro: str = "unknown") -> RawBundle:
    text = _read(path).strip()
    if not text:
        raise CollectError(f"日志文件 {path} 为空")
    return RawBundle(
        dmesg_text=text,
        kernel_version=kernel,
        distro=distro,
        extra_context={"note": "离线日志文件,无实时系统上下文"},
        source=f"file:{path}",
    )
