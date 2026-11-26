"""Offline log file: read dmesg/kern.log (.gz and stdin supported)."""

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
        raise CollectError(f"cannot read log file {path}: {e}") from e


def collect_file(path: str, kernel: str = "unknown", distro: str = "unknown") -> RawBundle:
    text = _read(path).strip()
    if not text:
        raise CollectError(f"log file {path} is empty")
    return RawBundle(
        dmesg_text=text,
        kernel_version=kernel,
        distro=distro,
        extra_context={"note": "offline log file; no live system context available"},
        source=f"file:{path}",
    )
