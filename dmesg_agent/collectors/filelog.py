"""Offline log file: read dmesg/kern.log (.gz and stdin supported)."""

from __future__ import annotations

import gzip
import re

from ..errors import CollectError
from .base import RawBundle

# journalctl -o short: "Nov 27 02:48:04 hostname kernel: ..."
_JOURNAL_HOST_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+\S+:")


def derive_hostname(text: str) -> str | None:
    """Best-effort host identity from a journalctl-style log.

    Raw dmesg (monotonic timestamps only) carries no hostname; returns None.
    The most frequent hostname wins when a file mixes several hosts.
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        m = _JOURNAL_HOST_RE.match(line)
        if m:
            host = m.group(1).strip()
            if host:
                counts[host] = counts.get(host, 0) + 1
    if not counts:
        return None
    return max(counts, key=counts.get)


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
    extra: dict[str, str] = {
        "note": "offline log file; no live system context available",
    }
    hostname = derive_hostname(text)
    if hostname:
        extra["hostname"] = hostname
    return RawBundle(
        dmesg_text=text,
        kernel_version=kernel,
        distro=distro,
        extra_context=extra,
        source=f"file:{path}",
    )
