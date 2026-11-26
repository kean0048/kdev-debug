"""Prefilter: cut suspicious segments out of the whole log using known error signatures,
reducing noise and token usage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CONTEXT = 3  # lines of context kept around each hit


@dataclass
class Block:
    start: int  # 1-based, inclusive
    end: int    # 1-based, inclusive
    names: list[str] = field(default_factory=list)


SIGNATURES: list[tuple[str, re.Pattern]] = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in [
        ("panic", r"kernel panic|Attempted to kill"),
        ("bug", r"\bBUG[:\s]|\bOops\b"),
        ("call-trace", r"Call Trace|stack backtrace"),
        ("fault", r"general protection fault|\bKASAN\b|\bKCSAN\b|null pointer dereference|page fault"),
        ("lockup", r"soft lockup|hard LOCKUP|hard lockup|watchdog.*BUG"),
        ("hung-task", r"blocked for more than|hung_task|\btainted\b"),
        ("oom", r"Out of memory|oom-kill|Killed process|oom_reaper|Memory cgroup out of memory"),
        ("segfault", r"segfault|\btraps:|\bDo \w+ fault\b"),
        ("fs-error", r"EXT4-fs error|EXT4-fs warning|XFS \(.*\): .*(error|corruption)|BTRFS.*error"),
        ("io-error", r"I/O error|blk_update_request|critical target|medium error|critical write"),
        ("nvme", r"nvme[0-9]*.*(error|timeout|reset|abort|failing)"),
        ("ata", r"ata[0-9]+.*(error|exception|hardreset|failed|EMERG)"),
        ("mce", r"\bmce\b|Machine check|Hardware Error|Uncorrectable"),
        ("edac", r"EDAC.*(error|corrected)"),
        ("pcie-aer", r"\bAER\b|PCIe Bus Error|pcieport.*error"),
        ("thermal", r"thermal|temperature above|throttl|over-heat|overheat"),
        ("gpu-amd", r"amdgpu.*(reset|hang|ih error|halt|timeout)|ring .*timeout|\[drm\].*timeout"),
        ("gpu-nvidia", r"\bXid\b|nvidia.*(error|fault|bug)"),
        ("gpu-nouveau", r"nouveau.*(error|fault|gr \d)"),
        ("usb", r"usb .*(disconnect|reset|error)|xhci.*(died|error|timeout)|hub .*(disconnect|error)"),
        ("net-link", r"link is (down|up)|NIC Link is (Down|Up)"),
        ("net-ddos", r"possible SYN flooding|TCP: request_sock"),
        ("security", r"audit:.*denied|apparmor.*DENIED|avc:\s*denied"),
        ("firmware", r"(Direct-)?[Ff]irmware load.*(?:fail|error)|failed to load"),
        ("driver", r"driver .*(?:failed|error)|(?:probe|init).*(?:failed|error)"),
        ("power", r"(suspend|resume|hibernate).*fail|ACPI.*error"),
        # additional signatures in the style of syzkaller pkg/report
        ("lockdep", r"circular locking|deadlock|inconsistent lock state|already held|trying to lock"),
        ("rcu-stall", r"rcu.*stall|self-detected stall"),
        ("sanitizer", r"\bUBSAN\b|\bKFENCE\b|use-after-free|slab.*corrupt|list.*corrupted|refcount_t:|BUG: (MAX_|Kmap)"),
        ("page-alloc", r"page allocation failure|pageblock|corrupted page|bad page"),
        ("workqueue", r"BUG: workqueue|workqueue.*lockup|workqueue: *WARNING"),
        ("warning", r"WARNING:"),
        # non-kernel signals: appear in journals that mix kernel + userspace lines
        ("systemd-failed", r"Main process exited|Failed to start|entered failed state|failed with result"),
        ("app-crash", r"core dumped|Aborted|Assertion .* failed|double free|corrupted"),
        ("disk-space", r"No space left on device|ENOSPC|write failed.*space"),
    ]
]

GENERIC_LEVEL = re.compile(r"\b(err|error|fail|failed|failure|fault|crit|alert|emerg|panic)\b", re.IGNORECASE)


def find_blocks(lines: list[str]) -> list[Block]:
    """Return suspicious segments sorted by line number and merged. If nothing matches, return a single whole-log block."""
    intervals: list[list] = []  # [start, end, [names]]
    for i, line in enumerate(lines):
        names = [name for name, pat in SIGNATURES if pat.search(line)]
        if names:
            _push(intervals, max(0, i - CONTEXT), min(len(lines) - 1, i + CONTEXT), names)
    if not intervals:
        # fallback: coarse level-word screen; if still nothing, hand the whole log to the model
        for i, line in enumerate(lines):
            if GENERIC_LEVEL.search(line):
                _push(intervals, max(0, i - CONTEXT), min(len(lines) - 1, i + CONTEXT), ["level-keyword"])
    if not intervals:
        return [Block(start=1, end=len(lines), names=["whole-log"])]
    intervals.sort(key=lambda x: x[0])
    blocks: list[Block] = []
    for start, end, names in intervals:
        if blocks and start <= blocks[-1].end + 1:
            blocks[-1].end = max(blocks[-1].end, end)
            for n in names:
                if n not in blocks[-1].names:
                    blocks[-1].names.append(n)
        else:
            blocks.append(Block(start=start + 1, end=end + 1, names=list(names)))
    return blocks


def _push(intervals: list, start: int, end: int, names: list[str]) -> None:
    for iv in intervals:
        if start <= iv[1] and end >= iv[0]:  # overlap
            iv[0], iv[1] = min(iv[0], start), max(iv[1], end)
            for n in names:
                if n not in iv[2]:
                    iv[2].append(n)
            return
    intervals.append([start, end, list(names)])


def render_blocks(lines: list[str], blocks: list[Block], max_chars: int = 900_000) -> str:
    """Render as text with real line numbers; truncate by block order and note it if too long."""
    chunks = []
    for b in blocks:
        header = f"### Segment L{b.start}-{b.end} [{', '.join(b.names)}]"
        body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(b.start, b.end + 1))
        chunks.append((header, body))
    total = sum(len(h) + len(bd) + 2 for h, bd in chunks)
    if total > max_chars and chunks:
        # over budget: trim EVERY segment's head+tail rather than dropping the
        # later ones — in chronological logs the newest events matter most
        # (sashiko trims contiguous runs inside quotes, never whole items)
        avg_line = max(1, total // max(1, sum(len(bd.splitlines()) for _, bd in chunks)))
        keep = max(10, max_chars // max(1, len(chunks)) // avg_line)
        slim = []
        for h, bd in chunks:
            ls = bd.splitlines()
            if len(ls) > keep:
                head = keep - keep // 2
                ls = ls[:head] + [f"... {len(ls) - keep} lines omitted ..."] + ls[-(keep - head):]
            slim.append((h, "\n".join(ls)))
        chunks = slim
    out = []
    for h, bd in chunks:
        out.append(f"{h}\n{bd}\n")
    return "\n".join(out)
