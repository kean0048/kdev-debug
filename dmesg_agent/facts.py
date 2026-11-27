"""Deterministic fact extraction: hard facts the model must not contradict.

Everything here is rule-based and derived only from the log or whitelisted
collection output. Facts anchor the LLM's reasoning (severity, victim process,
device identity) and land in the report as an auditable appendix. They are
never evidence quotes themselves — the verbatim-quote rules still apply.
"""

from __future__ import annotations

import re

_OOM_RE = re.compile(r"Out of memory: Killed process (\d+) \(([^)]*)\)")
_HUNG_RE = re.compile(r"INFO: task (.+?):(\d+) blocked for more than (\d+) seconds")
_SOFT_LOCK_RE = re.compile(r"watchdog: BUG: soft lockup - CPU#(\d+) stuck for (\d+)s", re.I)
_HARD_LOCK_RE = re.compile(r"watchdog: BUG: hard LOCKUP", re.I)
_PANIC_RE = re.compile(r"Kernel panic - not syncing: (.+)")
_FS_ERR_RE = re.compile(
    r"EXT4-fs error|EXT4-fs warning|XFS \([^)]*\):.*(?:error|corruption)|"
    r"BTRFS.*(?:error|corrupt)", re.I)
_FS_DEV_RE = re.compile(r"\(device ([^)\s]+)\)")
_IO_LINE_RE = re.compile(r"I/O error|medium error|critical medium error", re.I)
_IO_DEV_RE = re.compile(r"\bdev ([A-Za-z0-9._:-]+)")
_MCE_RE = re.compile(r"Machine check|Hardware Error|Uncorrectable|mce: \[Hardware Error\]", re.I)
_RCU_STALL_RE = re.compile(r"\brcu\w*\b.*\bstall", re.I)
_NVRM_ERR_RE = re.compile(r"NVRM:.*\b(NV_ERR_[A-Z0-9_]+)\b")
_EDAC_RE = re.compile(r"EDAC MC\d+: (\d+) CE, (\d+) UE")

_SMART_DEV_RE = re.compile(r"^==\s*/dev/(\S+)")
_SMART_HEALTH_RE = re.compile(r"SMART overall-health self-assessment test result:\s*(\S+)")
_SMART_NVME_RE = re.compile(
    r"^(Percentage Used|Available Spare|Media and Data Integrity Errors|"
    r"Power On Hours|Temperature|Unsafe Shutdowns):\s*(.+?)\s*$")
_SMART_ATTR_KEYS = {
    "Reallocated_Sector_Ct", "Current_Pending_Sector", "Offline_Uncorrectable",
    "Media_Wearout_Indicator", "Wear_Leveling_Count", "Percentage_Used",
    "Available_Spare", "Power_On_Hours",
}

_FAILED_UNIT_RE = re.compile(
    r"^(\S+\.(?:service|socket|timer|mount|target|path|device|slice))\s+loaded\s+failed\b")
_DF_RE = re.compile(r"^(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(\S+)")
_LOAD_RE = re.compile(r"load averages?:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)")
_MEM_RE = re.compile(r"^Mem:\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)")
_DISK_FULL_PCT = 90


def _fact(kind: str, key: str, value: str, line: int | None = None) -> dict:
    return {"kind": kind, "key": key, "value": value, "line": line}


def _bump(counter: dict, kind: str, line_no: int) -> None:
    entry = counter.setdefault(kind, [0, None])
    entry[0] += 1
    if entry[1] is None:
        entry[1] = line_no


def extract_facts(lines: list[str], collected_texts=()) -> list[dict]:
    """Extract deterministic facts from log lines and collected command output."""
    facts: list[dict] = []
    oom: dict[str, list[tuple[int, int]]] = {}
    hung: dict[str, tuple[int, int, int]] = {}
    lockups: dict[tuple[str, str], list] = {}
    io: dict[str, list[int]] = {}
    fs: dict[str, list[int]] = {}
    counts: dict[str, list] = {}
    nvrm: dict[str, list] = {}  # NV_ERR code -> [count, first line]
    edac: list = [0, 0, None]  # corrected, uncorrected, first line

    for i, line in enumerate(lines, 1):
        m = _OOM_RE.search(line)
        if m:
            oom.setdefault(m.group(2), []).append((int(m.group(1)), i))
        m = _HUNG_RE.search(line)
        if m:
            task, pid, secs = m.group(1).strip(), int(m.group(2)), int(m.group(3))
            cur = hung.get(task)
            if cur is None or secs > cur[1]:
                hung[task] = (pid, secs, i)
        m = _SOFT_LOCK_RE.search(line)
        if m:
            lockups.setdefault(("soft-lockup", m.group(1)), []).append((int(m.group(2)), i))
        elif _HARD_LOCK_RE.search(line):
            _bump(counts, "hard-lockup", i)
        if _PANIC_RE.search(line) or "general protection fault" in line.lower() \
                or "unable to handle kernel paging request" in line.lower():
            _bump(counts, "panic", i)
        if _IO_LINE_RE.search(line):
            m = _IO_DEV_RE.search(line)
            io.setdefault(m.group(1) if m else "unknown", []).append(i)
        if _FS_ERR_RE.search(line):
            m = _FS_DEV_RE.search(line)
            fs.setdefault(m.group(1) if m else "filesystem", []).append(i)
        if _MCE_RE.search(line):
            _bump(counts, "mce", i)
        if _RCU_STALL_RE.search(line):
            _bump(counts, "rcu-stall", i)
        m = _NVRM_ERR_RE.search(line)
        if m:
            code = m.group(1).lower().removeprefix("nv_err_")
            entry = nvrm.setdefault(code, [0, i])
            entry[0] += 1
        m = _EDAC_RE.search(line)
        if m:
            if edac[2] is None:
                edac[2] = i
            edac[0] += int(m.group(1))
            edac[1] += int(m.group(2))

    for proc, events in sorted(oom.items()):
        pids = ", ".join(str(p) for p, _ in events[:5])
        facts.append(_fact("oom", proc,
                           f"killed {len(events)} time(s); pid(s) {pids}",
                           events[0][1]))
    for task, (pid, secs, line_no) in sorted(hung.items()):
        facts.append(_fact("hung-task", task,
                           f"pid {pid} blocked for more than {secs}s", line_no))
    for (kind, cpu), events in sorted(lockups.items()):
        facts.append(_fact(kind, f"cpu{cpu}",
                           f"{len(events)} occurrence(s), max {max(s for s, _ in events)}s",
                           events[0][1]))
    for dev, lines_at in sorted(io.items()):
        facts.append(_fact("io-error", dev,
                           f"{len(lines_at)} I/O error line(s)", lines_at[0]))
    for dev, lines_at in sorted(fs.items()):
        facts.append(_fact("fs-error", dev,
                           f"{len(lines_at)} filesystem error/warning line(s)", lines_at[0]))
    for code, (n, first) in sorted(nvrm.items()):
        facts.append(_fact("gpu-nvrm", code, f"{n} matching line(s)", first))
    if edac[2] is not None:
        facts.append(_fact("edac", "totals",
                           f"{edac[0]} corrected, {edac[1]} uncorrected error(s)", edac[2]))
    for kind, (n, first) in sorted(counts.items()):
        if n:
            facts.append(_fact(kind, "log", f"{n} matching line(s)", first))

    for text in collected_texts:
        if text:
            facts.extend(_collected_facts(text))

    return _dedup_cap(facts)


def _collected_facts(text: str) -> list[dict]:
    facts: list[dict] = []
    dev = "disk"
    failed_units: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _SMART_DEV_RE.match(line)
        if m:
            dev = m.group(1)
            continue
        m = _SMART_HEALTH_RE.search(line)
        if m:
            facts.append(_fact("smart-health", dev, m.group(1)))
            continue
        m = _SMART_NVME_RE.match(line.strip())
        if m:
            facts.append(_fact("smart", f"{dev} {m.group(1)}", m.group(2)))
            continue
        parts = line.split()
        if len(parts) >= 10 and parts[0].isdigit() and parts[1] in _SMART_ATTR_KEYS \
                and parts[9] not in ("-", ""):
            facts.append(_fact("smart", f"{dev} {parts[1]}", parts[9]))
        m = _FAILED_UNIT_RE.match(line)
        if m and m.group(1) not in failed_units:
            failed_units.append(m.group(1))
        m = _DF_RE.match(line)
        if m and int(m.group(2)) >= _DISK_FULL_PCT:
            facts.append(_fact("disk-space", m.group(3),
                               f"{m.group(2)}% used ({m.group(1)})"))
        m = _LOAD_RE.search(line)
        if m:
            facts.append(_fact("load", "1/5/15m", f"{m.group(1)} / {m.group(2)} / {m.group(3)}"))
        m = _MEM_RE.match(line)
        if m:
            facts.append(_fact("memory", "meminfo",
                               f"total {m.group(1)}, used {m.group(2)}, "
                               f"available {m.group(4)}"))
    if failed_units:
        shown = ", ".join(failed_units[:5])
        more = f" (+{len(failed_units) - 5} more)" if len(failed_units) > 5 else ""
        facts.append(_fact("service", "failed-units", f"{len(failed_units)} unit(s): {shown}{more}"))
    return facts


def _dedup_cap(facts: list[dict], cap: int = 40) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in facts:
        key = (f["kind"], f["key"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= cap:
            break
    return out


def render_facts(facts: list[dict], max_chars: int = 3_000) -> str:
    if not facts:
        return ""
    lines = []
    for f in facts:
        loc = f" (line {f['line']})" if f.get("line") else ""
        lines.append(f"- [{f['kind']}] {f['key']}: {f['value']}{loc}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars].rsplit("\n", 1)[0] + "\n... (facts truncated) ..."
    return text
