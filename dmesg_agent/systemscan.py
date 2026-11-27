"""Proactive system scan: problems that never print a dmesg line.

Covers the structural blind spots of kernel-log-only analysis: failed systemd
units, userspace application errors/crashes, disk/inode exhaustion, load and
resource pressure, broken package state, network configuration. Like the
playbooks, every command is a whitelisted read-only shell string; nothing here
is driven by model or log content.

The scan runs on demand (--scan) or proactively whenever an executor is
available and triage found nothing suspicious.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .executors import Executor
from .playbooks import CollectedEvidence, _truncate

CHANGES_CHAR_BUDGET = 6_000
CHANGES_MAX_CHARS_PER_CMD = 2_000

SCAN_CHAR_BUDGET = 12_000
SCAN_MAX_CHARS_PER_CMD = 2_500

# (subsystem, command, purpose)
SCAN_ITEMS: list[tuple[str, str, str]] = [
    ("service", "systemctl --failed --no-legend --no-pager 2>/dev/null",
     "failed systemd units"),
    ("service", "systemctl is-system-running 2>/dev/null; systemctl list-units --state=degraded --no-legend --no-pager 2>/dev/null | head -10",
     "overall unit health / degraded targets"),
    ("userspace", "journalctl -p err -b --no-pager -n 80 2>/dev/null | tail -80",
     "error-level journal entries this boot (userspace, not only kernel)"),
    ("crashes", "coredumpctl list --no-legend --no-pager 2>/dev/null | tail -15 || ls -lt /var/crash 2>/dev/null | head -10",
     "recently crashed programs"),
    ("disk-space", "df -h 2>/dev/null | grep -viE 'tmpfs|udev|devtmpfs' | head -15",
     "filesystem usage"),
    ("disk-space", "df -i 2>/dev/null | grep -viE 'tmpfs|udev|devtmpfs' | head -15",
     "inode usage"),
    ("performance", "uptime; cat /proc/loadavg; cat /proc/pressure/io /proc/pressure/cpu /proc/pressure/memory 2>/dev/null",
     "load average and PSI resource pressure"),
    ("performance", "ps -eo pid,pcpu,pmem,stat,comm --sort=-pcpu 2>/dev/null | head -8",
     "top CPU consumers"),
    ("package", "dpkg --audit 2>/dev/null | head -20; command -v dnf >/dev/null 2>&1 && dnf -q check 2>/dev/null | head -10; true",
     "broken/half-installed packages (dpkg/rpm)"),
    ("net-config", "ip -br addr 2>/dev/null; ip route 2>/dev/null | head -10; ip -d link 2>/dev/null | grep -c 'master bond' ; grep -v '^#' /etc/resolv.conf 2>/dev/null | head -5",
     "addresses, default routes, resolver config"),
]


def run_system_scan(executor: Executor) -> list[CollectedEvidence]:
    """Run all scan items, skipping tools that are missing; capped per item and overall."""
    results: list[CollectedEvidence] = []
    used = 0
    for _sub, cmd, why in SCAN_ITEMS:
        res = executor.run(cmd, timeout=45)
        if res.skip_reason:
            ev = CollectedEvidence(cmd, why, f"(skipped: {res.skip_reason})", "skipped")
        elif not res.usable:
            ev = CollectedEvidence(cmd, why, "(clean / no output)", "empty")
        else:
            ev = CollectedEvidence(cmd, why, _truncate(res.out, SCAN_MAX_CHARS_PER_CMD), "ok")
        used += len(ev.output)
        results.append(ev)
        if used >= SCAN_CHAR_BUDGET:
            break
    return results


def run_system_changes(executor: Executor, ts: datetime | None = None) -> list[CollectedEvidence]:
    """Recent system changes: reboots, kernel/package installs, suspend/resume,
    mounts, service restarts — and, when the log carries an absolute time, the
    non-kernel journal window around the first fault. Sudden faults are often
    preceded by a change; this is the evidence that makes that link checkable."""
    cmds: list[tuple[str, str]] = []
    if ts is not None:
        since = (ts - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        until = (ts + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        cmds.append((
            f"journalctl --no-pager -o short --since '{since}' --until '{until}' "
            f"2>/dev/null | grep -viE 'kernel:' | tail -40",
            f"non-kernel system events around the first fault ({since} ± window)"))
    cmds += [
        ("uptime -s; cat /proc/uptime 2>/dev/null", "boot time and uptime"),
        ("last -x 2>/dev/null | head -10", "recent reboots, shutdowns and runlevel changes"),
        ("stat -c '%y %n' /boot/vmlinuz-$(uname -r) 2>/dev/null; "
         "ls -lt /boot/vmlinuz-* 2>/dev/null | head -3",
         "kernel image install times (did the running kernel change recently?)"),
        ("tail -20 /var/log/apt/history.log 2>/dev/null", "recent package install/upgrade history"),
        ("journalctl --no-pager -o short -b --since '7 days ago' 2>/dev/null "
         "| grep -viE 'kernel:' "
         "| grep -iE 'upgrade|install|suspend|resume|sleep|mount|umount|restart|Started|Stopped' "
         "| tail -30", "recent user-space system changes this boot"),
    ]
    results: list[CollectedEvidence] = []
    used = 0
    for cmd, why in cmds:
        res = executor.run(cmd, timeout=30)
        if res.skip_reason:
            ev = CollectedEvidence(cmd, why, f"(skipped: {res.skip_reason})", "skipped")
        elif not res.usable:
            ev = CollectedEvidence(cmd, why, "(no output)", "empty")
        else:
            ev = CollectedEvidence(cmd, why, _truncate(res.out, CHANGES_MAX_CHARS_PER_CMD), "ok")
        used += len(ev.output)
        results.append(ev)
        if used >= CHANGES_CHAR_BUDGET:
            break
    return results


def run_cross_boot(executor: Executor, n: int) -> list[CollectedEvidence]:
    """Error-level kernel log of the previous n boots — shows whether a problem
    is a one-off or recurs across reboots."""
    results: list[CollectedEvidence] = []
    for i in range(1, max(1, min(n, 5)) + 1):
        cmd = f"journalctl -k -b -{i} --no-pager -p err 2>/dev/null | tail -40"
        res = executor.run(cmd, sudo=True, timeout=60)
        if res.skip_reason:
            ev = CollectedEvidence(cmd, f"error-level kernel log of boot -{i}",
                                   f"(skipped: {res.skip_reason})", "skipped")
        elif not res.usable:
            ev = CollectedEvidence(cmd, f"error-level kernel log of boot -{i}",
                                   "(no log for this boot)", "empty")
        else:
            ev = CollectedEvidence(cmd, f"error-level kernel log of boot -{i}",
                                   _truncate(res.out, SCAN_MAX_CHARS_PER_CMD), "ok")
        results.append(ev)
    return results


# Read-only drgn probe over the live kernel (/proc/kcore, needs root). Each
# block is guarded so one changed helper across kernel versions cannot break
# the whole probe.
_DRGN_SNIPPET = """
import sys
try:
    import drgn
except ImportError:
    print("MISSING_DRGN"); sys.exit(0)
prog = None
try:
    prog = drgn.program_from_kernel()
except Exception as e:
    print("cannot open live kernel:", e); sys.exit(0)
try:
    print("uptime_seconds:", int(prog.uptime_sec))
except Exception:
    pass
try:
    from drgn.helpers.linux.task import for_each_task
    n = 0
    for t in for_each_task(prog):
        try:
            if t.__state == 2:  # TASK_UNINTERRUPTIBLE (D state)
                n += 1
                if n <= 20:
                    print("D-state:", int(t.pid), bytes(t.comm.string_()).decode(errors="replace"))
        except Exception:
            continue
    print("total_D_state:", n)
except Exception as e:
    print("task walk failed:", e)
try:
    from drgn.helpers.linux import list_for_each_entry
except Exception:
    pass
print("done")
"""


def run_live_probe(executor: Executor) -> list[CollectedEvidence]:
    """Live kernel data-structure forensics via drgn (skips cleanly when drgn is
    not installed). Read-only: never writes to /dev/kmem, only /proc/kcore."""
    cmd = f"python3 <<'DRGN_PY'\n{_DRGN_SNIPPET}DRGN_PY\n"
    res = executor.run(cmd, sudo=True, timeout=90)
    why = "live kernel forensics via drgn: D-state tasks, uptime"
    if res.skip_reason:
        ev = CollectedEvidence("drgn live probe", why, f"(skipped: {res.skip_reason})", "skipped")
    elif not res.usable or "MISSING_DRGN" in res.out:
        ev = CollectedEvidence("drgn live probe", why,
                               "(drgn not installed or live kernel unavailable)", "empty")
    else:
        ev = CollectedEvidence("drgn live probe", why, _truncate(res.out, SCAN_MAX_CHARS_PER_CMD), "ok")
    return [ev]
