"""vmcore analysis via the crash utility (optional, deterministic, read-only).

The agent never types interactive crash commands: it writes a fixed batch
script of whitelisted commands, runs `crash -i script vmlinux vmcore` once and
feeds the output into the same evidence corpus as everything else. Missing
crash / missing vmlinux / unreadable dump all degrade to a skipped evidence
entry with the exact reason (same pattern as the drgn live probe).

vmlinux debuginfo is NOT downloaded or guessed; the caller supplies it
(--vmlinux or DMESG_AGENT_VMLINUX), matching the README's hotkdump/debuginfod
note that getting vmlinux is a separate concern.
"""

from __future__ import annotations

import os
import shutil
import tempfile

from .executors import Executor
from .playbooks import CollectedEvidence, _truncate

VMCORE_MAX_CHARS = 60_000

# fixed, read-only crash batch; each line is a standard crash command
_CRASH_SCRIPT = """log
sys
bt
ps
mod -t
net -i
mount
dev -d
quit
"""


def analyze_vmcore(executor: Executor, vmcore: str, vmlinux: str | None) -> CollectedEvidence:
    why = "vmcore post-mortem via crash: dmesg tail, panic context, backtraces, tasks, modules"
    if not os.path.isfile(vmcore):
        return CollectedEvidence("crash", why, f"(vmcore not found: {vmcore})", "skipped")
    if shutil.which("crash") is None:
        return CollectedEvidence("crash", why,
                                 "(crash utility not installed; apt/dnf install crash)", "skipped")
    if not vmlinux:
        return CollectedEvidence("crash", why,
                                 "(no vmlinux debuginfo given; pass --vmlinux or set "
                                 "DMESG_AGENT_VMLINUX)", "skipped")
    if not os.path.isfile(vmlinux):
        return CollectedEvidence("crash", why, f"(vmlinux not found: {vmlinux})", "skipped")

    fd, script = tempfile.mkstemp(prefix="dmesg-agent-crash-", suffix=".cmd")
    with os.fdopen(fd, "w") as f:
        f.write(_CRASH_SCRIPT)
    # sudo -S reads the password before sh starts, so redirect stdin from the
    # script file to avoid the batch script being consumed by sudo.
    cmd = f"crash -i {script} {vmlinux} {vmcore} </dev/null"
    res = executor.run(cmd, sudo=True, timeout=600)
    try:
        os.unlink(script)
    except OSError:
        pass

    if res.skip_reason:
        return CollectedEvidence("crash batch", why, f"(skipped: {res.skip_reason})", "skipped")
    out = res.out or res.err
    if not out.strip():
        return CollectedEvidence("crash batch", why, "(crash produced no output)", "empty")
    return CollectedEvidence("crash batch", why, _truncate(out, VMCORE_MAX_CHARS), "ok")
