"""Declarative collection playbooks (borrowed from sashiko: deterministic subsystem routing + budgeted prefetch).

Security boundary: every runnable command is declared in this file's whitelist.
The model can only "suggest" — never "execute". Even instructions injected via
log content cannot make the agent run anything outside the whitelist.

prefetch (before the first analysis): runs unprivileged commands only, chosen
deterministically by the triage signatures that matched, to stop the model from
guessing blind.
deep (verification): for a concern, runs deeper per-subsystem commands (may use
sudo and trigger a password prompt).
"""

from __future__ import annotations

from dataclasses import dataclass

from .executors import Executor

PREFETCH_CHAR_BUDGET = 20_000   # total cap for prefetched context (characters)
DEEP_MAX_CMDS_PER_CONCERN = 6   # max collection commands per open question
DEEP_MAX_CHARS_PER_CMD = 3_000  # per-command output truncation


@dataclass(frozen=True)
class CollectCmd:
    cmd: str
    why: str
    sudo: bool = False


# triage signature → subsystem (deterministic routing; the model doesn't choose)
SIGNATURE_TO_SUBSYSTEM = {
    "oom": "memory",
    "nvme": "storage", "ata": "storage", "io-error": "storage", "fs-error": "storage",
    "gpu-amd": "gpu", "gpu-nvidia": "gpu", "gpu-nouveau": "gpu",
    "thermal": "thermal",
    "net-link": "network", "net-ddos": "network",
    "lockup": "locking", "hung-task": "locking", "call-trace": "locking",
    "mce": "hardware", "edac": "hardware", "pcie-aer": "hardware", "fault": "hardware",
    "usb": "usb",
    "firmware": "firmware", "power": "power",
    "security": "security",
    "systemd-failed": "service", "app-crash": "userspace",
    "disk-space": "disk-space",
}

# concern text (model output) → subsystem keyword routing
SUBSYSTEM_KEYWORDS = {
    "memory": ["memory", "oom", "swap", "malloc", "page", "allocation"],
    "storage": ["storage", "disk", "nvme", "sata", "ata", "i/o", "io ", "block", "ext4", "xfs", "btrfs", "file system", "jbd2", "sector"],
    "gpu": ["gpu", "amdgpu", "nvidia", "nouveau", "drm", "vram", "ring", "graphics", "display"],
    "thermal": ["thermal", "temperature", "throttl", "overheat", "cooling", "fan"],
    "network": ["network", "eth", "wlan", "wifi", "tcp ", "nic", "interface", "link flap", "link"],
    "locking": ["lock", "deadlock", "watchdog", "hung", "stuck", "schedul", "cpu#", "soft lockup", "rcu"],
    "security": ["security", "audit", "apparmor", "selinux", "avc", "denied", "permission", "seccomp"],
    "usb": ["usb", "hid", "peripheral"],
    "firmware": ["firmware", "bios", "efi", "acpi", "microcode"],
    "power": ["power", "suspend", "resume", "acpi", "sleep", "standby", "battery"],
    "hardware": ["hardware", "mce", "machine check", "edac", "ecc", "dimm", "pcie", "aer", "motherboard"],
    "service": ["service", "systemd", "unit", "daemon", "socket", "timer", "mount unit"],
    "userspace": ["application", "app", "crash", "core dump", "coredump", "segfault", "abort", "library", "python", "java"],
    "disk-space": ["space", "full", "enospc", "no space", "inode", "quota", "log rotation"],
    "package": ["package", "dpkg", "apt", "dnf", "rpm", "dependency", "broken", "half-installed", "upgrade"],
    "net-config": ["address", "route", "gateway", "dns", "resolver", "dhcp", "configuration", "nameserver", "bond"],
    "performance": ["slow", "latency", "load", "pressure", "backlog", "congest", "throughput", "iowait"],
}

# global prefetch (no sudo; always included)
GLOBAL_PREFETCH: list[CollectCmd] = [
    CollectCmd("uname -a", "kernel and host basics"),
    CollectCmd("uptime", "load and uptime"),
    CollectCmd("free -h", "memory/swap overview"),
    CollectCmd("ps aux --sort=-%mem | head -12", "top memory consumers right now"),
    CollectCmd("dmesg --level=emerg,alert,crit,err 2>/dev/null | tail -60", "most recent error-level messages"),
]

PREFETCH_BY_SUBSYSTEM: dict[str, list[CollectCmd]] = {
    "memory": [
        CollectCmd("cat /proc/meminfo | head -30", "meminfo detail (dirty/free/commit)"),
        CollectCmd("cat /proc/buddyinfo 2>/dev/null", "buddy-system fragmentation"),
        CollectCmd("journalctl -k --no-pager 2>/dev/null | grep -icE 'out of memory|oom-kill' || true", "OOM occurrence count"),
    ],
    "storage": [
        CollectCmd("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,ROTA,MODEL 2>/dev/null", "block device inventory"),
        CollectCmd("cat /sys/block/*/queue/scheduler 2>/dev/null", "I/O scheduler settings"),
        CollectCmd("df -h 2>/dev/null | head -15", "file system capacity"),
    ],
    "gpu": [
        CollectCmd("lspci -nnk 2>/dev/null | grep -iA3 -E 'vga|3d|display'", "GPU model and driver"),
    ],
    "thermal": [
        CollectCmd("sensors 2>/dev/null | head -40 || cat /sys/class/thermal/thermal_zone*/type /sys/class/thermal/thermal_zone*/temp 2>/dev/null | paste - -", "current temperatures"),
    ],
    "network": [
        CollectCmd("ip -s link show 2>/dev/null | head -60", "NIC tx/rx and error counters"),
    ],
    "locking": [
        CollectCmd("ps -eo stat,pid,comm 2>/dev/null | awk '$1 ~ /^D/' | head -20", "processes currently in D state"),
        CollectCmd("cat /proc/pressure/* 2>/dev/null", "PSI resource pressure"),
    ],
    "hardware": [
        CollectCmd("lspci -nn 2>/dev/null | head -40", "PCI device overview"),
    ],
    "usb": [
        CollectCmd("lsusb 2>/dev/null", "USB device tree"),
    ],
    "firmware": [
        CollectCmd("efibootmgr -v 2>/dev/null | head -20", "EFI boot entries"),
    ],
    "power": [
        CollectCmd("cat /sys/power/state 2>/dev/null", "supported sleep states"),
    ],
    "security": [],
    "service": [
        CollectCmd("systemctl --failed --no-legend --no-pager 2>/dev/null", "failed units"),
        CollectCmd("systemctl is-system-running 2>/dev/null", "overall system state"),
    ],
    "userspace": [
        CollectCmd("journalctl -p err -b --no-pager -n 40 2>/dev/null", "recent error-level journal lines"),
    ],
    "disk-space": [
        CollectCmd("df -h 2>/dev/null | grep -viE 'tmpfs|udev' | head -12", "filesystem usage"),
        CollectCmd("du -xsh /var/log 2>/dev/null", "log directory size"),
    ],
    "package": [
        CollectCmd("dpkg --audit 2>/dev/null | head -15 || true", "dpkg consistency"),
    ],
    "net-config": [
        CollectCmd("ip -br addr 2>/dev/null; ip route 2>/dev/null | head -8", "addresses and routes"),
    ],
    "performance": [
        CollectCmd("cat /proc/pressure/io /proc/pressure/cpu 2>/dev/null", "IO/CPU pressure stall"),
        CollectCmd("vmstat 1 3 2>/dev/null", "run-queue / iowait sampling"),
    ],
}

# deep collection: more specialized, may need root — run per subsystem for inconclusive concerns only
DEEP_BY_SUBSYSTEM: dict[str, list[CollectCmd]] = {
    "memory": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'out of memory|oom-kill|killed process' | tail -60", "full context of historical OOM events", sudo=True),
        CollectCmd("ps -eo pid,user,rss,vmess,stat,comm --sort=-rss | head -20", "per-process memory detail"),
    ],
    "storage": [
        CollectCmd("for d in $(lsblk -dn -o NAME 2>/dev/null | head -6); do echo \"== /dev/$d\"; smartctl -H -A /dev/$d 2>&1 | grep -iE 'overall health|Reallocated|Pending Sector|Uncorrect|Wear Leveling|Percentage Used|Temperature|Power On Hours'; done", "SMART health and key attributes for all disks", sudo=True),
        CollectCmd("journalctl -k --no-pager | grep -iE 'blk_update_request|I/O error|nvme[0-9]|ata[0-9]+\\.[0-9]|EXT4-fs error|XFS.*error' | tail -80", "all historical I/O errors for this disk", sudo=True),
    ],
    "gpu": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'amdgpu|nvidia|drm|nouveau|Xid' | tail -120", "GPU driver history", sudo=True),
        CollectCmd("cat /sys/class/drm/card*/device/gpu_busy_percent 2>/dev/null", "current GPU busy percent", sudo=True),
    ],
    "thermal": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'thermal|temperature|throttl|fan' | tail -60", "historical over-temp/throttling events", sudo=True),
        CollectCmd("cat /sys/class/hwmon/*/temp*_input 2>/dev/null", "raw hwmon temperature readings"),
    ],
    "network": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'link is (down|up)|NIC Link|link flap' | tail -60", "link up/down history (flap frequency)", sudo=True),
        CollectCmd("for i in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -6); do echo \"== $i\"; ethtool -S $i 2>/dev/null | grep -iE 'err|drop|discard|fifo|crc' | head -12; done", "NIC error/drop counters"),
    ],
    "locking": [
        CollectCmd("journalctl -k --no-pager | grep -B2 -A25 -iE 'soft lockup|blocked for more than|hung_task' | tail -120", "full call traces of lockup/hung-task events", sudo=True),
        CollectCmd("cat /proc/1/stack /proc/pressure/io 2>/dev/null", "init stack and I/O pressure"),
    ],
    "security": [
        CollectCmd("journalctl --no-pager | grep -iE 'avc: *denied|apparmor.*DENIED' | tail -60", "full denial records (policy gap assessment)", sudo=True),
    ],
    "usb": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'usb .*(disconnect|reset|error|enumerate)' | tail -60", "USB disconnect/reset/enumeration history", sudo=True),
    ],
    "firmware": [
        CollectCmd("dmidecode -t bios -t system 2>/dev/null | head -40", "BIOS/board revision (known-errata check)", sudo=True),
        CollectCmd("journalctl -k --no-pager | grep -iE 'firmware|microcode' | tail -40", "firmware loading history", sudo=True),
    ],
    "power": [
        CollectCmd("journalctl --no-pager -b -1 2>/dev/null | tail -80", "log just before the last shutdown/suspend", sudo=True),
    ],
    "hardware": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'mce|machine check|edac|aer' | tail -80", "full hardware error records", sudo=True),
        CollectCmd("edac-util -s 2>/dev/null || ras-mc-ctl --summary 2>/dev/null", "memory ECC error counts", sudo=True),
    ],
    "service": [
        CollectCmd("for u in $(systemctl --failed --no-legend --no-pager 2>/dev/null | awk \'{print $2}\' | head -4); do echo \"== $u\"; systemctl status --no-pager -n 30 $u 2>/dev/null; done", "status and last logs of failed units", sudo=True),
        CollectCmd("journalctl -b --no-pager -p err --exclude-priority=warning 2>/dev/null | tail -100", "all error-priority journal lines this boot", sudo=True),
    ],
    "userspace": [
        CollectCmd("coredumpctl list --no-legend --no-pager 2>/dev/null | tail -10", "recent core dumps", sudo=True),
        CollectCmd("coredumpctl info $(coredumpctl list --no-legend --no-pager 2>/dev/null | tail -1 | awk \'{print $NF}\') 2>/dev/null | head -60", "details of the newest core dump", sudo=True),
        CollectCmd("journalctl -b --no-pager | grep -iE 'segfault|core dumped|aborted|oom-kill.*killed process' | tail -60", "crash-related journal history", sudo=True),
    ],
    "disk-space": [
        CollectCmd("df -i 2>/dev/null | grep -viE 'tmpfs|udev'", "inode usage"),
        CollectCmd("du -xsh /var/log /var/cache /home /tmp 2>/dev/null | sort -h | tail -8", "largest space consumers", sudo=True),
        CollectCmd("journalctl --disk-usage 2>/dev/null", "journal disk usage"),
        CollectCmd("find /var/log -xdev -type f -size +100M -printf '%s %p\\n' 2>/dev/null | sort -rn | head -8", "largest log files", sudo=True),
    ],
    "package": [
        CollectCmd("dpkg --audit 2>&1 | head -30 || true", "full dpkg audit output"),
        CollectCmd("apt-get check 2>&1 | tail -10 || dnf -q check 2>&1 | tail -10 || true", "dependency resolution check"),
        CollectCmd("journalctl -b --no-pager | grep -iE 'dpkg|apt|dnf|rpm' | tail -40", "package manager activity this boot", sudo=True),
    ],
    "net-config": [
        CollectCmd("networkctl status 2>/dev/null | head -40 || nmcli -f DEVICE,STATE,CONNECTION fields device 2>/dev/null", "network manager state"),
        CollectCmd("resolvectl status 2>/dev/null | head -25 || cat /etc/resolv.conf 2>/dev/null", "DNS resolution configuration"),
        CollectCmd("ip -s link show 2>/dev/null | head -60", "per-interface counters"),
    ],
    "performance": [
        CollectCmd("pidstat 1 3 2>/dev/null | tail -25 || top -b -n 1 | head -25", "per-task CPU sampling"),
        CollectCmd("iotop -b -n 1 -o 2>/dev/null | head -15 || cat /proc/pressure/io 2>/dev/null", "top I/O consumers", sudo=True),
        CollectCmd("vmstat 1 5 2>/dev/null", "run-queue/IO/swap sampling over 5s"),
    ],
}


def subsystems_from_signatures(names: set[str]) -> set[str]:
    return {SIGNATURE_TO_SUBSYSTEM[s] for s in names if s in SIGNATURE_TO_SUBSYSTEM}


def subsystems_from_text(text: str) -> set[str]:
    text = text.lower()
    return {sub for sub, kws in SUBSYSTEM_KEYWORDS.items()
            if any(k.lower() in text for k in kws)}


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + "\n... (truncated) ..."


class CollectedEvidence:
    __slots__ = ("cmd", "why", "output", "status")

    def __init__(self, cmd: str, why: str, output: str, status: str):
        self.cmd, self.why, self.output, self.status = cmd, why, output, status

    def as_dict(self) -> dict:
        return {"cmd": self.cmd, "why": self.why, "output": self.output, "status": self.status}


def run_prefetch(executor: Executor, signature_names: set[str]) -> list[CollectedEvidence]:
    """Deterministic prefetch: global set + subsystems picked by triage signatures;
    unprivileged commands only, within a character budget."""
    cmds: list[CollectCmd] = list(GLOBAL_PREFETCH)
    for sub in sorted(subsystems_from_signatures(signature_names)):
        cmds.extend(PREFETCH_BY_SUBSYSTEM.get(sub, []))
    return _run(executor, cmds, PREFETCH_CHAR_BUDGET, skip_sudo=True)


def run_deep(executor: Executor, concern_text: str) -> list[CollectedEvidence]:
    """Deep collection: route the concern text to subsystems, run the matching
    playbooks (sudo allowed), capped in count."""
    subs = subsystems_from_text(concern_text)
    cmds: list[CollectCmd] = []
    seen: set[str] = set()
    for sub in sorted(subs):
        for c in DEEP_BY_SUBSYSTEM.get(sub, []):
            if c.cmd not in seen:
                seen.add(c.cmd)
                cmds.append(c)
    return _run(executor, cmds[:DEEP_MAX_CMDS_PER_CONCERN],
                DEEP_MAX_CMDS_PER_CONCERN * DEEP_MAX_CHARS_PER_CMD, skip_sudo=False)


def _run(executor: Executor, cmds: list[CollectCmd], budget: int, skip_sudo: bool) -> list[CollectedEvidence]:
    results: list[CollectedEvidence] = []
    used = 0
    for c in cmds:
        if skip_sudo and c.sudo:
            continue
        res = executor.run(c.cmd, sudo=c.sudo)
        if res.skip_reason:
            ev = CollectedEvidence(c.cmd, c.why, f"(skipped: {res.skip_reason})", "skipped")
        elif not res.usable:
            ev = CollectedEvidence(c.cmd, c.why, "(no output or unusable)", "empty")
        else:
            out = _truncate(res.out, DEEP_MAX_CHARS_PER_CMD)
            ev = CollectedEvidence(c.cmd, c.why, out, "ok")
        used += len(ev.output)
        results.append(ev)
        if used >= budget:
            break
    return results
