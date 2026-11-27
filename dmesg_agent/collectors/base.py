"""Unified container for collected data plus the shared collection pipeline (run via an Executor)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import CollectError


@dataclass
class RawBundle:
    dmesg_text: str
    kernel_version: str = "unknown"
    distro: str = "unknown"
    extra_context: dict = field(default_factory=dict)
    source: str = "file"


# (context key, command) — missing commands are tolerated and skipped
CONTEXT_COMMANDS: list[tuple[str, str]] = [
    ("kernel_version", "uname -r"),
    ("distro", "cat /etc/os-release | head -5"),
    ("machine_id", "cat /etc/machine-id 2>/dev/null || hostname"),
    ("cpu", "nproc"),
    ("mem", "free -h | head -3"),
    ("modules", "lsmod | awk 'NR>1{print $1}' | sort | paste -sd' ' -"),
    ("pci", "lspci -nnk 2>/dev/null | head -120"),
]

_DMESG_CMDS: dict[str, list[tuple[str, str]]] = {
    "now": [
        ("dmesg -T", "dmesg -T --color=never"),
        ("dmesg", "dmesg"),
        ("journalctl", "journalctl -k --no-pager -o short"),
        ("kern.log", "cat /var/log/kern.log"),
        ("dmesg-file", "cat /var/log/dmesg"),
    ],
    "previous": [
        ("journalctl -b -1", "journalctl -k -b -1 --no-pager -o short"),
    ],
}


def parse_os_release(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    first = text.strip().splitlines()
    return first[0] if first else "unknown"


def collect_via(executor, boot: str = "now") -> RawBundle:
    """Collect the kernel log and system context via an executor (shared by local/ssh)."""
    cmds = _DMESG_CMDS.get(boot, _DMESG_CMDS["now"])
    dmesg_text = None
    # pass 1 unprivileged; pass 2 via sudo (triggers the password prompt only
    # if needed — journalctl -b -1 and dmesg are read-only, whitelisted commands)
    for sudo in (False, True):
        for _label, cmd in cmds:
            r = executor.run(cmd, sudo=sudo, timeout=60)
            if r.usable:
                dmesg_text = r.out
                break
        if dmesg_text:
            break
    if not dmesg_text:
        hint = (
            "reading the previous boot's log requires journalctl with root "
            "(sudo prompt was declined or unavailable); or use --file"
            if boot == "previous"
            else "reading the kernel log may need root (sudo prompt was declined or unavailable); "
                 "or use --file to analyze an exported log"
        )
        raise CollectError(f"could not obtain the kernel log: {hint}")

    extra: dict[str, str] = {}
    kernel_version = "unknown"
    distro = "unknown"
    for key, cmd in CONTEXT_COMMANDS:
        r = executor.run(cmd)
        if not r.usable:
            continue
        if key == "kernel_version":
            kernel_version = r.out.splitlines()[0].strip()
        elif key == "distro":
            distro = parse_os_release(r.out)
        else:
            extra[key] = r.out
    return RawBundle(
        dmesg_text=dmesg_text,
        kernel_version=kernel_version,
        distro=distro,
        extra_context=extra,
        source=f"{executor.name}({boot})",
    )
