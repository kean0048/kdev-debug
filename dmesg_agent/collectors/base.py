"""采集结果的统一容器与共用采集管道(经 Executor 执行)。"""

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


# (context key, 命令) —— 缺失命令容错跳过
CONTEXT_COMMANDS: list[tuple[str, str]] = [
    ("kernel_version", "uname -r"),
    ("distro", "cat /etc/os-release | head -5"),
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
    """经执行器采集内核日志与系统上下文(local/ssh 共用)。"""
    cmds = _DMESG_CMDS.get(boot, _DMESG_CMDS["now"])
    dmesg_text = None
    for _label, cmd in cmds:
        r = executor.run(cmd, timeout=60)
        if r.usable:
            dmesg_text = r.out
            break
    if not dmesg_text:
        hint = (
            "读取上一次启动的日志需要 journalctl(建议 sudo 运行)"
            if boot == "previous"
            else "读取内核日志可能需要 root 权限(sudo dmesg),或用 --file 分析已导出的日志文件"
        )
        raise CollectError(f"无法获取内核日志:{hint}")

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
