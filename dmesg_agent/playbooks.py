"""声明式采集 playbook(借鉴 sashiko 的确定性子系统路由 + 预算化 prefetch)。

安全边界:命令白名单在本文件声明,模型只能"建议"不能"执行"——日志内容中
即使注入指令,也无法让 agent 运行白名单以外的命令。

prefetch(初始分析前):只跑无权限命令,按 triage 命中的签名确定性选择,消除模型盲猜。
deep(深度核验):针对 inconcern 问题,跑该子系统更深的命令(可含 sudo,触发密码框)。
"""

from __future__ import annotations

from dataclasses import dataclass

from .executors import Executor

PREFETCH_CHAR_BUDGET = 20_000   # 预取上下文总量上限(字符)
DEEP_MAX_CMDS_PER_CONCERN = 6   # 每个待验证问题最多采集命令数
DEEP_MAX_CHARS_PER_CMD = 3_000  # 单条输出截断


@dataclass(frozen=True)
class CollectCmd:
    cmd: str
    why: str
    sudo: bool = False


# triage 签名 → 子系统(确定性路由,不让模型猜)
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
}

# concern 文本(模型输出)→ 子系统关键词路由
SUBSYSTEM_KEYWORDS = {
    "memory": ["内存", "memory", "oom", "swap", "交换", "malloc", "页"],
    "storage": ["存储", "disk", "nvme", "sata", "ata", "i/o", "io ", "block", "ext4", "xfs", "btrfs", "文件", "jbd2", "磁盘", "sector"],
    "gpu": ["gpu", "amdgpu", "nvidia", "nouveau", "drm", "显存", "ring", "图形"],
    "thermal": ["温", "thermal", "throttl", "overheat", "散热", "风扇"],
    "network": ["网络", "eth", "wlan", "wifi", "tcp ", "网卡", "interface", "link flap", "网络链路"],
    "locking": ["锁", "lock", "deadlock", "watchdog", "hung", "stuck", "调度", "cpu#", "soft lockup", "rcu"],
    "security": ["安全", "audit", "apparmor", "selinux", "avc", "denied", "权限", "seccomp"],
    "usb": ["usb", "hid", "外设"],
    "firmware": ["固件", "firmware", "bios", "efi", "acpi", "microcode"],
    "power": ["电源", "power", "suspend", "resume", "acpi", "睡眠", "待机", "battery"],
    "hardware": ["硬件", "hardware", "mce", "machine check", "edac", "ecc", "内存条", "pcie", "aer", "主板"],
}

# 全局预取(无 sudo,任何分析都带上)
GLOBAL_PREFETCH: list[CollectCmd] = [
    CollectCmd("uname -a", "内核与主机基本信息"),
    CollectCmd("uptime", "负载与运行时长"),
    CollectCmd("free -h", "内存/交换总览"),
    CollectCmd("ps aux --sort=-%mem | head -12", "当前内存占用 Top 进程"),
    CollectCmd("dmesg --level=emerg,alert,crit,err 2>/dev/null | tail -60", "最近 error 级日志"),
]

PREFETCH_BY_SUBSYSTEM: dict[str, list[CollectCmd]] = {
    "memory": [
        CollectCmd("cat /proc/meminfo | head -30", "meminfo 细项(脏页/空闲/提交)"),
        CollectCmd("cat /proc/buddyinfo 2>/dev/null", "伙伴系统碎片化程度"),
        CollectCmd("journalctl -k --no-pager 2>/dev/null | grep -icE 'out of memory|oom-kill' || true", "OOM 发生次数"),
    ],
    "storage": [
        CollectCmd("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,ROTA,MODEL 2>/dev/null", "块设备清单"),
        CollectCmd("cat /sys/block/*/queue/scheduler 2>/dev/null", "I/O 调度器设置"),
        CollectCmd("df -h 2>/dev/null | head -15", "文件系统容量"),
    ],
    "gpu": [
        CollectCmd("lspci -nnk 2>/dev/null | grep -iA3 -E 'vga|3d|display'", "显卡型号与驱动"),
    ],
    "thermal": [
        CollectCmd("sensors 2>/dev/null | head -40 || cat /sys/class/thermal/thermal_zone*/type /sys/class/thermal/thermal_zone*/temp 2>/dev/null | paste - -", "当前温度"),
    ],
    "network": [
        CollectCmd("ip -s link show 2>/dev/null | head -60", "网卡收发/错包计数"),
    ],
    "locking": [
        CollectCmd("ps -eo stat,pid,comm 2>/dev/null | awk '$1 ~ /^D/' | head -20", "当前 D 状态进程"),
        CollectCmd("cat /proc/pressure/* 2>/dev/null", "PSI 资源压力指标"),
    ],
    "hardware": [
        CollectCmd("lspci -nn 2>/dev/null | head -40", "PCI 设备总览"),
    ],
    "usb": [
        CollectCmd("lsusb 2>/dev/null", "USB 设备树"),
    ],
    "firmware": [
        CollectCmd("efibootmgr -v 2>/dev/null | head -20", "EFI 启动项"),
    ],
    "power": [
        CollectCmd("cat /sys/power/state 2>/dev/null", "支持的睡眠状态"),
    ],
    "security": [],
}

# 深度采集:更专业、可能需 root —— 仅对 inconclusive 问题按子系统执行
DEEP_BY_SUBSYSTEM: dict[str, list[CollectCmd]] = {
    "memory": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'out of memory|oom-kill|killed process' | tail -60", "历史 OOM 完整上下文", sudo=True),
        CollectCmd("ps -eo pid,user,rss,vmess,stat,comm --sort=-rss | head -20", "进程内存明细"),
    ],
    "storage": [
        CollectCmd("for d in $(lsblk -dn -o NAME 2>/dev/null | head -6); do echo \"== /dev/$d\"; smartctl -H -A /dev/$d 2>&1 | grep -iE 'overall health|Reallocated|Pending Sector|Uncorrect|Wear Leveling|Percentage Used|Temperature|Power On Hours'; done", "所有盘 SMART 健康与关键属性", sudo=True),
        CollectCmd("journalctl -k --no-pager | grep -iE 'blk_update_request|I/O error|nvme[0-9]|ata[0-9]+\\.[0-9]|EXT4-fs error|XFS.*error' | tail -80", "该盘相关全部历史 I/O 错误", sudo=True),
    ],
    "gpu": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'amdgpu|nvidia|drm|nouveau|Xid' | tail -120", "GPU 驱动历史日志", sudo=True),
        CollectCmd("cat /sys/class/drm/card*/device/gpu_busy_percent 2>/dev/null", "GPU 当前忙碌度", sudo=True),
    ],
    "thermal": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'thermal|temperature|throttl|fan' | tail -60", "历史温度/降频事件", sudo=True),
        CollectCmd("cat /sys/class/hwmon/*/temp*_input 2>/dev/null", "hwmon 原始温度读数"),
    ],
    "network": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'link is (down|up)|NIC Link|link flap' | tail -60", "链路 up/down 历史(判断抖动频率)", sudo=True),
        CollectCmd("for i in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -6); do echo \"== $i\"; ethtool -S $i 2>/dev/null | grep -iE 'err|drop|discard|fifo|crc' | head -12; done", "网卡错包/丢包计数"),
    ],
    "locking": [
        CollectCmd("journalctl -k --no-pager | grep -B2 -A25 -iE 'soft lockup|blocked for more than|hung_task' | tail -120", "lockup/hung task 的完整 call trace", sudo=True),
        CollectCmd("cat /proc/1/stack /proc/pressure/io 2>/dev/null", "init 栈与 IO 压力"),
    ],
    "security": [
        CollectCmd("journalctl --no-pager | grep -iE 'avc: *denied|apparmor.*DENIED' | tail -60", "完整拒绝记录(判断策略缺口)", sudo=True),
    ],
    "usb": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'usb .*(disconnect|reset|error|enumerate)' | tail -60", "USB 插拔/枚举历史", sudo=True),
    ],
    "firmware": [
        CollectCmd("dmidecode -t bios -t system 2>/dev/null | head -40", "BIOS/主板版本(查已知 errata)", sudo=True),
        CollectCmd("journalctl -k --no-pager | grep -iE 'firmware|microcode' | tail -40", "固件加载历史", sudo=True),
    ],
    "power": [
        CollectCmd("journalctl --no-pager -b -1 2>/dev/null | tail -80", "上次关机/睡眠前的日志", sudo=True),
    ],
    "hardware": [
        CollectCmd("journalctl -k --no-pager | grep -iE 'mce|machine check|edac|aer' | tail -80", "硬件错误完整记录", sudo=True),
        CollectCmd("edac-util -s 2>/dev/null || ras-mc-ctl --summary 2>/dev/null", "内存 ECC 错误计数", sudo=True),
    ],
}


def subsystems_from_signatures(names: set[str]) -> set[str]:
    return {SIGNATURE_TO_SUBSYSTEM[s] for s in names if s in SIGNATURE_TO_SUBSYSTEM}


def subsystems_from_text(text: str) -> set[str]:
    text = text.lower()
    return {sub for sub, kws in SUBSYSTEM_KEYWORDS.items()
            if any(k.lower() in text for k in kws)}


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + "\n... (截断) ..."


class CollectedEvidence:
    __slots__ = ("cmd", "why", "output", "status")

    def __init__(self, cmd: str, why: str, output: str, status: str):
        self.cmd, self.why, self.output, self.status = cmd, why, output, status

    def as_dict(self) -> dict:
        return {"cmd": self.cmd, "why": self.why, "output": self.output, "status": self.status}


def run_prefetch(executor: Executor, signature_names: set[str]) -> list[CollectedEvidence]:
    """确定性预取:全局 + 按 triage 签名选子系统,只跑无 sudo 命令,限预算。"""
    cmds: list[CollectCmd] = list(GLOBAL_PREFETCH)
    for sub in sorted(subsystems_from_signatures(signature_names)):
        cmds.extend(PREFETCH_BY_SUBSYSTEM.get(sub, []))
    return _run(executor, cmds, PREFETCH_CHAR_BUDGET, skip_sudo=True)


def run_deep(executor: Executor, concern_text: str) -> list[CollectedEvidence]:
    """深度采集:按 concern 文本路由子系统,取匹配 playbook(含 sudo),限量。"""
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
            ev = CollectedEvidence(c.cmd, c.why, f"(跳过: {res.skip_reason})", "skipped")
        elif not res.usable:
            ev = CollectedEvidence(c.cmd, c.why, "(无输出或不可用)", "empty")
        else:
            out = _truncate(res.out, DEEP_MAX_CHARS_PER_CMD)
            ev = CollectedEvidence(c.cmd, c.why, out, "ok")
        used += len(ev.output)
        results.append(ev)
        if used >= budget:
            break
    return results
