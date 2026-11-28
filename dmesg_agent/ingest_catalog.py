"""Built-in ingestion catalog for `dmesg-agent learn --auto`.

The point is coverage without per-user commands: one targeted query per
high-value fault class/subsystem, run against lore (patches and threads carry
``Fixes:``/commit trailers) and the public Bugzilla. Entries use the same L1
subsystem names as diagnosis; `max_mb` bounds one lore download (auto splits
each query into per-year windows, newest first), `bugzilla` adds a
kernel.org tracker query, `tracker_limit` bounds its detail fetches.

`learn --auto` walks this list in order under a global download budget and the
normal extract/dedup pipeline, so repeated or `--loop` runs fill gaps instead
of re-paying for already-known records.
"""

from __future__ import annotations

DEFAULT_TRACKER_BASE = "https://bugzilla.kernel.org"
DEFAULT_MAX_MB = 32
DEFAULT_TRACKER_LIMIT = 8

CATALOG: list[dict] = [
    # storage
    {"id": "nvme-timeout", "subsystem": "storage",
     "lore": "nvme timeout reset controller", "max_mb": 48,
     "bugzilla": "nvme timeout"},
    {"id": "nvmet-tcp", "subsystem": "storage",
     "lore": "nvmet-tcp TLS handshake timeout", "max_mb": 24},
    {"id": "ata-error", "subsystem": "storage",
     "lore": "ata failed command error", "max_mb": 48,
     "bugzilla": "ata error"},
    {"id": "sata-link", "subsystem": "storage",
     "lore": "SATA link down hardreset", "max_mb": 32},
    {"id": "scsi-medium", "subsystem": "storage",
     "lore": "SCSI Medium Error", "max_mb": 32},
    {"id": "ext4-error", "subsystem": "storage",
     "lore": "EXT4-fs error", "max_mb": 32, "bugzilla": "ext4 error"},
    {"id": "xfs-corruption", "subsystem": "storage",
     "lore": "XFS corruption", "max_mb": 32, "bugzilla": "xfs corruption"},
    {"id": "btrfs-error", "subsystem": "storage",
     "lore": "BTRFS error", "max_mb": 32, "bugzilla": "btrfs error"},
    {"id": "md-raid", "subsystem": "storage",
     "lore": "md raid failure", "max_mb": 32},
    {"id": "block-io", "subsystem": "storage",
     "lore": "I/O error blk_update_request", "max_mb": 32},
    # memory
    {"id": "oom-kill", "subsystem": "memory",
     "lore": "Out of memory Killed process", "max_mb": 48,
     "bugzilla": "out of memory killed process"},
    {"id": "page-alloc", "subsystem": "memory",
     "lore": "page allocation failure order", "max_mb": 32},
    {"id": "kasan", "subsystem": "memory",
     "lore": "KASAN use-after-free", "max_mb": 32},
    # gpu
    {"id": "amdgpu-ring", "subsystem": "gpu",
     "lore": "amdgpu ring timeout", "max_mb": 48,
     "bugzilla": "amdgpu ring timeout"},
    {"id": "i915-hang", "subsystem": "gpu",
     "lore": "i915 GPU hang", "max_mb": 48, "bugzilla": "i915 gpu hang"},
    {"id": "xe-hang", "subsystem": "gpu",
     "lore": "xe GPU hang", "max_mb": 32},
    {"id": "nvrm-error", "subsystem": "gpu",
     "lore": "NVRM NV_ERR_NO_MEMORY", "max_mb": 32,
     "bugzilla": "NVRM NV_ERR"},
    # firmware / usb / network
    {"id": "iwlwifi-firmware", "subsystem": "firmware",
     "lore": 'iwlwifi "no suitable firmware found"', "max_mb": 16,
     "bugzilla": "iwlwifi firmware"},
    {"id": "iwlwifi-be200", "subsystem": "firmware",
     "lore": "iwlwifi BE200 firmware", "max_mb": 16,
     "bugzilla": "iwlwifi BE200 firmware"},
    {"id": "xhci-reset", "subsystem": "usb",
     "lore": "xhci reset failed", "max_mb": 32,
     "bugzilla": "xhci reset"},
    {"id": "netdev-watchdog", "subsystem": "network",
     "lore": "NETDEV WATCHDOG transmit queue timed out", "max_mb": 32},
    {"id": "e1000e-reset", "subsystem": "network",
     "lore": "e1000e reset", "max_mb": 32},
    {"id": "nfs-timeout", "subsystem": "network",
     "lore": "nfs server not responding", "max_mb": 24},
    # hardware / thermal
    {"id": "aer", "subsystem": "hardware",
     "lore": "AER corrected error", "max_mb": 32,
     "bugzilla": "AER corrected error"},
    {"id": "mce", "subsystem": "hardware",
     "lore": "machine check exception", "max_mb": 32},
    {"id": "thermal-critical", "subsystem": "thermal",
     "lore": "thermal zone critical temperature", "max_mb": 32},
    # locking
    {"id": "soft-lockup", "subsystem": "locking",
     "lore": "soft lockup CPU stuck", "max_mb": 48,
     "bugzilla": "soft lockup"},
    {"id": "hung-task", "subsystem": "locking",
     "lore": "task blocked for more than", "max_mb": 32},
    {"id": "rcu-stall", "subsystem": "locking",
     "lore": "INFO: rcu detected stall", "max_mb": 32},
]


def selected_entries(limit: int = 0, only: set[str] | None = None) -> list[dict]:
    """Catalog entries for one --auto pass (limit 0 = all; only = id filter)."""
    entries = list(CATALOG[:limit]) if limit else list(CATALOG)
    if only:
        entries = [entry for entry in entries if entry["id"] in only]
    return entries
