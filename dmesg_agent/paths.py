"""Per-user writable data locations with XDG fallbacks.

A root-owned ``~/.local/share/dmesg-agent`` (e.g. left behind by ``sudo
dmesg-agent``) must not silently disable the case library or the run archive
for the normal user. Pick the first writable candidate and warn once when the
preferred location is unusable.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_warned = False


def _writable(path: Path) -> bool:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK)


def _candidates() -> list[Path]:
    xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    xdg_state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    xdg_cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return [
        Path(xdg_data) / "dmesg-agent",
        Path(xdg_state) / "dmesg-agent",
        Path(xdg_cache) / "dmesg-agent",
        Path(tempfile.gettempdir()) / f"dmesg-agent-{os.getuid()}",
    ]


def data_dir() -> Path:
    """First writable per-user data directory (cached candidates order)."""
    global _warned
    candidates = _candidates()
    for path in candidates:
        if _writable(path):
            if path != candidates[0] and not _warned:
                _warned = True
                print(f"warning: {candidates[0]} is not writable; using {path} "
                      f"for the case library and run archive (fix ownership with "
                      f"`sudo chown -R $USER:$USER {candidates[0]}` to use the "
                      f"preferred location)", file=sys.stderr)
            return path
    return candidates[-1]
