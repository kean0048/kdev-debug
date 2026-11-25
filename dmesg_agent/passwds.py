"""sudo 密码获取:终端隐藏输入 / 桌面弹窗(zenity、kdialog),进程内缓存,绝不落盘。"""

from __future__ import annotations

import getpass
import shutil
import subprocess
import sys

MODES = ("auto", "terminal", "gui", "none")


class PassResolver:
    def __init__(self, mode: str = "auto"):
        if mode not in MODES:
            raise ValueError(f"askpass 模式须为 {MODES}")
        self.mode = mode
        self._cached: str | None = None

    @property
    def has_password(self) -> bool:
        return self._cached is not None

    def get(self, prompt: str = "需要 root 权限采集日志") -> str | None:
        if self._cached is not None:
            return self._cached
        if self.mode == "none":
            return None
        if self.mode in ("auto", "terminal"):
            pwd = self._terminal(prompt)
            if pwd is not None:
                self._cached = pwd
                return pwd
            if self.mode == "terminal":
                return None
        if self.mode in ("auto", "gui"):
            pwd = self._gui(prompt)
            if pwd:
                self._cached = pwd
                return pwd
        return None

    def _terminal(self, prompt: str) -> str | None:
        if not sys.stdin.isatty():
            return None
        try:
            return getpass.getpass(f"[dmesg-agent] {prompt}(回车跳过): ") or None
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return None

    def _gui(self, prompt: str) -> str | None:
        import os
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            return None
        if shutil.which("zenity"):
            cmd = ["zenity", "--password", "--title=dmesg-agent", f"--text={prompt}"]
        elif shutil.which("kdialog"):
            cmd = ["kdialog", "--password", prompt]
        else:
            return None
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.rstrip("\n") or None
