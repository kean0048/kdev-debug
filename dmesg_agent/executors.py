"""Command-executor abstraction: one interface for local and SSH, with sudo -S elevation.

Security boundary: playbooks declare only whitelisted read-only commands; the model
cannot inject arbitrary commands.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass

from .passwds import PassResolver

_NO_DATA_RE = re.compile(r"^(-- No entries --|Hint: You are currently not seeing.*)[\s\S]*$")


@dataclass
class ExecResult:
    ok: bool
    out: str = ""
    err: str = ""
    skip_reason: str | None = None  # why it did not run (e.g. no password / missing command)

    @property
    def usable(self) -> bool:
        return self.ok and bool(self.out) and not _NO_DATA_RE.match(self.out.strip())


class Executor:
    name = "?"
    can_collect = False  # whether dynamic command collection is supported (False in --file mode)

    def run(self, cmd: str, sudo: bool = False, timeout: int = 30) -> ExecResult:
        raise NotImplementedError

    def close(self) -> None:
        pass


class LocalExecutor(Executor):
    name = "local"
    can_collect = True

    def __init__(self, resolver: PassResolver | None = None):
        self.resolver = resolver or PassResolver("none")
        self._is_root = os.geteuid() == 0
        self._sudo_checked = False
        self._passwordless_sudo = False

    def _password(self) -> str | None:
        return self.resolver.get()

    def _needs_password(self) -> bool:
        if self._sudo_checked:
            return not self._passwordless_sudo
        self._sudo_checked = True
        try:
            proc = subprocess.run(
                ["sudo", "-n", "true"], capture_output=True, timeout=10,
            )
            self._passwordless_sudo = proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            self._passwordless_sudo = False
        return not self._passwordless_sudo

    def run(self, cmd: str, sudo: bool = False, timeout: int = 30) -> ExecResult:
        argv: list[str] = ["sh", "-c", cmd]
        password = None
        if sudo and not self._is_root and self._needs_password():
            password = self._password()
            if password is None:
                return ExecResult(ok=False, skip_reason="requires root (no password provided, skipped)")
            argv = ["sudo", "-S", "sh", "-c", cmd]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, errors="replace",
                timeout=timeout, input=(password + "\n") if password else None,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(ok=False, skip_reason=f"timed out ({timeout}s)")
        except OSError as e:
            return ExecResult(ok=False, skip_reason=str(e))
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        if proc.returncode != 0 and "sudo:" in err.lower() and "password" in err.lower():
            return ExecResult(ok=False, err=err, skip_reason="sudo authentication failed")
        if not out or _NO_DATA_RE.match(out):
            return ExecResult(ok=proc.returncode == 0, out="", err=err)
        return ExecResult(ok=True, out=out, err=err)


class SSHExecutor(Executor):
    name = "ssh"
    can_collect = True

    def __init__(self, host: str, user: str, port: int = 22,
                 key_filename: str | None = None, resolver: PassResolver | None = None):
        try:
            import paramiko
        except ImportError as e:
            from .errors import CollectError
            raise CollectError("SSH mode requires paramiko: pip install paramiko") from e
        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._client.connect(host, port=port, username=user,
                                 key_filename=key_filename, allow_agent=True, look_for_keys=True)
        except Exception as e:
            from .errors import CollectError
            raise CollectError(f"SSH connection to {user}@{host}:{port} failed: {e}") from e
        self._host, self._user = host, user
        self.resolver = resolver or PassResolver("none")

    def run(self, cmd: str, sudo: bool = False, timeout: int = 30) -> ExecResult:
        password: str | None = None
        if sudo:
            password = self.resolver.get(f"sudo password for {self._user}@{self._host}")
            if password is None:
                return ExecResult(ok=False, skip_reason="requires root (no password provided, skipped)")
            full = f"sudo -S sh -c {shlex.quote(cmd)}"
        else:
            full = f"sh -c {shlex.quote(cmd)}"
        try:
            stdin, stdout, stderr = self._client.exec_command(full, timeout=timeout)
            if password is not None:
                try:
                    stdin.write(password + "\n")
                    stdin.flush()
                except Exception:
                    pass  # sudo may already have a cached credential
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
        except Exception as e:
            return ExecResult(ok=False, skip_reason=f"SSH execution failed: {e}")
        if "sudo:" in err.lower() and "password" in err.lower() and not out:
            return ExecResult(ok=False, err=err, skip_reason="sudo authentication failed")
        if not out or _NO_DATA_RE.match(out):
            return ExecResult(ok=True, out="", err=err)
        return ExecResult(ok=True, out=out, err=err)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
