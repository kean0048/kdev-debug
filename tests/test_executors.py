import sys
import types

import dmesg_agent.executors as ex_mod
from dmesg_agent.executors import LocalExecutor, SSHExecutor
from dmesg_agent.passwds import PassResolver


class _Proc:
    returncode = 0
    stdout = "kernel log text"
    stderr = ""


def _capture_run(monkeypatch):
    seen: dict = {}

    def fake_run(argv, **kw):
        seen["argv"] = list(argv)
        seen["input"] = kw.get("input")
        return _Proc()

    monkeypatch.setattr(ex_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(ex_mod.os, "geteuid", lambda: 1000)  # pretend non-root
    return seen


def test_passwordless_sudo_still_elevates(monkeypatch):
    # regression: sudo -n succeeded → the old code ran the command WITHOUT sudo
    seen = _capture_run(monkeypatch)
    ex = LocalExecutor(PassResolver("none"))
    ex._sudo_checked, ex._passwordless_sudo = True, True
    r = ex.run("dmesg -T", sudo=True)
    assert r.usable
    assert seen["argv"] == ["sudo", "sh", "-c", "dmesg -T"]


def test_password_required_uses_sudo_S(monkeypatch):
    seen = _capture_run(monkeypatch)
    ex = LocalExecutor(PassResolver("none"))
    ex._sudo_checked, ex._passwordless_sudo = True, False
    ex._password = lambda: "pw"
    r = ex.run("dmesg -T", sudo=True)
    assert r.usable
    assert seen["argv"] == ["sudo", "-S", "sh", "-c", "dmesg -T"]
    assert seen["input"] == "pw\n"


def test_no_password_available_skips_without_running(monkeypatch):
    seen = _capture_run(monkeypatch)
    ex = LocalExecutor(PassResolver("none"))  # mode none → resolver returns None
    ex._sudo_checked, ex._passwordless_sudo = True, False
    r = ex.run("dmesg -T", sudo=True)
    assert not r.ok
    assert "no password provided" in (r.skip_reason or "")
    assert "argv" not in seen  # the command was never executed


# ---------------------------------------------------------------- SSH executor

class _FakeChannel:
    def __init__(self, rc: int):
        self._rc = rc

    def settimeout(self, _t):
        pass

    def recv_exit_status(self):
        return self._rc


class _FakeIO:
    def __init__(self, data: bytes = b"", rc: int = 0):
        self._data = data
        self.channel = _FakeChannel(rc)
        self.written = b""

    def read(self):
        return self._data

    def write(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.written += data

    def flush(self):
        pass


def _install_fake_paramiko(monkeypatch, passwordless: bool):
    holder: dict = {}

    class _Client:
        def __init__(self, *a, **kw):
            self.commands: list[str] = []
            self.stdin_streams: list[_FakeIO] = []
            holder["client"] = self

        def load_system_host_keys(self):
            pass

        def set_missing_host_key_policy(self, _policy):
            pass

        def connect(self, *a, **kw):
            pass

        def exec_command(self, full, timeout=None):
            self.commands.append(full)
            if full == "sudo -n true":
                return (_FakeIO(), _FakeIO(b"", 0 if passwordless else 1),
                        _FakeIO(b"", 0 if passwordless else 1))
            stdin = _FakeIO()
            self.stdin_streams.append(stdin)
            return stdin, _FakeIO(b"ok", 0), _FakeIO()

        def close(self):
            pass

    fake = types.SimpleNamespace(
        SSHClient=_Client,
        AutoAddPolicy=lambda: object(),
        ssh_exception=types.SimpleNamespace(AuthenticationException=Exception),
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    return holder


def test_ssh_passwordless_sudo_does_not_prompt(monkeypatch):
    holder = _install_fake_paramiko(monkeypatch, passwordless=True)
    ex = SSHExecutor("host", "user", resolver=PassResolver("none"))
    r = ex.run("dmesg -T", sudo=True)
    assert r.ok
    client = holder["client"]
    assert client.commands == ["sudo -n true", "sudo sh -c 'dmesg -T'"]
    assert all(s.written == b"" for s in client.stdin_streams), \
        "passwordless sudo must not feed a password"


def test_ssh_password_sudo_uses_stdin(monkeypatch):
    holder = _install_fake_paramiko(monkeypatch, passwordless=False)
    ex = SSHExecutor("host", "user", resolver=PassResolver("terminal"))
    ex.resolver.get = lambda prompt="": "pw"
    r = ex.run("dmesg -T", sudo=True)
    assert r.ok
    client = holder["client"]
    assert client.commands[0] == "sudo -n true"
    assert client.commands[1].startswith("sudo -S sh -c ")
    assert client.stdin_streams[0].written == b"pw\n"


def test_ssh_no_password_skips_actual_command(monkeypatch):
    holder = _install_fake_paramiko(monkeypatch, passwordless=False)
    ex = SSHExecutor("host", "user", resolver=PassResolver("none"))
    r = ex.run("dmesg -T", sudo=True)
    assert not r.ok
    assert "no password provided" in (r.skip_reason or "")
    assert holder["client"].commands == ["sudo -n true"]
    assert not holder["client"].stdin_streams


def test_ssh_sudo_probe_is_cached(monkeypatch):
    holder = _install_fake_paramiko(monkeypatch, passwordless=True)
    ex = SSHExecutor("host", "user", resolver=PassResolver("none"))
    ex.run("uptime", sudo=True)
    ex.run("free -h", sudo=True)
    assert holder["client"].commands.count("sudo -n true") == 1
