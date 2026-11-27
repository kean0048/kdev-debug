import dmesg_agent.executors as ex_mod
from dmesg_agent.executors import LocalExecutor
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
