import pytest

from dmesg_agent.collectors.base import collect_via
from dmesg_agent.errors import CollectError
from dmesg_agent.executors import ExecResult

_JOURNAL_CMD = "journalctl -k -b -1 --no-pager -o short"


class _FakeExec:
    name = "fake"

    def __init__(self, journal_sudo_out=None):
        self.journal_sudo_out = journal_sudo_out
        self.calls: list[tuple[str, bool]] = []

    def run(self, cmd, sudo=False, timeout=30):
        self.calls.append((cmd, sudo))
        if cmd.startswith("journalctl"):
            if sudo and self.journal_sudo_out:
                return ExecResult(ok=True, out=self.journal_sudo_out)
            return ExecResult(ok=True, out="Hint: You are currently not seeing messages from other users.")
        return ExecResult(ok=True, out="PRETTY_NAME=Debian 13")


def test_previous_boot_retried_with_sudo():
    ex = _FakeExec(journal_sudo_out="abc: [ 1.2] usb error")
    bundle = collect_via(ex, boot="previous")
    assert bundle.dmesg_text == "abc: [ 1.2] usb error"
    assert (_JOURNAL_CMD, False) in ex.calls
    assert (_JOURNAL_CMD, True) in ex.calls


def test_previous_boot_unusable_even_with_sudo(tmp_path):
    ex = _FakeExec(journal_sudo_out=None)
    with pytest.raises(CollectError) as e:
        collect_via(ex, boot="previous")
    assert "journalctl with root" in str(e.value)


def test_no_sudo_retry_when_unprivileged_pass_works():
    ex = _FakeExec(journal_sudo_out=None)
    ex.run_unpriv_ok = True

    def run(cmd, sudo=False, timeout=30):
        ex.calls.append((cmd, sudo))
        if cmd.startswith("dmesg"):
            return ExecResult(ok=True, out="[ 0.1] ok")
        return ExecResult(ok=True, out="PRETTY_NAME=Debian 13")

    ex.run = run
    bundle = collect_via(ex, boot="now")
    assert bundle.dmesg_text == "[ 0.1] ok"
    assert not any(s for _c, s in ex.calls), "must not prompt for sudo when the first pass works"
