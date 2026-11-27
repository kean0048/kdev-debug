import pytest

from dmesg_agent.cli import _resolve_host
from dmesg_agent.collectors.base import RawBundle, collect_via
from dmesg_agent.collectors.filelog import collect_file, derive_hostname
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


# --------------------------------------------------- offline file host identity

_JOURNAL_LOG = (
    "Nov 27 02:48:04 thinkstationpgx kernel: audit: type=1400 ...\n"
    "Nov 27 02:48:05 thinkstationpgx kernel: EXT4-fs error (device sda1): ...\n"
    "Nov 27 02:48:06 thinkstationpgx systemd[1]: Started foo.service\n"
)


def test_derive_hostname_from_journal_lines():
    assert derive_hostname(_JOURNAL_LOG) == "thinkstationpgx"


def test_derive_hostname_none_for_raw_dmesg():
    raw = "[    0.000000] Linux version 6.12.11\n[    1.234] EXT4-fs error\n"
    assert derive_hostname(raw) is None


def test_derive_hostname_majority_wins():
    text = ("Nov 27 02:00:00 host-a kernel: x\n"
            "Nov 27 02:00:01 host-b kernel: y\n"
            "Nov 27 02:00:02 host-b kernel: z\n")
    assert derive_hostname(text) == "host-b"


def test_file_bundle_keeps_derived_hostname(tmp_path):
    path = tmp_path / "dmesg.txt"
    path.write_text(_JOURNAL_LOG)
    bundle = collect_file(str(path), kernel="7.0.0", distro="Ubuntu 24.04")
    assert bundle.extra_context["hostname"] == "thinkstationpgx"


def _args(**kw):
    from types import SimpleNamespace
    defaults = {"host_id": None, "ssh": None, "file": None}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def test_resolve_host_prefers_explicit_id():
    bundle = RawBundle(dmesg_text="", extra_context={"hostname": "pgx"})
    assert _resolve_host(_args(host_id="fixed", file="x.txt"), bundle) == "fixed"


def test_resolve_host_uses_machine_id_then_hostname():
    bundle = RawBundle(dmesg_text="", extra_context={"machine_id": "abc", "hostname": "pgx"})
    assert _resolve_host(_args(file="x.txt"), bundle) == "abc"
    bundle2 = RawBundle(dmesg_text="", extra_context={"hostname": "pgx"})
    assert _resolve_host(_args(file="x.txt"), bundle2) == "pgx"


def test_resolve_host_file_fallback_warns(capsys):
    bundle = RawBundle(dmesg_text="", extra_context={})
    assert _resolve_host(_args(file="/var/tmp/dmesg.txt"), bundle) == "dmesg.txt"
    assert "--host-id" in capsys.readouterr().err
