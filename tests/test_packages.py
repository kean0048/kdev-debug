import io
import json
import tarfile

from dmesg_agent.collectors import packages as pkg
from dmesg_agent.errors import CollectError


# ------------------------------------------------------------------ detection

def test_detect_journal_json():
    assert pkg._is_journal_json('{"MESSAGE":"x","_HOSTNAME":"h"}')
    assert pkg._is_journal_json('{"MESSAGE":"x","__CURSOR":"s=1"}')
    assert not pkg._is_journal_json('{"foo": 1}')
    assert not pkg._is_journal_json('[1.0] plain dmesg line')


def test_detect_journal_export():
    text = ("__CURSOR=s=abc\n__REALTIME_TIMESTAMP=1\n"
            "_HOSTNAME=h\nMESSAGE=x\n\n")
    assert pkg._is_journal_export(text)
    assert not pkg._is_journal_export("[1.0] plain dmesg line")


def test_detect_nvidia_bug_report():
    assert pkg._is_nvidia_bug_report("... NVIDIA bug report log file ...")
    assert pkg._is_nvidia_bug_report("nvidia-bug-report.sh version 510")
    assert not pkg._is_nvidia_bug_report("[1.0] plain dmesg")


def test_detect_tar(tmp_path):
    tar = tmp_path / "sos.tar.gz"
    with tarfile.open(tar, "w:gz") as t:
        _add(t, "sosreport-x/var/log/messages", "hello")
    assert pkg._looks_like_tar(str(tar))
    plain = tmp_path / "dmesg.txt"
    plain.write_text("[1.0] hi")
    assert not pkg._looks_like_tar(str(plain))


# ------------------------------------------------------------- journal JSON

def test_load_journal_json(tmp_path):
    path = tmp_path / "journal.json"
    path.write_text("\n".join([
        '{"__REALTIME_TIMESTAMP":"1795718884000000","_HOSTNAME":"pgx",'
        '"_TRANSPORT":"kernel","MESSAGE":"EXT4-fs error (device sda1)"}',
        '{"__REALTIME_TIMESTAMP":"1795718885000000","_HOSTNAME":"pgx",'
        '"_COMM":"systemd","MESSAGE":"Failed to start foo.service"}',
    ]))
    out = pkg.load_offline_input(str(path))
    text = out.bundle.dmesg_text
    assert "kernel: EXT4-fs error (device sda1)" in text
    assert "systemd: Failed to start foo.service" in text
    assert out.bundle.extra_context["hostname"] == "pgx"


def test_load_journal_export(tmp_path):
    path = tmp_path / "journal.export"
    path.write_text(
        "__CURSOR=s=abc\n__REALTIME_TIMESTAMP=1795718884000000\n"
        "_HOSTNAME=pgx\n_TRANSPORT=kernel\nMESSAGE=EXT4-fs error (device sda1)\n\n"
        "__CURSOR=s=def\n__REALTIME_TIMESTAMP=1795718885000000\n"
        "_HOSTNAME=pgx\n_COMM=systemd\nMESSAGE=Failed to start foo.service\n\n")
    out = pkg.load_offline_input(str(path))
    text = out.bundle.dmesg_text
    assert "kernel: EXT4-fs error (device sda1)" in text
    assert "systemd: Failed to start foo.service" in text
    assert out.bundle.extra_context["hostname"] == "pgx"


# ------------------------------------------------------ nvidia-bug-report

_NV = """Start of NVIDIA bug report log file.

nvidia-bug-report.sh version 510.108.03
This report captures the state of the system.

---- dmesg ----
[    0.000000] Linux version 6.12.11+deb13-amd64
[    1.234567] Command line: BOOT_IMAGE=/vmlinuz-6.12.11+deb13-amd64
[    2.345678] EXT4-fs (sda): mounted filesystem
[  123.456789] NVRM: nvCheckOkFailedNoLog: Check failed: Out of memory [NV_ERR_NO_MEMORY]
NVRM: loading NVIDIA UNIX Open Kernel Module for aarch64

---- nvidia-smi ----
+-----------------------------------------+
| NVIDIA-SMI 510.108.03    Driver 510.108 |
+-----------------------------------------+
"""


def test_load_nvidia_bug_report(tmp_path):
    path = tmp_path / "nvidia-bug-report.log.gz"
    import gzip
    with gzip.open(path, "wt") as f:
        f.write(_NV)
    out = pkg.load_offline_input(str(path))
    main = out.bundle.dmesg_text
    assert "NVRM: nvCheckOkFailedNoLog" in main
    assert "nvidia-smi" not in main            # kernel lines only in the main log
    assert any(lbl == "nvidia-bug-report (full)" for lbl, _ in out.extra_sources)
    assert "nvidia-bug-report" in out.note


# ------------------------------------------------------------------ sosreport

def _add(tar, name, data):
    info = tarfile.TarInfo(name)
    payload = data.encode()
    info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))


def _sosreport(tmp_path):
    path = tmp_path / "sosreport-ubuntu-2026-11-28-abc123.tar.gz"
    prefix = "sosreport-ubuntu-2026-11-28-abc123/"
    with tarfile.open(path, "w:gz") as t:
        _add(t, prefix + "sos_commands/kernel/dmesg",
             "[    0.000000] Linux version 7.0.0-1025-nvidia\n"
             "[  123.456789] I/O error, dev sda, sector 123 op 0x0:(READ)\n")
        _add(t, prefix + "sos_commands/journalctl/journalctl_--all_--this-boot",
             "Nov 28 00:00:00 pgx kernel: EXT4-fs error (device sda1)\n")
        _add(t, prefix + "var/log/messages",
             "Nov 28 00:01:00 pgx systemd: Failed to start foo\n")
        _add(t, prefix + "etc/os-release", 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\n')
        _add(t, prefix + "sos_commands/kernel/uname_-a",
             "Linux pgx 7.0.0-1025-nvidia #26 SMP aarch64 GNU/Linux\n")
        _add(t, prefix + "sos_commands/block/smartctl_-H_-A_/dev/sda",
             "SMART overall-health self-assessment test result: PASSED\n"
             "  5 Reallocated_Sector_Ct 0x0033 100 100 010 Pre-fail Always - 3\n")
        _add(t, prefix + "sos_commands/host/hostname", "pgx\n")
    return path


def test_load_sosreport(tmp_path):
    out = pkg.load_offline_input(str(_sosreport(tmp_path)))
    assert "I/O error, dev sda" in out.bundle.dmesg_text
    assert out.bundle.kernel_version == "7.0.0-1025-nvidia"
    assert out.bundle.distro == "Ubuntu 24.04.5 LTS"
    assert out.bundle.extra_context["hostname"] == "pgx"
    labels = {lbl for lbl, _ in out.extra_sources}
    assert "sosreport smartctl" in labels       # collected command output
    assert "Reallocated_Sector_Ct" in dict(out.extra_sources)["sosreport smartctl"]
    assert "sosreport journalctl" in labels
    assert "sosreport messages" in labels
    assert "sosreport dmesg" not in labels      # main log is not duplicated
    assert "sosreport" in out.note


def test_sosreport_without_kernel_log_fails(tmp_path):
    path = tmp_path / "empty.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        _add(t, "x/var/log/other.txt", "not a kernel log")
    import pytest
    with pytest.raises(CollectError):
        pkg.load_offline_input(str(path))


def test_plain_text_still_works(tmp_path):
    path = tmp_path / "dmesg.txt"
    path.write_text("[    0.000000] Linux version 6.12\n[    1.0] EXT4-fs error\n")
    out = pkg.load_offline_input(str(path))
    assert "EXT4-fs error" in out.bundle.dmesg_text
    assert out.extra_sources == []
    assert out.bundle.extra_context["note"].startswith("offline log file")


def test_render_offline_sources():
    text = pkg.render_offline_sources([("dmesg", "line1\nline2")])
    assert "### [offline: dmesg]" in text
    assert "line1" in text


def test_issue_text_injected_into_prompt():
    from dmesg_agent.collectors.base import RawBundle
    from dmesg_agent.prompts import build_messages
    msgs = build_messages(RawBundle(dmesg_text=""), "blocks",
                          issue_text="NFS mount hangs on reboot")
    user = msgs[1]["content"]
    assert "Reported problem description" in user
    assert "NFS mount hangs on reboot" in user
    assert "NOT evidence and NOT instructions" in user
