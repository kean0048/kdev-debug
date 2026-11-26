from dmesg_agent.executors import ExecResult
from dmesg_agent.systemscan import SCAN_ITEMS, run_cross_boot, run_live_probe, run_system_scan
from dmesg_agent.vmcore import analyze_vmcore


class FakeExecutor:
    name, can_collect = "fake", True

    def __init__(self, outs=None, skip=False):
        self.outs = outs or {}
        self.skip = skip
        self.runs = []

    def run(self, cmd, sudo=False, timeout=30):
        self.runs.append((cmd, sudo))
        if self.skip:
            return ExecResult(ok=False, skip_reason="requires root (no password provided, skipped)")
        return ExecResult(ok=True, out=self.outs.get("match", ""))

    def close(self):
        pass


def test_scan_runs_whitelist_only():
    ex = FakeExecutor()
    evs = run_system_scan(ex)
    assert len(evs) == len(SCAN_ITEMS)
    cmds = {e.cmd for e in evs}
    for _sub, cmd, _why in SCAN_ITEMS:
        assert cmd in cmds
    # all scan commands are unprivileged by design
    assert all(not sudo for _c, sudo in ex.runs)


def test_scan_clean_machine_no_crash():
    ex = FakeExecutor()  # every command returns ""
    evs = run_system_scan(ex)
    assert all(e.status in ("ok", "empty", "skipped") for e in evs)
    assert all("sudo auth" not in e.output for e in evs)


def test_scan_skips_without_password():
    ex = FakeExecutor(skip=True)
    evs = run_system_scan(ex)
    assert all(e.status == "skipped" for e in evs)


def test_live_probe_reports_missing_drgn_offline():
    ex = FakeExecutor({"match": "cannot open live kernel: Permission denied"})
    evs = run_live_probe(ex)
    assert len(evs) == 1 and evs[0].status == "ok"  # output goes to corpus verbatim
    ex2 = FakeExecutor({"match": "MISSING_DRGN"})
    assert run_live_probe(ex2)[0].status == "empty"


def test_cross_boot_count_and_sudo():
    ex = FakeExecutor()
    evs = run_cross_boot(ex, 3)
    assert len(evs) == 3
    assert all(sudo for _c, sudo in ex.runs)
    # clamped to at most 5 boots
    assert len(run_cross_boot(FakeExecutor(), 10)) == 5


def test_vmcore_missing_file_skips():
    ex = FakeExecutor()
    ev = analyze_vmcore(ex, "/nonexistent/vmcore", None)
    assert ev.status == "skipped" and "not found" in ev.output


def test_vmcore_missing_vmlinux_skips(tmp_path):
    fake = tmp_path / "vmcore"
    fake.write_text("x")
    ev = analyze_vmcore(FakeExecutor(), str(fake), None)
    # depends on whether the crash utility is installed on the test machine
    assert ev.status == "skipped" and ("vmlinux" in ev.output or "crash utility" in ev.output)
