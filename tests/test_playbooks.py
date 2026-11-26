from dmesg_agent.executors import ExecResult
from dmesg_agent.passwds import PassResolver
from dmesg_agent.playbooks import (
    DEEP_BY_SUBSYSTEM, run_deep, run_prefetch, subsystems_from_signatures,
    subsystems_from_text,
)


class RecExecutor:
    name, can_collect = "rec", True

    def __init__(self):
        self.runs = []

    def run(self, cmd, sudo=False, timeout=30):
        self.runs.append((cmd, sudo))
        return ExecResult(ok=True, out="fake output")

    def close(self):
        pass


def test_signature_routing():
    assert subsystems_from_signatures({"oom", "nvme", "gpu-amd"}) == {"memory", "storage", "gpu"}


def test_text_routing():
    subs = subsystems_from_text("NVMe I/O errors, suspect SSD media bad sectors, need smartctl")
    assert "storage" in subs
    assert "gpu" not in subsystems_from_text("out of memory triggered the OOM killer")
    assert "memory" in subsystems_from_text("out of memory triggered the OOM killer")


def test_prefetch_skips_sudo():
    ex = RecExecutor()
    evs = run_prefetch(ex, {"oom"})
    assert any(cmd for cmd, sudo in ex.runs if not sudo)
    assert all(not sudo for _, sudo in ex.runs)
    assert any(e.status == "ok" for e in evs)


def test_deep_uses_sudo_and_limit():
    ex = RecExecutor()
    evs = run_deep(ex, "NVMe bad sectors smartctl")
    assert ex.runs  # storage has deep commands
    assert len(evs) <= 6
    sudo_cmds = [c for c, s in ex.runs if s]
    assert any("smartctl" in c for c in sudo_cmds), "storage deep verification should include a smartctl sudo command"


def test_deep_skips_without_password():
    ex = RecExecutor()
    # mimic a real LocalExecutor with resolver=none: skip when no password is available
    from dmesg_agent.executors import LocalExecutor

    lex = LocalExecutor(PassResolver("none"))
    evs = run_deep(lex, "smartctl media")
    # without root it must at least not crash: skip or succeed
    assert all(e.status in ("ok", "skipped", "empty") for e in evs)
    if lex.resolver is not None:
        assert not any("sudo auth" in e.output for e in evs)


def test_prefetch_budget():
    evs = run_prefetch(RecExecutor(), set(subsystems_from_signatures(
        {"oom", "nvme", "gpu-amd", "thermal", "net-link", "lockup", "mce", "usb", "firmware", "power"})))
    total = sum(len(e.output) for e in evs)
    assert total <= 30_000  # 20k budget + truncation slack on the last item
