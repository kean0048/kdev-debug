import os

from dmesg_agent.triage import find_blocks, render_blocks

DATA = os.path.join(os.path.dirname(__file__), "data", "sample_dmesg.txt")


def _lines():
    with open(DATA, encoding="utf-8") as f:
        return f.read().splitlines()


def test_signatures_hit():
    blocks = find_blocks(_lines())
    names = {n for b in blocks for n in b.names}
    for expected in ["oom", "lockup", "hung-task", "gpu-amd", "io-error", "nvme", "fs-error", "security"]:
        assert expected in names, f"missing signature {expected}, got: {names}"


def test_nvrm_out_of_memory_is_gpu_not_oom():
    lines = ["[ 1.0] NVRM: nvCheckOkFailedNoLog: Check failed: Out of memory "
             "[NV_ERR_NO_MEMORY] (0x51) returned from _memdescAllocInternal"]
    names = {n for b in find_blocks(lines) for n in b.names}
    assert "gpu-nvidia" in names
    assert "oom" not in names


def test_block_line_numbers_are_real():
    lines = _lines()
    blocks = find_blocks(lines)
    text = render_blocks(lines, blocks)
    for b in blocks:
        expected = f"{b.start}: {lines[b.start - 1]}"
        assert expected in text


def test_blocks_sorted_and_disjoint():
    blocks = find_blocks(_lines())
    assert all(a.end < b.start for a, b in zip(blocks, blocks[1:]))


def test_syzkaller_style_signatures():
    lines = [
        "clean", "clean", "clean", "clean", "clean", "clean",
        "[  1.0] WARNING: possible circular locking dependency detected",
        "[  2.0] rcu: INFO: rcu_sched detected stalls on CPUs/tasks",
        "[  3.0] BUG: KASAN: use-after-free in foo+0x1/0x2",
        "[  4.0] refcount_t: underflow; use-after-free",
        "[  5.0] page allocation failure: order:2, mode:0xcc0(GFP_KERNEL)",
        "clean", "clean", "clean", "clean", "clean",
    ]
    names = {n for b in find_blocks(lines) for n in b.names}
    for expected in ["lockdep", "rcu-stall", "sanitizer", "page-alloc"]:
        assert expected in names, names


def test_clean_log_falls_back_to_whole():
    lines = ["[    0.1] boot ok", "[    0.2] everything fine"]
    blocks = find_blocks(lines)
    assert len(blocks) == 1
    assert blocks[0].names == ["whole-log"]
    assert blocks[0].start == 1 and blocks[0].end == len(lines)


def test_over_budget_keeps_all_segments_trimmed():
    # one huge merged block (adjacent lockup lines); trimming must keep the
    # tail (chronological recency matters), not drop it wholesale
    lines = [f"[{i}.0] soft lockup - CPU#{i} stuck for 22s! work" for i in range(500)]
    blocks = find_blocks(lines)
    assert len(blocks) == 1 and blocks[0].end == 500
    text = render_blocks(lines, blocks, max_chars=4_000)
    assert "lines omitted" in text
    assert "CPU#499" in text  # tail preserved
    assert "CPU#0 " in text   # head preserved
