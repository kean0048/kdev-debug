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
        assert expected in names, f"缺少签名 {expected}, 实际: {names}"


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
