import subprocess
from pathlib import Path

from dmesg_agent.srcmap import SrcMap, extract_symbols

TRACE = [
    "[ 3456.789150] RIP: 0010:ext4_writepages+0x1a2/0x4d0 [ext4]",
    "[ 3456.789200]  <TASK>",
    "[ 3456.789220]  ? do_writepages+0xd5/0x1e0",
    "[ 3456.789240]  ? wb_workfn+0xa5/0x2f0",
]


def _git(tree: Path, *args):
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "HOME": str(tree)}
    subprocess.run(["git", "-C", str(tree), *args], check=True, env=env,
                   capture_output=True)


def make_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "kern"
    (tree / "fs" / "ext4").mkdir(parents=True)
    src = """static int ext4_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	int ret = 0;
	return ret;
}

void wb_workfn(struct work_struct *work)
{
	do_writepages(NULL, NULL);
}

static void ext4_writepages_helper(void)
{
}
"""
    (tree / "fs" / "ext4" / "inode.c").write_text(src)
    (tree / "fs" / "fs-writeback.c").write_text(
        "void wb_workfn2(struct work_struct *work)\n{\n}\n")
    (tree / "Makefile").write_text("VERSION = 7\nPATCHLEVEL = 4\n")
    _git(tree, "init", "-q", ".")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", "one")
    (tree / "fs" / "ext4" / "inode.c").write_text(src.replace("int ret = 0;", "int ret = 1; // fix"))
    _git(tree, "commit", "-q", "-am", "ext4: fix ret init")
    return tree


def test_extract_symbols(tmp_path):
    syms = extract_symbols(TRACE)
    assert ("ext4_writepages", "ext4") in syms
    assert ("do_writepages", "") in syms
    assert ("wb_workfn", "") in syms
    assert len(syms) == len(set(s[0] for s in syms))


def test_lookup_body_history(tmp_path):
    tree = make_tree(tmp_path)
    sm = SrcMap(str(tree), cache_dir=tmp_path / "cache")
    sm.build_index()
    info = sm.lookup("ext4_writepages", module="ext4")
    assert info.file.endswith("fs/ext4/inode.c")
    assert "writeback_control" in info.body and info.body.rstrip().endswith("}")
    assert any("fix ret init" in h for h in info.history)
    # helper 也在索引里
    assert sm.lookup("ext4_writepages_helper") is not None


def test_module_hint_prefers_path(tmp_path):
    tree = make_tree(tmp_path)
    sm = SrcMap(str(tree), cache_dir=tmp_path / "cache")
    sm.build_index()
    info = sm.lookup("wb_workfn2", module="fs")
    assert info.file.endswith("fs/fs-writeback.c")


def test_render(tmp_path):
    tree = make_tree(tmp_path)
    sm = SrcMap(str(tree), cache_dir=tmp_path / "cache")
    text, infos = sm.render([("ext4_writepages", "ext4"), ("wb_workfn", "")])
    assert "fs/ext4/inode.c" in text and "最近提交" in text
    assert len(infos) == 2
