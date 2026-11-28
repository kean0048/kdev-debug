import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from dmesg_agent import cli
from dmesg_agent import plugins as pf
from dmesg_agent.collectors.base import RawBundle
from dmesg_agent.plugins import RunContext
from dmesg_agent.triage import Block
from dmesg_agent.verify import VerifySummary

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "data" / "sample_dmesg.txt"


@pytest.fixture(autouse=True)
def loaded_registry():
    pf.registry.reset()
    pf.load_plugins()
    yield


def _tar(tmp_path) -> Path:
    path = tmp_path / "sos.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("sos/dmesg")
        body = ("[    0.000000] Linux version 6.12.11\n"
                "[    1.0] EXT4-fs error (device sda1)\n").encode()
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
    return path


def test_registry_order_and_named():
    reg = pf.Registry()

    @reg.register("collect", name="late", order=20)
    def late(ctx):
        pass

    @reg.register("collect", name="early", order=10)
    def early(ctx):
        pass

    assert [f._plugin_meta.name for f in reg.get("collect")] == ["early", "late"]
    assert reg.named("collect", "early") is early
    assert reg.named("collect", "nope") is None


def test_discover_finds_every_kind_and_reloads():
    assert not pf.registry.errors
    kinds = {m.kind for m in pf.registry.all_meta()}
    assert {"source", "collect", "context", "deep", "post", "render"} <= kinds
    assert pf.registry.named("source", "offline_packages")
    # reset + rediscover must re-run decorators from cached modules
    pf.registry.reset()
    pf.load_plugins()
    assert pf.registry.named("collect", "facts")


def test_disable_plugins_by_env(monkeypatch):
    pf.registry.reset()
    monkeypatch.setenv("DMESG_AGENT_DISABLE_PLUGINS", "collect_facts,render_brief")
    pf.load_plugins()
    assert pf.registry.named("collect", "facts") is None
    assert pf.registry.named("render", "brief") is None
    assert pf.registry.named("source", "offline_packages") is not None


def test_source_plugin_claims_package_not_plain(tmp_path):
    fn = pf.registry.named("source", "offline_packages")
    tar = _tar(tmp_path)
    ctx = RunContext(args=SimpleNamespace(file=str(tar), kernel="unknown",
                                          distro="unknown"))
    assert fn(ctx) is True
    assert "EXT4-fs error" in ctx.bundle.dmesg_text
    plain = tmp_path / "dmesg.txt"
    plain.write_text("[1.0] hi")
    ctx2 = RunContext(args=SimpleNamespace(file=str(plain), kernel="unknown",
                                           distro="unknown"))
    assert fn(ctx2) is False


def test_facts_plugin():
    fn = pf.registry.named("collect", "facts")
    ctx = RunContext(args=SimpleNamespace(),
                     lines=["[1.0] Out of memory: Killed process 1 (chrome)"])
    fn(ctx)
    assert any(f["kind"] == "oom" for f in ctx.facts)
    assert "oom" in ctx.facts_text


def test_issue_plugin(tmp_path):
    path = tmp_path / "issue.txt"
    path.write_text("NFS mounts hang on reboot\n")
    fn = pf.registry.named("context", "issue")
    ctx = RunContext(args=SimpleNamespace(issue=str(path)))
    fn(ctx)
    assert ctx.issue_text == "NFS mounts hang on reboot"


def test_deep_plugin_calls_deep_dive(monkeypatch):
    from dmesg_agent.plugins import deep_playbooks
    seen = {}

    def fake(client, executor, result, lines, bundle, **kw):
        seen.update(kw)
        return {"deep": True}, ["collected"]

    monkeypatch.setattr(deep_playbooks, "deep_dive", fake)
    ctx = RunContext(
        args=SimpleNamespace(no_deep=False, max_verify=2, deep_rounds=1),
        executor=object(), result={"inconclusive_concerns": [{"title": "x"}]},
        lines=["line"], bundle=RawBundle(dmesg_text=""), scan_lines=["scan"],
        make_stream=None)
    deep_playbooks.deep(ctx)
    assert ctx.result == {"deep": True} and ctx.corpus == ["collected"]
    assert ctx.deep_used and seen["max_concerns"] == 2 and seen["max_rounds"] == 1


def test_knowledge_and_archive_post_plugins(tmp_path, monkeypatch):
    from dmesg_agent.plugins import post_archive, post_knowledge
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    result = {"summary": "s", "findings": [], "inconclusive_concerns": [],
              "dismissed_concerns": []}
    ctx = RunContext(
        args=SimpleNamespace(no_knowledge=False, knowledge_db=str(tmp_path / "kb.db"),
                             kmatch_threshold=0.65),
        argv=["test"], host="host-a", run_uuid="run-1",
        bundle=RawBundle(dmesg_text="[1.0] x", kernel_version="6.12", source="file:x"),
        blocks=[Block(1, 1, ["x"])], result=result, summary=VerifySummary(),
        cfg=SimpleNamespace(base_url="http://x"), client=SimpleNamespace(
            exchanges=[], last_model="m"))
    post_knowledge.knowledge(ctx)
    assert "knowledge" in ctx.result
    post_archive.archive(ctx)
    assert ctx.archive_path and Path(ctx.archive_path).is_file()


def test_render_plugins(tmp_path):
    from dmesg_agent.plugins import render_brief, render_html
    result = {"summary": "s", "findings": [], "inconclusive_concerns": [],
              "dismissed_concerns": []}
    ctx = RunContext(
        args=SimpleNamespace(html=str(tmp_path / "r.html")), result=result,
        bundle=RawBundle(dmesg_text="", kernel_version="6", source="test"),
        summary=VerifySummary(), blocks=[Block(1, 1, ["x"])], lines=["[1.0] x"],
        answer="", srcmap_version="")
    assert "dmesg AI diagnosis (brief)" in render_brief.brief(ctx)
    path = render_html.html(ctx)
    assert Path(path).is_file() and ctx.html_written


def test_core_runs_with_empty_registry(monkeypatch, capsys):
    empty = pf.Registry()
    monkeypatch.setattr(cli.plugin_framework, "load_plugins", lambda: empty)
    result = {"summary": "ok", "findings": [], "inconclusive_concerns": [],
              "dismissed_concerns": []}
    monkeypatch.setattr(cli, "run_analysis",
                        lambda *a, **kw: (result, json.dumps(result)))
    code = cli.main(["--file", str(SAMPLE), "--no-knowledge",
                     "--base-url", "http://127.0.0.1:9", "--brief"])
    captured = capsys.readouterr()
    assert code == 0
    assert "dmesg AI diagnosis report" in captured.out
    assert "brief renderer plugin not installed" in captured.err


def test_package_without_source_plugin_fails_clearly(tmp_path, monkeypatch, capsys):
    empty = pf.Registry()
    monkeypatch.setattr(cli.plugin_framework, "load_plugins", lambda: empty)
    code = cli.main(["--file", str(_tar(tmp_path)), "--no-knowledge",
                     "--base-url", "http://127.0.0.1:9"])
    err = capsys.readouterr().err
    assert code == 2
    assert "no source plugin claimed" in err


def test_plugins_list_smoke(capsys):
    assert cli._plugins_main(["list"]) == 0
    out = capsys.readouterr().out
    assert "source:" in out and "collect:" in out and "render:" in out


def _core_args():
    return ["--file", str(SAMPLE), "--no-knowledge",
            "--base-url", "http://127.0.0.1:9", "--brief"]


def test_crashing_collect_plugin_does_not_break_core(monkeypatch, capsys):
    reg = pf.Registry()

    @reg.register("collect", name="boom")
    def boom(ctx):
        raise RuntimeError("collect boom")

    monkeypatch.setattr(cli.plugin_framework, "load_plugins", lambda: reg)
    result = {"summary": "ok", "findings": [], "inconclusive_concerns": [],
              "dismissed_concerns": []}
    monkeypatch.setattr(cli, "run_analysis",
                        lambda *a, **kw: (result, json.dumps(result)))
    assert cli.main(_core_args()) == 0
    captured = capsys.readouterr()
    assert "collect plugin boom failed" in captured.err
    assert "dmesg AI diagnosis report" in captured.out


def test_crashing_brief_renderer_falls_back(monkeypatch, capsys):
    reg = pf.Registry()

    @reg.register("render", name="brief")
    def brief(ctx):
        raise RuntimeError("render boom")

    monkeypatch.setattr(cli.plugin_framework, "load_plugins", lambda: reg)
    result = {"summary": "ok", "findings": [], "inconclusive_concerns": [],
              "dismissed_concerns": []}
    monkeypatch.setattr(cli, "run_analysis",
                        lambda *a, **kw: (result, json.dumps(result)))
    assert cli.main(_core_args()) == 0
    captured = capsys.readouterr()
    assert "render plugin brief failed" in captured.err
    assert "dmesg AI diagnosis report" in captured.out
