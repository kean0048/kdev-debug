from types import SimpleNamespace

from dmesg_agent.collectors.base import RawBundle
from dmesg_agent.knownissues import KnownIssueStore, classify_text
from dmesg_agent.prompts import build_messages

LOG = "[456.789] nvme nvme0: I/O 12 QID 1 timeout, reset controller"


def _store_with_issue(tmp_path):
    db = tmp_path / "ki.db"
    store = KnownIssueStore(db)
    c = classify_text("nvme timeout", LOG)
    assert store.upsert(source="lore", source_id="m1", url="https://lore/1",
                        title="nvme: fix timeout on controller reset",
                        classification=c, root_cause="controller reset race",
                        fix={"commit": "be8e82caa685"}, confidence=0.9)
    store.set_extraction(1, symptom="nvme I/O timeout", root_cause="reset race",
                         fix={"upgrade_to": "6.12.121"}, log_snippets=[LOG],
                         confidence=0.9, model="test")
    store.close()
    return db


def _ctx(db, **over):
    ctx = SimpleNamespace(
        args=SimpleNamespace(known_issues_db=str(db), no_known_issues=False),
        blocks=[SimpleNamespace(start=1, end=1, names=["nvme"])],
        lines=[LOG],
        known_issues_text="",
        known_issues=[],
        log=lambda *a: None,
    )
    for key, value in over.items():
        setattr(ctx, key, value)
    return ctx


def test_known_issue_lookup_injects_matches(tmp_path):
    from dmesg_agent.plugins.context_known_issues import known_issues
    db = _store_with_issue(tmp_path)
    ctx = _ctx(db)
    known_issues(ctx)
    assert ctx.known_issues and ctx.known_issues[0]["id"] == 1
    text = ctx.known_issues_text
    assert "nvme: fix timeout on controller reset" in text
    assert "Known cause: reset race" in text
    assert "upgrade_to=6.12.121" in text
    assert "https://lore/1" in text


def test_known_issue_lookup_noop_without_store_or_when_disabled(tmp_path):
    from dmesg_agent.plugins.context_known_issues import known_issues
    known_issues(_ctx(tmp_path / "missing.db"))
    db = _store_with_issue(tmp_path)
    ctx = _ctx(db, args=SimpleNamespace(known_issues_db=str(db),
                                        no_known_issues=True))
    known_issues(ctx)
    assert ctx.known_issues_text == ""
    assert ctx.known_issues == []


def test_known_issues_prompt_block_is_marked_not_evidence():
    msgs = build_messages(RawBundle(dmesg_text=""), "1: x",
                          known_issues_text="- #1 [storage/nvme] example")
    user = msgs[-1]["content"]
    assert "Known issues from the community knowledge base" in user
    assert "NOT evidence from this host" in user
    assert "- #1 [storage/nvme] example" in user


def test_known_issues_plugin_registered_and_flags_parse():
    from dmesg_agent import plugins as pf
    from dmesg_agent.cli import build_parser
    pf.registry.reset()
    pf.load_plugins()
    assert pf.registry.named("context", "known_issues") is not None
    args = build_parser().parse_args(["--file", "x", "--known-issues-db",
                                      "/tmp/ki.db", "--no-known-issues"])
    assert args.known_issues_db == "/tmp/ki.db"
    assert args.no_known_issues is True
