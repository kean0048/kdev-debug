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
    missing = _ctx(tmp_path / "missing.db")
    known_issues(missing)
    assert missing.known_issues_text == ""
    assert missing.known_issues_meta["status"] == "no-store"
    db = _store_with_issue(tmp_path)
    ctx = _ctx(db, args=SimpleNamespace(known_issues_db=str(db),
                                        no_known_issues=True))
    known_issues(ctx)
    assert ctx.known_issues_text == ""
    assert ctx.known_issues == []
    assert ctx.known_issues_meta["status"] == "disabled"


def test_recall_classifies_each_block_separately(tmp_path):
    from dmesg_agent.plugins.context_known_issues import known_issues
    line = ("[    7.810218] iwlwifi 0000:09:00.0: Direct firmware load for "
            "iwlwifi-gl-c0-fm-c0-c102.ucode failed with error -2")
    db = tmp_path / "ki.db"
    store = KnownIssueStore(db)
    store.upsert(source="lore", source_id="iw1", url="https://lore/iw",
                 title="iwlwifi BE200: linux-firmware lacks the ucode",
                 classification=classify_text("", line),
                 root_cause="linux-firmware package is too old")
    store.close()
    lines = ["[    2.644343] ACPI: thermal: Thermal Zone [THM0] (65 C)", line]
    ctx = SimpleNamespace(
        args=SimpleNamespace(known_issues_db=str(db), no_known_issues=False),
        blocks=[SimpleNamespace(start=1, end=1, names=["thermal"]),
                SimpleNamespace(start=2, end=2, names=["firmware"])],
        lines=lines, known_issues_text="", known_issues=[],
        known_issues_meta={}, log=lambda *a: None)
    known_issues(ctx)
    assert ctx.known_issues, "the firmware block must still be matched"
    top = ctx.known_issues[0]
    assert top["block"] == "L2-2"
    assert top["fault_class"] == "firmware"


def test_post_attaches_recall_trace_and_model_usage():
    from dmesg_agent.plugins.context_known_issues import known_issues_trace
    ctx = SimpleNamespace(
        result={"known_issue_usage": [
            {"id": 1, "used": "rejected", "why": "target mode, not host nvme"}]},
        known_issues_meta={"status": "matched", "store": "db",
                           "matches": [{"id": 1}]})
    known_issues_trace(ctx)
    trace = ctx.result["known_issues"]
    assert trace["usage"][0]["used"] == "rejected"
    disabled = SimpleNamespace(result={},
                               known_issues_meta={"status": "disabled"})
    known_issues_trace(disabled)
    assert "known_issues" not in disabled.result


def test_known_issues_prompt_block_is_marked_not_evidence():
    msgs = build_messages(RawBundle(dmesg_text=""), "1: x",
                          known_issues_text="- #1 [storage/nvme] example")
    user = msgs[-1]["content"]
    assert "Known issues from the community knowledge base" in user
    assert "NOT evidence from this host" in user
    assert "- #1 [storage/nvme] example" in user
    assert "known_issue_usage" in user


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
