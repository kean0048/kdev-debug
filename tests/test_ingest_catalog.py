from datetime import datetime
from types import SimpleNamespace

from dmesg_agent.ingest_catalog import CATALOG, selected_entries
from dmesg_agent.knownissues import KnownIssueStore
from dmesg_agent.plugins.learn import _auto_years, build_parser

_MBOX = """From a@example.com Mon Nov 25 10:00:00 2026
Message-ID: <auto1@example.com>
Date: Mon, 25 Nov 2026 10:00:00 +0000
Subject: [PATCH] nvme: fix timeout on controller reset

[ 456.789] nvme nvme0: I/O 12 QID 1 timeout, reset controller

"""


def test_catalog_covers_main_subsystems():
    ids = [entry["id"] for entry in CATALOG]
    assert len(ids) == len(set(ids))
    subsystems = {entry["subsystem"] for entry in CATALOG}
    assert {"storage", "memory", "gpu", "network", "hardware",
            "locking"} <= subsystems
    for entry in CATALOG:
        assert entry["id"] and entry["subsystem"]
        assert entry.get("lore") or entry.get("bugzilla")
        assert 1 <= entry.get("max_mb", 32) <= 256
        assert entry.get("tracker_limit", 8) >= 1


def test_parser_accepts_auto_flags():
    args = build_parser().parse_args(["--auto", "--auto-max-mb", "64",
                                      "--auto-max-queries", "2",
                                      "--auto-only", "aer"])
    assert args.auto is True
    assert args.auto_max_mb == 64
    assert args.auto_max_queries == 2
    assert args.auto_only == ["aer"]


def test_selected_entries_limit_and_only():
    assert selected_entries(0) == CATALOG
    assert selected_entries(2) == CATALOG[:2]
    only = selected_entries(0, {"aer"})
    assert [entry["id"] for entry in only] == ["aer"]


def test_auto_years_newest_first():
    years = list(_auto_years(SimpleNamespace(auto_since_year=2024)))
    assert years[-1] == 2024
    assert years[0] == datetime.now().year
    assert all(newer > older for newer, older in zip(years, years[1:]))


def test_learn_auto_runs_lore_and_bugzilla(monkeypatch, tmp_path):
    from dmesg_agent.plugins import learn as learn_mod
    src = tmp_path / "auto.mbox"
    src.write_text(_MBOX)
    calls = []

    def fake_lore(query, full_threads=False, max_mb=128, progress=None):
        calls.append(("lore", query))
        src.write_text(_MBOX)  # auto removes each downloaded mbox
        return str(src)

    def fake_bugzilla(base, query, limit=8, progress=None):
        calls.append(("bugzilla", query))
        return [{"source": "bugzilla:test", "source_id": "9",
                 "url": "https://b/9", "title": "ata6: hardreset failed",
                 "body": "[1.0] ata6: SError: { CommWake }\nata6: hardreset failed",
                 "date": ""}]

    monkeypatch.setattr(learn_mod, "fetch_lore_search", fake_lore)
    monkeypatch.setattr(learn_mod, "fetch_bugzilla", fake_bugzilla)
    db = tmp_path / "ki.db"
    # No explicit source and no --auto: the catalog is the default action.
    code = learn_mod.learn([
        "--max-queries", "1", "--since-year", str(datetime.now().year),
        "--db", str(db)])
    assert code == 0
    assert calls[0][0] == "lore"
    assert any(kind == "bugzilla" for kind, _ in calls)
    store = KnownIssueStore(db)
    assert store.count() == 2
    fixes = {row["source"]: row["fix"] for row in store.list()}
    assert fixes["bugzilla:test"]["bug"] == "9"  # pointer, not comment text
