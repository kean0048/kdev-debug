import json

import pytest

from dmesg_agent import trackers
from dmesg_agent.knownissues import KnownIssueStore
from dmesg_agent.plugins.learn import build_parser


class _Resp:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self.body


def _serve(monkeypatch, routes):
    """Mock urlopen; routes = [(URL substring, JSON payload)], first match wins."""
    seen = []

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        seen.append(req)
        for needle, payload in routes:
            if needle in url:
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return _Resp(body)
        raise AssertionError(f"unexpected URL {url}")
    monkeypatch.setattr(trackers.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_fetch_bugzilla_reads_comment0(monkeypatch):
    seen = _serve(monkeypatch, [
        ("/rest/bug/123/comment",
         {"bugs": {"123": {"comments": [{"text": "nvme log here"}]}}}),
        ("/rest/bug?", {"bugs": [{"id": 123, "summary": "nvme: I/O timeout",
                                  "status": "NEW", "product": "IO",
                                  "component": "NVMe",
                                  "creation_time": "2024-05-01T12:00:00Z"}]}),
    ])
    issues = trackers.fetch_bugzilla("https://bugzilla.kernel.org/", "nvme timeout")
    assert len(issues) == 1
    issue = issues[0]
    assert issue["source"] == "bugzilla:bugzilla.kernel.org"
    assert issue["source_id"] == "123"
    assert issue["url"] == "https://bugzilla.kernel.org/show_bug.cgi?id=123"
    assert issue["title"] == "nvme: I/O timeout"
    assert "nvme log here" in issue["body"]
    assert issue["date"].startswith("2024-05-01T12:00:00")
    assert any("dmesg-agent" in str(v) for v in seen[0].headers.values())


def test_fetch_bugzilla_reports_progress(monkeypatch):
    messages = []
    _serve(monkeypatch, [
        ("/rest/bug/5/comment",
         {"bugs": {"5": {"comments": [{"text": "nvme log"}]}}}),
        ("/rest/bug?", {"bugs": [{"id": 5, "summary": "nvme timeout"}]}),
    ])
    trackers.fetch_bugzilla("https://b", "q", limit=5, progress=messages.append)
    assert any("1 bug(s) matched" in m for m in messages)
    assert any("descriptions 1/1" in m for m in messages)


def test_fetch_bugzilla_reads_only_the_first_comment(monkeypatch):
    # Full comment threads are not fetched; the bug id/URL is the fix pointer.
    _serve(monkeypatch, [
        ("/rest/bug/7/comment", {"bugs": {"7": {"comments": [
            {"text": "reporter description"},
            {"text": "Fixed by commit deadbeef1234 upstream."}]}}}),
        ("/rest/bug?", {"bugs": [{"id": 7, "summary": "nvme timeout",
                                  "status": "RESOLVED",
                                  "resolution": "FIXED"}]}),
    ])
    issues = trackers.fetch_bugzilla("https://b", "nvme timeout")
    body = issues[0]["body"]
    assert "reporter description" in body
    assert "Fixed by commit deadbeef1234" not in body
    assert issues[0]["url"].endswith("id=7")


def test_fetch_bugzilla_accepts_simple_comment_list(monkeypatch):
    _serve(monkeypatch, [
        ("/rest/bug/9/comment", {"bugs": {"9": [{"text": "ata6 SError"}]}}),
        ("/rest/bug?", {"bugs": [{"id": 9, "summary": "ata6: hardreset failed"}]}),
    ])
    issues = trackers.fetch_bugzilla("https://bugzilla.example", "ata")
    assert len(issues) == 1
    assert "ata6 SError" in issues[0]["body"]


def test_fetch_launchpad_reads_bug_details(monkeypatch):
    seen = _serve(monkeypatch, [
        ("/bugs/42", {"id": 42, "title": "nvme timeout on boot",
                      "description": "[ 1.0] nvme nvme0: I/O timeout",
                      "date_created": "2024-06-01T00:00:00+00:00"}),
        ("ws.op=searchTasks",
         {"entries": [{"bug_link": "https://api.launchpad.net/1.0/bugs/42",
                       "title": "task title"}]}),
    ])
    issues = trackers.fetch_launchpad("nvme timeout")
    assert len(issues) == 1
    issue = issues[0]
    assert issue["source"] == "launchpad"
    assert issue["source_id"] == "42"
    assert issue["url"] == "https://bugs.launchpad.net/bugs/42"
    assert issue["title"] == "nvme timeout on boot"
    assert "nvme nvme0" in issue["body"]
    assert seen[0].headers.get("Accept") == "application/json"


def test_fetch_gitlab_project_issues(monkeypatch):
    seen = _serve(monkeypatch, [
        ("/api/v4/projects/GNOME%2Fmutter/issues", [{
            "iid": 7, "title": "gnome-shell hangs after resume",
            "description": "Call Trace...", "labels": ["crash"],
            "web_url": "https://gitlab.gnome.org/GNOME/mutter/-/issues/7",
            "created_at": "2024-07-01T10:00:00.000Z"}]),
    ])
    issues = trackers.fetch_gitlab("https://gitlab.gnome.org/GNOME/mutter", "hang")
    assert len(issues) == 1
    issue = issues[0]
    assert issue["source"] == "gitlab:gitlab.gnome.org/GNOME/mutter"
    assert issue["source_id"] == "GNOME/mutter!7"
    assert issue["url"].endswith("/issues/7")
    assert "Call Trace" in issue["body"] and "Labels: crash" in issue["body"]
    assert "state=all" in seen[0].full_url and "search=hang" in seen[0].full_url


def test_gitlab_target_requires_project_path():
    with pytest.raises(ValueError, match="HOST/GROUP/PROJECT"):
        trackers.fetch_gitlab("https://gitlab.gnome.org", "x")


def test_learn_parser_tracker_args():
    args = build_parser().parse_args([
        "--tracker-query", "q", "--bugzilla", "https://b", "--launchpad",
        "--gitlab", "https://g/G/P", "--tracker-limit", "5"])
    assert args.bugzilla == ["https://b"]
    assert args.launchpad is True
    assert args.gitlab == ["https://g/G/P"]
    assert args.tracker_limit == 5


def test_learn_ingests_tracker_results(monkeypatch, tmp_path):
    from dmesg_agent.plugins import learn as learn_mod
    issue = {"source": "launchpad", "source_id": "42",
             "url": "https://bugs.launchpad.net/bugs/42",
             "title": "nvme0: I/O timeout resets controller",
             "body": "[1.0] nvme nvme0: I/O 12 timeout, reset controller",
             "date": "2024-06-01T00:00:00+00:00"}
    monkeypatch.setattr(learn_mod, "fetch_launchpad",
                        lambda query, limit=25, progress=None: [issue])
    db = tmp_path / "ki.db"
    code = learn_mod.learn(["--tracker-query", "nvme timeout", "--launchpad",
                            "--db", str(db)])
    assert code == 0
    store = KnownIssueStore(db)
    assert store.count() == 1
    row = store.list()[0]
    assert row["subsystem"] == "storage" and row["fault_class"] == "nvme"
    assert row["source"] == "launchpad"
    assert row["fix"]["bug"] == "42"  # compact pointer, not comment text
