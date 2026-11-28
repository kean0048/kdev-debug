import gzip
import json

import pytest

from dmesg_agent.knownissues import (KnownIssueStore, classify_text,
                                     is_noise_issue, series_key)
from dmesg_agent.plugins.learn import (build_parser, fetch_lore_search,
                                       iter_mbox, learn, _lore_request)


def test_classify_oom():
    c = classify_text(
        "Out of memory killer fires under load",
        "Kernel log: [ 123.456] Out of memory: Killed process 1234 (chrome)")
    assert c.subsystem == "memory"
    assert c.fault_class == "oom"
    assert c.has_log


def test_classify_nvme():
    c = classify_text(
        "nvme0 I/O timeout resetting controller",
        "[ 456.789] nvme nvme0: I/O 12 QID 1 timeout, reset controller")
    assert c.subsystem == "storage"
    assert c.fault_class == "nvme"


def test_classify_unclassified_without_signal():
    c = classify_text("random discussion with no kernel signal", "")
    assert c.subsystem == "unclassified"
    assert c.fault_class == "unclassified"
    assert c.fingerprint  # still has a fingerprint for the fallback bucket


def test_classify_tokens_are_bounded():
    c = classify_text("ata6 SATA link failure", "ata6: SError { CommWake } "
                      "ata6: hardreset failed " * 20)
    assert len(c.tokens) <= 40


def _mk(cls, title="t", source="lore", source_id="m@x", url="https://lore/1",
       root="", fix=None, conf=0.0):
    return dict(source=source, source_id=source_id, url=url, title=title,
                classification=cls, root_cause=root, fix=fix, confidence=conf)


def test_store_insert_and_idempotent(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c = classify_text("oom kill", "[1.0] Out of memory: Killed process 1 (x)")
    assert store.upsert(**_mk(c, source_id="m1")) is True
    assert store.count() == 1
    # same (source, source_id) is idempotent
    assert store.upsert(**_mk(c, source_id="m1")) is False
    assert store.count() == 1


def test_store_dedupes_same_fingerprint_across_sources(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c1 = classify_text("nvme timeout", "[1.0] nvme nvme0: I/O 12 timeout, reset")
    c2 = classify_text("nvme timeout (bugzilla)", "[2.0] nvme nvme0: I/O 12 timeout, reset")
    assert c1.fingerprint == c2.fingerprint
    assert store.upsert(**_mk(c1, source="lore", source_id="l1",
                              url="https://lore/1")) is True
    # different source, same fingerprint -> merges URL, no new row
    assert store.upsert(**_mk(c2, source="bugzilla", source_id="b1",
                              url="https://bz/1")) is False
    assert store.count() == 1
    row = store.get(1)
    assert row["urls"] == ["https://lore/1", "https://bz/1"]


def test_store_three_level_index(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    store.upsert(**_mk(classify_text("oom", "[1.0] Out of memory: Killed process 1 (x)"),
                       source_id="m1"))
    store.upsert(**_mk(classify_text("nvme", "[2.0] nvme nvme0: I/O timeout"),
                       source_id="m2"))
    assert store.list(subsystem="memory")[0]["fault_class"] == "oom"
    assert store.list(subsystem="storage", fault_class="nvme")[0]["source_id"] == "m2"
    stats = store.stats()
    assert stats["total"] == 2
    assert {s["subsystem"] for s in stats["subsystems"]} == {"memory", "storage"}


def test_record_is_tiny(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c = classify_text("nvme timeout", "[1.0] nvme nvme0: I/O 12 timeout, reset")
    store.upsert(**_mk(c, source_id="m1",
                       root="firmware bug fixed in FW 1.3",
                       fix={"upgrade_to": "FW 1.3"}))
    # the distilled record must stay far below 1 KB on disk
    size = (tmp_path / "ki.db").stat().st_size
    assert size < 8192, f"store grew to {size} bytes for one record"


def test_fix_pointers_and_snippets_are_bounded(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c = classify_text("nvme timeout", "[1.0] nvme nvme0: I/O 12 timeout")
    store.upsert(**_mk(c, fix={"url": "https://example/" + "x" * 400,
                               "bug": "1234567890"}))
    row = store.get(1)
    assert len(row["fix"]["url"]) == 300
    assert row["fix"]["bug"] == "1234567890"
    store.set_extraction(1, symptom="s", root_cause="r", fix={},
                         log_snippets=["x" * 500] * 6, confidence=0.5)
    row = store.get(1)
    assert len(row["log_snippets"]) == 4
    assert all(len(snippet) == 200 for snippet in row["log_snippets"])


def test_watermark_cursor(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    assert store.get_watermark("lore") == ""
    store.set_watermark("lore", "2026-11-28T00:00:00Z")
    assert store.get_watermark("lore") == "2026-11-28T00:00:00Z"


# ------------------------------------------------------------------- mbox

_MBOX = """From a@example.com Mon Nov 25 10:00:00 2026
Message-ID: <msg1@example.com>
Date: Mon, 25 Nov 2026 10:00:00 +0000
Subject: [PATCH] nvme: fix timeout on controller reset

[ 456.789] nvme nvme0: I/O 12 QID 1 timeout, reset controller

From b@example.com Mon Nov 26 10:00:00 2026
Message-ID: <msg2@example.com>
Date: Tue, 26 Nov 2026 10:00:00 +0000
Subject: OOM killer kills chrome

[ 123.456] Out of memory: Killed process 1234 (chrome)

"""


def test_iter_mbox(tmp_path):
    path = tmp_path / "lore.mbox"
    path.write_text(_MBOX)
    issues = iter_mbox(str(path))
    assert len(issues) == 2
    assert issues[0]["source_id"] == "msg1@example.com"
    assert issues[0]["url"] == "https://lore.kernel.org/all/msg1@example.com/"
    assert "nvme" in issues[0]["body"]
    assert issues[1]["date"].startswith("2026-11-26")


def test_learn_parser_defaults():
    p = build_parser()
    args = p.parse_args(["--mbox", "x.mbox"])
    assert args.source == "lore" and args.interval == 3600 and not args.loop


def test_learn_registered():
    from dmesg_agent import plugins as pf
    pf.registry.reset()
    pf.load_plugins()
    assert pf.registry.named("command", "learn") is not None


def test_classify_ata_is_storage_not_network():
    # "SATA link failure" must not be misread as a network link
    c = classify_text("ata6 SATA link failure disables device",
                      "ata6: SError: { CommWake }\nata6: hardreset failed")
    assert c.subsystem == "storage"
    assert c.fault_class == "ata"
    assert "network" not in c.subsystems


def test_iter_mbox_supports_gzip(tmp_path):
    path = tmp_path / "lore.mbox.gz"
    with gzip.open(path, "wt") as f:
        f.write(_MBOX)
    issues = iter_mbox(str(path))
    assert len(issues) == 2


def test_iter_mbox_rejects_html(tmp_path):
    path = tmp_path / "search.html"
    path.write_text("<!doctype html><html><title>search</title></html>")
    with pytest.raises(ValueError, match="HTML"):
        iter_mbox(str(path))


def test_iter_mbox_rejects_non_mbox(tmp_path):
    path = tmp_path / "empty.mbox"
    path.write_text("just some prose, no mail envelope")
    with pytest.raises(ValueError, match="no messages"):
        iter_mbox(str(path))


def test_learn_reports_bad_input_and_exits_2(tmp_path, capsys):
    path = tmp_path / "search.html"
    path.write_text("<html><body>not an mbox</body></html>")
    code = learn(["--mbox", str(path), "--db", str(tmp_path / "ki.db")])
    captured = capsys.readouterr()
    assert code == 2
    assert "HTML" in captured.err


def test_primary_class_follows_first_signal():
    # A patch thread can quote an unrelated "Failed to start" line later; the
    # primary L1/L2 must follow the first signal (nvme), not alphabetical order.
    c = classify_text("nvme-tcp: validate the TLS handshake timeout",
                      "nvme: timeout\nFailed to start foo.service")
    assert c.subsystem == "storage"
    assert c.fault_class == "nvme"
    assert "service" in c.subsystems  # still multi-label


def test_lore_search_request_shape():
    url, data, headers = _lore_request("nvme timeout", full_threads=False)
    assert "q=nvme+timeout" in url and url.endswith("&x=m")
    assert data == b"z=results+only"
    assert "dmesg-agent" in headers["User-Agent"] and "renhai2.k@gmail.com" in headers["User-Agent"]
    _url, data2, _h = _lore_request("x", full_threads=True)
    assert data2 == b"x=full+threads"


class _FakeResp:
    def __init__(self, body: bytes):
        self.body, self.pos = body, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self, n=-1):
        chunk = self.body[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


def test_fetch_lore_search_mocked(monkeypatch, tmp_path):
    from dmesg_agent.plugins import learn as learn_mod
    body = gzip.compress(_MBOX.encode())
    monkeypatch.setattr(learn_mod.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    calls = []
    path = fetch_lore_search("nvme timeout", max_mb=1, progress=calls.append)
    try:
        issues = iter_mbox(path)
        assert len(issues) == 2
        assert calls and calls[-1] == len(body)
    finally:
        __import__("pathlib").Path(path).unlink(missing_ok=True)


def test_fetch_lore_search_size_cap(monkeypatch):
    from dmesg_agent.plugins import learn as learn_mod
    body = b"x" * (2 * 1024 * 1024)
    monkeypatch.setattr(learn_mod.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    with pytest.raises(ValueError, match="exceeds"):
        fetch_lore_search("broad query", max_mb=1)


def test_learn_lore_search_end_to_end(monkeypatch, tmp_path, capsys):
    from dmesg_agent.plugins import learn as learn_mod
    src = tmp_path / "search.mbox"
    src.write_text(_MBOX)
    monkeypatch.setattr(learn_mod, "fetch_lore_search",
                        lambda query, full_threads=False, max_mb=128, progress=None: str(src))
    db = tmp_path / "ki.db"
    code = learn(["--lore-search", "nvme timeout", "--db", str(db), "--limit", "10"])
    assert code == 0
    from dmesg_agent.knownissues import KnownIssueStore
    store = KnownIssueStore(db)
    assert store.count() == 2


def test_noise_filter_releases_and_review_series():
    assert is_noise_issue("Linux 6.12.120-rc2 review", "",
                          classify_text("Linux 6.12.120-rc2 review"))
    assert is_noise_issue("[PATCH 6.12 000/816] 6.12.120-rc1 review", "",
                          classify_text("[PATCH 6.12 000/816] 6.12.120-rc1 review"))
    assert is_noise_issue("random discussion with no signal", "",
                          classify_text("random discussion with no signal"))


def test_noise_filter_keeps_specific_issues():
    title = "[PATCH 6.12 378/816] nvmet-tcp: validate the TLS handshake timeout"
    assert not is_noise_issue(title, "", classify_text(title))
    oom_line = "[1.0] Out of memory: Killed process 1 (x)"
    assert not is_noise_issue("OOM", oom_line, classify_text("OOM", oom_line))


def test_noise_filter_bulk_mail_kinds():
    for title in (
        "[GIT PULL] nvme updates for Linux 7.4",
        "[ANNOUNCE] Release v6.12.114-cip34",
        "[meta-yocto][scarthgap 3/3] yocto-bsps: update to v6.6.160",
        "[OE-core][scarthgap 42/55] linux-yocto/6.6: update to v6.6.157",
        'FAILED: patch "[PATCH] nvmet-tcp: validate the TLS handshake timeout"',
        "Re: Linux 7.1-rc2",
        "[PULL] drm-misc-next",
        "Fwd: intel-gfx-bugs Digest, Vol 91, Issue 2",
    ):
        assert is_noise_issue(title, "", classify_text(title)), title
    title = "[PATCH] nvmet-tcp: fix use-after-free when TLS handshake completes"
    assert not is_noise_issue(title, "", classify_text(title))


def test_series_key_collapses_versions_and_replies():
    a = series_key("[PATCH v3 1/2] nvmet-tcp: validate the TLS handshake timeout")
    b = series_key("Re: [PATCH v2 2/2] nvmet-tcp: validate the TLS handshake timeout")
    assert a == b == "nvmet-tcp: validate the tls handshake timeout"


def test_store_dedupes_patch_series(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c1 = classify_text("[PATCH v2 1/2] nvmet-tcp: validate TLS handshake timeout", "")
    c2 = classify_text("[PATCH v3 2/2] nvmet-tcp: validate TLS handshake timeout", "")
    key = series_key("[PATCH v2 1/2] nvmet-tcp: validate TLS handshake timeout")
    assert store.upsert(source="lore", source_id="a", url="https://lore/a",
                        title="v2 patch", classification=c1, series_key=key) is True
    assert store.upsert(source="lore", source_id="b", url="https://lore/b",
                        title="v3 patch", classification=c2, series_key=key) is False
    assert store.count() == 1
    assert store.get(1)["urls"] == ["https://lore/a", "https://lore/b"]


def test_primary_prefers_title_subsystem_over_generic_signal():
    c = classify_text("[PATCH 75/98] nvmet-tcp: hold the queue while the TLS timer is armed",
                      "Failed to start foo.service")
    assert c.subsystem == "storage"
    assert c.fault_class == "unclassified"  # no storage signature in the text


def test_primary_ignores_noise_class_when_title_is_specific():
    c = classify_text("[PATCH 5/7] nvmet-tcp: add wq_unbound module parameter",
                      "No space left on device")
    assert c.subsystem == "storage"


def test_fetch_lore_search_rejects_html_early(monkeypatch, tmp_path):
    from dmesg_agent.plugins import learn as learn_mod
    body = b"<!doctype html><html><body>search page</body></html>" + b"x" * 100
    monkeypatch.setattr(learn_mod.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    with pytest.raises(ValueError, match="HTML"):
        fetch_lore_search("x", max_mb=1)


def test_learn_extracts_pending_records(tmp_path, monkeypatch):
    from dmesg_agent.plugins import learn as learn_mod
    src = tmp_path / "m.mbox"
    src.write_text(_MBOX)
    calls = []

    def fake_extract(client, title, body):
        calls.append(title)
        return {"symptom": "s", "root_cause": "rc",
                "fix": {"commit": "abc123"}, "log_snippets": [],
                "confidence": 0.9}

    monkeypatch.setattr(learn_mod, "extract_issue", fake_extract)
    db = tmp_path / "ki.db"
    code = learn(["--mbox", str(src), "--db", str(db), "--extract",
                  "--max-extract", "1"])
    assert code == 0
    assert len(calls) == 1
    store = KnownIssueStore(db)
    extracted = [r for r in store.list() if r["extracted"]]
    assert len(extracted) == 1
    assert extracted[0]["root_cause"] == "rc"
    assert extracted[0]["fix"]["commit"] == "abc123"
    assert extracted[0]["confidence"] == 0.9


def test_ci_noise_filtered():
    for title in (
        "\u2714 CI.Hooks: success for drm/xe: Fix build",
        "=?utf-8?q?=E2=9C=93_CI=2EHooks=3A_success_for_drm/xe?=",
        "\u2717 CI.Hooks: failure for XE HDCP Enablement",
    ):
        assert is_noise_issue(title, "", classify_text(title)), title


def test_iter_mbox_decodes_rfc2047_subject(tmp_path):
    path = tmp_path / "ci.mbox"
    path.write_text(
        "From a@example.com Mon Nov 25 10:00:00 2026\n"
        "Message-ID: <ci@example.com>\n"
        "Date: Mon, 25 Nov 2026 10:00:00 +0000\n"
        "Subject: =?utf-8?q?=E2=9C=93_CI=2EHooks=3A_success_for_drm/xe?=\n"
        "\n"
        "CI body\n\n")
    issues = iter_mbox(str(path))
    assert "CI.Hooks" in issues[0]["title"]


def test_search_ranks_exact_fingerprint_before_same_class(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    line0 = "[1.0] nvme nvme0: I/O 12 timeout, reset controller"
    line1 = "[2.0] nvme nvme1: I/O 99 timeout, reset controller"
    c0 = classify_text("nvme timeout", line0)
    c1 = classify_text("nvme timeout", line1)
    assert c0.fault_class == c1.fault_class == "nvme"
    assert c0.fingerprint != c1.fingerprint
    store.upsert(source="lore", source_id="m0", url="u0", title="a",
                 classification=c0)
    store.upsert(source="lore", source_id="m1", url="u1", title="b",
                 classification=c1)
    hits = store.search(fingerprint=c0.fingerprint, fault_classes=c0.fault_classes,
                        subsystems=c0.subsystems, tokens=c0.tokens)
    assert [h["id"] for h in hits[:2]] == [1, 2]
    assert "exact fingerprint" in hits[0]["match"]
    assert "same fault class" in hits[1]["match"]


def test_search_ignores_generic_fault_classes(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    c = classify_text("i8042 keylock",
                      "[2.668332] i8042: Warning: Keylock active")
    assert c.fault_class == "warning"
    store.upsert(source="lore", source_id="m1", url="u", title="keylock",
                 classification=c)
    # "warning" is a generic triage bucket, not a similarity signal
    assert store.search(fault_classes=["warning"]) == []


def test_search_ignores_unrelated_issues(tmp_path):
    store = KnownIssueStore(tmp_path / "ki.db")
    oom = classify_text("oom", "[1.0] Out of memory: Killed process 1 (x)")
    store.upsert(source="lore", source_id="m1", url="u", title="oom",
                 classification=oom)
    q = classify_text("nvme timeout", "[2.0] nvme nvme0: I/O 12 timeout")
    assert store.search(fingerprint=q.fingerprint, fault_classes=q.fault_classes,
                        subsystems=q.subsystems, tokens=q.tokens) == []


def test_noise_filter_pull_tag_anywhere():
    # lore prefixes list tags: [Intel-gfx] [PULL] drm-misc-next must still be
    # rejected, as must a Re: [GIT PULL] mail.
    for title in ("[Intel-gfx] [PULL] drm-misc-next",
                  "Re: [GIT PULL] nvme fixes for Linux 7.4"):
        assert is_noise_issue(title, "", classify_text(title)), title


def test_max_extract_caps_attempts_even_when_empty(tmp_path, monkeypatch):
    from dmesg_agent.plugins import learn as learn_mod
    src = tmp_path / "m.mbox"
    src.write_text(_MBOX)
    calls = []

    def empty_extract(client, title, body):
        calls.append(title)
        return None

    monkeypatch.setattr(learn_mod, "extract_issue", empty_extract)
    code = learn(["--mbox", str(src), "--db", str(tmp_path / "ki.db"),
                  "--extract", "--max-extract", "1"])
    assert code == 0
    assert len(calls) == 1
