import json
import os

from dmesg_agent import tracking
from dmesg_agent.tracking import _jaccard, record_recurrences, state_path


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))


def _finding(title, sub="storage", cause="failing ssd media wear"):
    return {"title": title, "subsystem": sub, "root_cause_hypothesis": cause,
            "severity": "high", "evidence": []}


def _run(tmp_path, monkeypatch, findings, host="host1"):
    record_recurrences({"findings": findings}, host)
    return findings


def test_same_run_no_recurrence(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    f = _run(tmp_path, monkeypatch, [_finding("NVMe I/O timeout")])
    assert "recurrence" not in f[0]


def test_repeat_run_counts_recurrence(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch, [_finding("NVMe I/O timeout")])
    f = _run(tmp_path, monkeypatch, [_finding("NVMe I/O timeout")])
    assert f[0]["recurrence"]["count"] == 2


def test_near_duplicate_words_merge(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch, [_finding("nvme i/o timeout reset controller")])
    # fingerprint differs (reset→abort) but Jaccard >= 0.5 → merged as same bug
    f = _run(tmp_path, monkeypatch, [_finding("nvme i/o timeout abort controller")])
    assert f[0]["recurrence"]["count"] == 2


def test_different_bug_not_merged(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch, [_finding("nvme i/o timeout reset controller")])
    f = _run(tmp_path, monkeypatch,
             [_finding("out of memory killed chrome", "memory",
                       "memory cgroup limit too low")])
    assert "recurrence" not in f[0]


def test_jaccard_threshold_semantics():
    w = tracking._words
    a = w("storage nvme i/o timeout failing ssd media")
    b = w("storage nvme timeout failing ssd media")
    assert _jaccard(a, b) >= tracking.JACCARD_SAME      # same bug, reworded
    c = w("memory oom killed process chrome")
    assert _jaccard(a, c) < tracking.JACCARD_SAME        # different bug


def test_host_isolation(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch, [_finding("oom kill chrome")], host="host-a")
    f_b = _run(tmp_path, monkeypatch, [_finding("oom kill chrome")], host="host-b")
    assert "recurrence" not in f_b[0]
    f_a = _run(tmp_path, monkeypatch, [_finding("oom kill chrome")], host="host-a")
    assert f_a[0]["recurrence"]["count"] == 2


def test_state_file_mode_0600_and_shape(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch, [_finding("nvme i/o timeout")])
    assert os.stat(state_path()).st_mode & 0o777 == 0o600
    data = json.loads(state_path().read_text())
    assert "host1" in data and len(data["host1"]) == 1


def test_first_seen_preserved(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record_recurrences({"findings": [_finding("nvme timeout")]}, "h",
                       now="2026-01-01T00:00:00")
    f = [_finding("nvme timeout")]
    record_recurrences({"findings": f}, "h", now="2026-06-01T00:00:00")
    assert f[0]["recurrence"]["first_seen"] == "2026-01-01T00:00:00"
    assert f[0]["recurrence"]["count"] == 2
