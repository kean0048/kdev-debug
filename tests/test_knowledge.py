import json
import os
import sqlite3

from dmesg_agent.knowledge import (
    DEFAULT_FUZZY,
    _jaccard,
    cases_main,
    evidence_fingerprint,
    record_run,
    text_words,
)


def _finding(title, sub="storage", cause="failing ssd media wear", evidence=None):
    return {"title": title, "subsystem": sub, "root_cause_hypothesis": cause,
            "severity": "high", "evidence": evidence or []}


def _run(db, findings, host="host1", now=None, **kw):
    result = {"findings": findings, "summary": "summary"}
    return record_run(db, host, result, now=now or "2026-01-01T00:00:00", **kw)


def _rows(db, sql, params=()):
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


# ------------------------------------------------ legacy text fallback

def test_same_run_no_recurrence(tmp_path):
    f = _finding("NVMe I/O timeout")
    _run(tmp_path / "kb.db", [f])
    assert "recurrence" not in f
    assert f["case"]["occurrences"] == 1


def test_repeat_run_counts_recurrence(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("NVMe I/O timeout")])
    f = _finding("NVMe I/O timeout")
    _run(db, [f])
    assert f["recurrence"]["count"] == 2
    assert f["case"]["tier"] == "exact"


def test_near_duplicate_words_merge(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("nvme i/o timeout reset controller")])
    f = _finding("nvme i/o timeout abort controller")
    _run(db, [f])
    assert f["recurrence"]["count"] == 2
    assert f["case"]["tier"] == "merged"


def test_different_bug_not_merged(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("nvme i/o timeout reset controller")])
    f = _finding("out of memory killed chrome", "memory", "memory cgroup limit too low")
    _run(db, [f])
    assert "recurrence" not in f


def test_jaccard_threshold_semantics():
    a = text_words("storage nvme i/o timeout failing ssd media")
    b = text_words("storage nvme timeout failing ssd media")
    assert _jaccard(a, b) >= 0.5
    c = text_words("memory oom killed process chrome")
    assert _jaccard(a, c) < 0.5


def test_host_isolation(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("oom kill chrome")], host="host-a")
    f_b = _finding("oom kill chrome")
    _run(db, [f_b], host="host-b")
    assert "recurrence" not in f_b
    f_a = _finding("oom kill chrome")
    _run(db, [f_a], host="host-a")
    assert f_a["recurrence"]["count"] == 2


def test_db_file_mode_and_rows(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("nvme i/o timeout")])
    assert os.stat(db).st_mode & 0o777 == 0o600
    assert len(_rows(db, "SELECT * FROM cases")) == 1
    assert len(_rows(db, "SELECT * FROM occurrences")) == 1


def test_first_seen_preserved(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_finding("nvme timeout")], now="2026-01-01T00:00:00")
    f = _finding("nvme timeout")
    _run(db, [f], now="2026-06-01T00:00:00")
    assert f["recurrence"]["first_seen"] == "2026-01-01T00:00:00"
    assert f["case"]["occurrences"] == 2


# ------------------------------------------------ evidence fingerprints

def _oom(pid, size):
    return _finding("OOM kill", "memory", "memory pressure", evidence=[{
        "quote": f"[ 2345.679000] Out of memory: Killed process {pid} (chrome) "
                 f"total-vm:{size}kB, anon-rss:1234kB", "verified": True}])


def test_evidence_fp_stable_across_pids_and_sizes(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_oom(111, 1000)])
    f = _oom(999, 999999)
    _run(db, [f])
    assert f["case"]["tier"] == "exact"
    assert f["recurrence"]["count"] == 2


def test_evidence_fp_normalizes_sectors():
    a = evidence_fingerprint(["[ 1.0] I/O error, dev sda, sector 123 op 0x0:(READ)"])
    b = evidence_fingerprint(["[ 9.0] I/O error, dev sda, sector 987654321 op 0x0:(READ)"])
    assert a.value == b.value


def test_evidence_fp_separates_fault_classes():
    oom = evidence_fingerprint(["[ 1.0] Out of memory: Killed process 5 (java)"])
    nvme = evidence_fingerprint(
        ["[ 2.0] nvme nvme0: I/O 12 (QID 1) Q 0x0 timeout, reset controller"])
    assert oom.value != nvme.value
    assert oom.core["subsystem"] == ["memory"]
    assert "storage" in nvme.core["subsystem"]


ATA6 = [
    "[ 100.0] ata6: SError: { CommWake }",
    "[ 101.0] ata6: hardreset failed",
    "[ 102.0] ata6.00: disable device",
]


def _ata(dev):
    return _finding(f"{dev} link failure", "storage", "sata link",
                    evidence=[{"quote": q.replace("ata6", dev), "verified": True}
                              for q in ATA6])


def test_fuzzy_similar_case_creates_separate_case(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_ata("ata6")])
    fp_a, fp_b = evidence_fingerprint(ATA6), evidence_fingerprint(
        [q.replace("ata6", "ata2") for q in ATA6])
    assert fp_a.value != fp_b.value
    assert _jaccard(set(fp_a.tokens), set(fp_b.tokens)) >= DEFAULT_FUZZY
    f = _ata("ata2")
    _run(db, [f])
    assert f["case"]["tier"] == "fuzzy"
    assert f["case"]["similar_case_id"] is not None
    assert f["case"]["occurrences"] == 1
    assert len(_rows(db, "SELECT * FROM cases")) == 2


def test_duplicate_findings_within_one_run_count_once(tmp_path):
    db = tmp_path / "kb.db"
    f1, f2 = _oom(1, 10), _oom(2, 20)
    _run(db, [f1, f2])
    assert len(_rows(db, "SELECT * FROM cases")) == 1
    assert _rows(db, "SELECT occurrences FROM cases")[0]["occurrences"] == 1
    assert f1["case"]["id"] == f2["case"]["id"]


def test_shadow_mode_does_not_change_conclusions(tmp_path):
    f = _finding("NVMe I/O timeout")
    before = {k: f[k] for k in ("title", "subsystem", "root_cause_hypothesis", "severity")}
    _run(tmp_path / "kb.db", [f])
    assert {k: f[k] for k in before} == before


# ------------------------------------------------ lifecycle + CLI

def test_fixed_case_reopens_on_recurrence(tmp_path, capsys):
    db = tmp_path / "kb.db"
    _run(db, [_oom(1, 10)])
    case_id = _rows(db, "SELECT id FROM cases")[0]["id"]
    assert cases_main(["--db", str(db), "fixed", str(case_id)]) == 0
    f = _oom(2, 20)
    _run(db, [f])
    assert f["case"]["regression"] is True
    assert f["case"]["status"] == "candidate"
    assert f["recurrence"]["count"] == 2


def test_cases_cli_list_and_confirm(tmp_path, capsys):
    db = tmp_path / "kb.db"
    _run(db, [_oom(1, 10), _ata("ata6")])
    assert cases_main(["--db", str(db), "list"]) == 0
    out = capsys.readouterr().out
    assert "candidate" in out and "OOM kill" in out
    case_id = _rows(db, "SELECT id FROM cases ORDER BY id")[0]["id"]
    assert cases_main(["--db", str(db), "confirm", str(case_id)]) == 0
    assert _rows(db, "SELECT status FROM cases WHERE id=?", (case_id,))[0]["status"] == "confirmed"
    assert cases_main(["--db", str(db), "show", str(case_id)]) == 0
    assert "confirmed" in capsys.readouterr().out


def test_cases_cli_db_flag_after_subcommand(tmp_path, capsys):
    db = tmp_path / "kb.db"
    _run(db, [_oom(1, 10)])
    assert cases_main(["list", "--db", str(db)]) == 0
    assert "OOM kill" in capsys.readouterr().out


def test_cases_cli_unknown_id(tmp_path, capsys):
    db = tmp_path / "kb.db"
    _run(db, [_oom(1, 10)])
    assert cases_main(["--db", str(db), "confirm", "9999"]) == 1
    assert "not found" in capsys.readouterr().err


def test_occurrence_evidence_is_stored(tmp_path):
    db = tmp_path / "kb.db"
    _run(db, [_oom(1, 10)])
    stored = json.loads(_rows(db, "SELECT evidence_json FROM occurrences")[0]["evidence_json"])
    assert "Out of memory" in stored[0]
