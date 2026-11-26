from dmesg_agent.verify import verify_result

LOG = [
    "[    0.000000] Linux version 6.12.11+deb13-amd64",
    "[ 2345.679000] Out of memory: Killed process 12345 (chrome) total-vm:12345678kB",
    "[ 3456.789012] watchdog: BUG: soft lockup - CPU#2 stuck for 23s!",
]


def _result(evidences):
    return {"findings": [{"title": "t", "evidence": evidences}]}


def test_exact_quote_verified():
    r = _result([{"line": 2, "quote": "Out of memory: Killed process 12345 (chrome) total-vm:12345678kB"}])
    s = verify_result(r, LOG)
    assert s.passed == 1 and s.total == 1
    assert r["findings"][0]["evidence"][0]["verified"] is True


def test_wrong_line_number_still_matches_content():
    r = _result([{"line": 99, "quote": "watchdog: BUG: soft lockup - CPU#2 stuck for 23s!"}])
    s = verify_result(r, LOG)
    ev = r["findings"][0]["evidence"][0]
    assert ev["verified"] is True and ev["actual_line"] == 3
    assert s.line_mismatch == 1


def test_fabricated_quote_flagged():
    r = _result([{"line": 1, "quote": "kernel panic - not syncing: VFS: Unable to mount root"}])
    s = verify_result(r, LOG)
    ev = r["findings"][0]["evidence"][0]
    assert ev["verified"] is False
    assert s.passed == 0 and s.total == 1
    assert r["findings"][0]["evidence_verified"] is False


def test_quote_with_timestamp_prefix_ok():
    r = _result([{"line": 2, "quote": "[ 2345.679000] Out of memory: Killed process 12345 (chrome)"}])
    s = verify_result(r, LOG)
    assert s.passed == 1


def test_short_quote_requires_exact():
    r = _result([{"line": 1, "quote": "error"}])
    s = verify_result(r, LOG)
    assert s.passed == 0


from dmesg_agent.verify import verify_result


def test_line_drift_within_five_auto_corrects():
    log = ["[ 1.0] alpha event", "[ 2.0] beta event", "[ 3.0] gamma event",
           "[ 4.0] delta event", "[ 5.0] eps event", "[ 6.0] zeta event"]
    result = {"findings": [{"title": "t", "evidence": [
        {"line": 6, "quote": "beta event"}]}]}  # claimed 6, actually 2 → drift
    s = verify_result(result, log)
    assert s.passed == 1
    assert result["findings"][0]["evidence"][0]["verified"] is True
    assert result["findings"][0]["evidence"][0]["actual_line"] == 2
    assert s.line_mismatch == 1


def test_drift_and_fabrication_still_distinct():
    log = ["[ 1.0] real line"]
    result = {"findings": [{"title": "t", "evidence": [
        {"line": 1, "quote": "totally invented"}]}]}
    verify_result(result, log)
    assert result["findings"][0]["evidence"][0]["verified"] is False
