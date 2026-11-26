"""Offline guard for the eval harness: every case must score fully with the
stub client, and all expected.json files must be well-formed. Catches harness
and fixture regressions without any network or LLM."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evals.run_eval import StubClient, aggregate, run_case, score_case  # noqa: E402

CASES = ROOT / "evals" / "cases"


def test_offline_stub_locates_every_case():
    rows = {}
    for case in sorted(CASES.iterdir()):
        if (case / "expected.json").exists():
            lines = (case / "log.txt").read_text().splitlines()
            rows[case.name] = run_case(case, StubClient(lines))
    assert rows, "no eval cases found"
    m = aggregate(rows)
    assert m["locate_rate"] == 1.0, rows
    assert m["evidence_rate"] == 1.0, rows


def test_expected_files_valid():
    for case in sorted(CASES.iterdir()):
        exp = json.loads((case / "expected.json").read_text())
        assert exp["id"] == case.name
        e = exp["expect"]
        assert e.get("subsystem") or e.get("any_keywords"), case.name
        assert (case / "log.txt").read_text().strip(), case.name


def test_score_case_detects_wrong_subsystem():
    expect = {"expect": {"subsystem": ["storage"], "severity": ["high"],
                         "any_keywords": ["nvme"]}, "must_not_dismiss": []}
    bad = {"findings": [{"title": "nvme timeout", "subsystem": "gpu", "severity": "high",
                         "evidence": [{"quote": "x", "verified": True}]}]}
    assert not score_case(bad, expect)["located"]


def test_score_case_detects_hallucinated_quote():
    expect = {"expect": {"subsystem": ["memory"], "severity": [], "any_keywords": ["oom"]},
              "must_not_dismiss": []}
    res = {"findings": [{"title": "oom kill", "subsystem": "memory", "severity": "high",
                         "evidence": [{"quote": "made up", "verified": False}]}]}
    assert not score_case(res, expect)["evidence_ok"]


def test_score_case_detects_bad_dismissal():
    expect = {"expect": {"subsystem": ["memory"], "severity": [], "any_keywords": ["oom"]},
              "must_not_dismiss": ["out of memory"]}
    res = {"findings": [{"title": "oom", "subsystem": "memory", "severity": "high",
                         "evidence": [{"quote": "x", "verified": True}]}],
           "dismissed_concerns": [{"counter_evidence_quote": "Out of memory happened",
                                   "quote_verified": True}]}
    assert not score_case(res, expect)["dismissal_ok"]


def test_cli_runner_smoke():
    r = subprocess.run([sys.executable, str(ROOT / "evals" / "run_eval.py"), "--json"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["metrics"]["cases"] >= 5
