import json
import subprocess

from dmesg_agent import scorecard
from dmesg_agent.scorecard import (
    build_card,
    collect_metrics,
    format_for_check,
    grade,
    latest_score,
    record,
    score_main,
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(tmp_path):
    root = tmp_path / "repo"
    _write(root / "pyproject.toml",
           '[project]\nname = "x"\ndependencies = ["requests"]\n')
    _write(root / "dmesg_agent" / "__init__.py",
           '"""Package."""\nfrom __future__ import annotations\n__version__ = "0.4.0"\n')
    for name in ("core", "io", "util"):
        _write(root / "dmesg_agent" / f"{name}.py",
               f'"""Module {name}."""\nfrom __future__ import annotations\n')
    _write(root / "tests" / "test_core.py", "def test_a():\n    pass\n\ndef test_b():\n    pass\n")
    _write(root / "evals" / "cases" / "c1" / "expected.json",
           json.dumps({"expect": {"subsystem": ["storage", "nvme"]}}))
    _write(root / "evals" / "cases" / "c1" / "log.txt", "[1.0] nvme error\n")
    _write(root / "evals" / "cases" / "c2" / "expected.json",
           json.dumps({"expect": {"subsystem": ["memory"]}}))
    _write(root / "evals" / "cases" / "c2" / "log.txt", "[1.0] oom\n")
    _write(root / "README.md", "# x\n")
    _write(root / "CLAUDE.md", "## Architecture\n")
    _write(root / ".github" / "workflows" / "ci.yml", "run: pytest\n")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(tmp_path)}
    subprocess.run(["git", "-C", str(root), "init", "-q", "."], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m",
                    "feat: storage and memory eval cases"], check=True, env=env)
    return root


def _eval_payload(detect=1.0, evidence=1.0, dismissal=1.0):
    return {"metrics": {"cases": 2, "detect_rate": detect, "evidence_rate": evidence,
                        "dismissal_rate": dismissal}, "cases": {}}


def test_collect_metrics(tmp_path):
    root = make_repo(tmp_path)
    m = collect_metrics(root)
    assert m["modules"] == 4
    assert m["test_functions"] == 2
    assert m["eval_cases"] == 2
    assert m["eval_categories"] == ["memory", "storage"]
    assert m["has_ci"] is True
    assert m["has_invariants"] is True
    assert m["runtime_deps"] == 1
    assert m["docstring_fraction"] == 1.0
    assert m["annotations_fraction"] == 1.0


def test_card_scores_in_bounds_and_weighted(tmp_path):
    root = make_repo(tmp_path)
    card = build_card(root, run_tests=False, eval_payload=_eval_payload())
    for key, section in card["sections"].items():
        assert 0.0 <= section["score"] <= 10.0, key
        assert all(item["points"] <= item["max"] for item in section["items"])
    expected = round(sum(scorecard.WEIGHTS[k] * card["sections"][k]["score"]
                         for k in scorecard.WEIGHTS), 1)
    assert card["overall"] == expected
    assert card["grade"] == grade(card["overall"])
    assert card["eval"]["mode"] == "stub"


def test_stub_mode_does_not_claim_live_accuracy(tmp_path):
    root = make_repo(tmp_path)
    card = build_card(root, run_tests=False, eval_payload=_eval_payload())
    live_item = next(i for i in card["sections"]["accuracy"]["items"]
                     if i["item"] == "live-model accuracy")
    assert live_item["points"] == 0.0
    assert "not run" in live_item["evidence"]


def test_live_mode_scores_accuracy(tmp_path):
    root = make_repo(tmp_path)
    stub = build_card(root, run_tests=False, eval_payload=_eval_payload())
    live = build_card(root, live=True, run_tests=False, eval_payload=_eval_payload())
    assert live["sections"]["accuracy"]["score"] > stub["sections"]["accuracy"]["score"]
    assert live["eval"]["mode"] == "live"


def test_record_writes_json_and_markdown(tmp_path):
    root = make_repo(tmp_path)
    card = build_card(root, run_tests=False, eval_payload=_eval_payload(), note="baseline")
    path = record(root, card)
    assert path.is_file() and path.parent.name == "scorecards"
    saved = json.loads(path.read_text())
    assert saved["note"] == "baseline"
    markdown = (root / "SCORECARD.md").read_text()
    assert f"## {card['week']}" in markdown
    assert "### Architecture" in markdown
    assert "### Accuracy" in markdown
    assert "live eval not run" in markdown
    assert "Improvement evidence" in markdown
    assert "feat: storage and memory eval cases" in markdown


def test_latest_score_reads_recorded_card(tmp_path):
    root = make_repo(tmp_path)
    card = build_card(root, run_tests=False, eval_payload=_eval_payload())
    record(root, card)
    assert latest_score(root)["week"] == card["week"]


def test_rerecord_same_week_does_not_compare_against_itself(tmp_path):
    root = make_repo(tmp_path)
    card = build_card(root, run_tests=False, eval_payload=_eval_payload())
    record(root, card)
    rebuilt = build_card(root, run_tests=False, eval_payload=_eval_payload())
    assert latest_score(root, before_week=rebuilt["week"]) is None
    assert rebuilt["improvement_basis"]["commits_count"] >= 1


def test_format_for_check():
    card = {"overall": 6.4, "week": "2026-W48", "version": "0.4.0",
            "scoring_start": "2026-W48",
            "sections": {"architecture": {"score": 8.3}, "accuracy": {"score": 5.2},
                         "improvement": {"score": 4.1}}}
    line = format_for_check(card)
    assert "6.4/10" in line and "2026-W48" in line and "SCORECARD.md" in line


def test_score_cli_json(tmp_path, capsys):
    root = make_repo(tmp_path)
    assert score_main(["--root", str(root), "--no-tests", "--json"]) == 0
    out = capsys.readouterr().out
    card = json.loads(out)
    assert card["week"] and card["sections"]["architecture"]["score"] > 0


def test_score_cli_rejects_missing_checkout(tmp_path, capsys):
    assert score_main(["--root", str(tmp_path), "--no-tests"]) == 2
    assert "no source checkout" in capsys.readouterr().err
