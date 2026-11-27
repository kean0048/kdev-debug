"""Weekly software scorecard: architecture, accuracy, improvement.

The score is computed from deterministic, reproducible measurements — never
from model self-assessment:

- Architecture: module layout, test density, docs/invariants, CI, dependency
  hygiene, annotation consistency.
- Accuracy: eval-suite coverage plus the measured detect/evidence/dismissal
  rates from ``evals/run_eval.py`` (offline stub by default; ``--live`` records
  real-model accuracy).
- Improvement: commits, lines and test/eval-case growth since the previous
  scorecard (or the last 7 days for the first card), plus a passing test run.

Every recorded week lives in two committed artifacts:

- ``dmesg_agent/scorecards/<YYYY-Www>.json`` — machine-readable basis
  (metrics, per-item points, evidence strings, eval results, commit list).
- ``SCORECARD.md`` — the human-readable history regenerated from the JSON.

Scoring starts with the release that introduced this module; users installing
later inherit that history from ``dmesg-agent check``.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from . import __version__

RUBRIC_VERSION = 1
WEIGHTS = {"architecture": 0.35, "accuracy": 0.45, "improvement": 0.20}
SCORING_START = "2026-W48"  # first week a scorecard was recorded

_MAX_POINTS = {"architecture": 10.0, "accuracy": 10.0, "improvement": 10.0}

_CATEGORY_MAP = [
    ("storage", ("storage", "nvme", "disk", "ext4", "xfs", "btrfs", "sata", "i/o")),
    ("memory", ("memory", "oom", "swap")),
    ("gpu", ("gpu", "drm", "amdgpu", "nvidia", "nouveau")),
    ("network", ("network", "net", "eth", "wlan", "wifi", "tcp")),
    ("locking", ("locking", "lockup", "hung", "rcu", "deadlock", "sched")),
    ("service", ("service", "systemd", "userspace")),
]


# ------------------------------------------------------------- helpers

def _git(root: Path, *args: str, timeout: int = 60) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def iso_week(d: date | None = None) -> str:
    cal = (d or date.today()).isocalendar()
    return f"{cal.year}-W{cal.week:02d}"


def _module_docstring(path: Path) -> bool:
    try:
        return ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) is not None
    except (SyntaxError, OSError):
        return False


def _count_test_functions(tests_dir: Path) -> int:
    total = 0
    for path in tests_dir.glob("test_*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            continue
        total += sum(1 for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.name.startswith("test_"))
    return total


def _eval_cases(root: Path) -> tuple[int, list[str], int]:
    cases_dir = root / "evals" / "cases"
    if not cases_dir.is_dir():
        return 0, [], 0
    count, categories, expected = 0, set(), 0
    for case in sorted(cases_dir.iterdir()):
        exp_path = case / "expected.json"
        if not exp_path.is_file():
            continue
        count += 1
        try:
            data = json.loads(exp_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        expected += int(data.get("expected_count", 1))
        for sub in data.get("expect", {}).get("subsystem", []):
            s = str(sub).lower()
            for name, keys in _CATEGORY_MAP:
                if any(k in s for k in keys):
                    categories.add(name)
    return count, sorted(categories), expected


def collect_metrics(root: Path) -> dict:
    pkg = root / "dmesg_agent"
    modules = sorted(pkg.rglob("*.py")) if pkg.is_dir() else []
    locs = {}
    for path in modules:
        try:
            locs[str(path.relative_to(root))] = sum(
                1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip())
        except OSError:
            continue
    docstrings = sum(1 for p in modules if _module_docstring(p))
    annotations = sum(1 for p in modules if "from __future__ import annotations" in
                      p.read_text(encoding="utf-8", errors="replace"))

    deps: list[str] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            text = ""
        if tomllib is not None:
            try:
                deps = tomllib.loads(text).get("project", {}).get("dependencies", [])
            except tomllib.TOMLDecodeError:
                pass
        else:  # Python 3.10: minimal dependency-list extraction
            m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL)
            deps = re.findall(r'"([^"]+)"', m.group(1)) if m else []

    workflows = root / ".github" / "workflows"
    has_ci = False
    if workflows.is_dir():
        has_ci = any("pytest" in p.read_text(encoding="utf-8", errors="replace")
                     for p in workflows.glob("*.yml"))

    claude = root / "CLAUDE.md"
    has_invariants = claude.is_file() and "Architecture" in claude.read_text(
        encoding="utf-8", errors="replace")

    test_files = sorted((root / "tests").glob("test_*.py")) if (root / "tests").is_dir() else []
    eval_cases, eval_categories, expected_bugs = _eval_cases(root)
    largest = max(locs.items(), key=lambda kv: kv[1]) if locs else ("", 0)
    head = _git(root, "rev-parse", "--short", "HEAD").strip()

    return {
        "version": __version__,
        "week": iso_week(),
        "date": date.today().isoformat(),
        "git_head": head,
        "modules": len(modules),
        "module_loc": sum(locs.values()),
        "largest_module": largest[0],
        "largest_module_lines": largest[1],
        "docstring_fraction": round(docstrings / len(modules), 2) if modules else 0.0,
        "annotations_fraction": round(annotations / len(modules), 2) if modules else 0.0,
        "test_files": len(test_files),
        "test_functions": _count_test_functions(root / "tests") if test_files else 0,
        "runtime_deps": len(deps),
        "has_readme": (root / "README.md").is_file(),
        "has_invariants": has_invariants,
        "has_ci": has_ci,
        "eval_cases": eval_cases,
        "eval_categories": eval_categories,
        "expected_bugs": expected_bugs,
    }


def _parse_shortstat(text: str) -> tuple[int, int]:
    files = insertions = 0
    m = re.search(r"(\d+) files? changed", text)
    if m:
        files = int(m.group(1))
    m = re.search(r"(\d+) insertions?\(\+\)", text)
    if m:
        insertions = int(m.group(1))
    return files, insertions


def collect_improvement(root: Path, prev: dict | None, metrics: dict,
                        run_tests: bool = True) -> dict:
    head = metrics.get("git_head") or "unknown"
    if prev and prev.get("git_head"):
        base = prev["git_head"]
        base_desc = f"{base} (previous scorecard {prev.get('week', '?')})"
        rng = f"{base}..HEAD"
    else:
        base_desc = f"7 days before {head} (baseline week)"
        since_commit = _git(root, "rev-list", "-1", "--before", "7 days ago", "HEAD").strip()
        if not since_commit:
            # repo younger than the window: measure from its root commit so the
            # commit count and diff stats stay consistent with each other
            roots = _git(root, "rev-list", "--max-parents=0", "HEAD").split()
            since_commit = roots[-1] if roots else ""
            if since_commit:
                base_desc = f"repository start {since_commit[:7]} (baseline week)"
        rng = f"{since_commit}..HEAD" if since_commit else ""

    subjects: list[str] = []
    if rng:
        subjects = [ln for ln in _git(root, "log", "--pretty=format:%h %s", rng,
                                      "-n", "20").splitlines() if ln.strip()]
    elif not prev:
        subjects = [ln for ln in _git(root, "log", "--pretty=format:%h %s",
                                      "--since", "7 days ago", "-n", "20").splitlines()
                    if ln.strip()]
    if not prev and not subjects:
        # baseline from the repository root: root..HEAD excludes the root
        # commit itself, so fall back to the full history for the evidence list
        subjects = [ln for ln in _git(root, "log", "--pretty=format:%h %s",
                                      "-n", "20").splitlines() if ln.strip()]

    files_changed = insertions = 0
    if rng:
        files_changed, insertions = _parse_shortstat(_git(root, "diff", "--shortstat", rng))

    prev_test = int(prev.get("metrics", {}).get("test_functions", 0)) if prev else None
    prev_eval = int(prev.get("metrics", {}).get("eval_cases", 0)) if prev else None
    test_delta = metrics["test_functions"] - prev_test if prev_test is not None else None
    eval_delta = metrics["eval_cases"] - prev_eval if prev_eval is not None else None

    tests_pass: bool | None = None
    if run_tests:
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q"],
                                  cwd=root, capture_output=True, text=True, timeout=300)
            tests_pass = proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            tests_pass = None

    return {
        "base": base_desc,
        "commits_count": len(subjects),
        "commits": subjects,
        "files_changed": files_changed,
        "insertions": insertions,
        "test_delta": test_delta,
        "eval_case_delta": eval_delta,
        "tests_pass": tests_pass,
    }


def run_eval(root: Path, live: bool = False, base_url: str | None = None,
             model: str | None = None, api_key: str | None = None) -> dict | None:
    runner = root / "evals" / "run_eval.py"
    if not runner.is_file():
        return None
    cmd = [sys.executable, str(runner), "--json"]
    if live:
        cmd.append("--live")
        for flag, value in (("--base-url", base_url), ("--model", model), ("--api-key", api_key)):
            if value:
                cmd.extend([flag, value])
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                              timeout=3600 if live else 300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


# ------------------------------------------------------------- scoring

def _item(name: str, points: float, maximum: float, evidence: str) -> dict:
    return {"item": name, "points": round(points, 2), "max": maximum, "evidence": evidence}


def _section(items: list[dict]) -> dict:
    return {"score": round(sum(i["points"] for i in items), 2), "max": 10.0, "items": items}


def score_architecture(m: dict) -> dict:
    items = [
        _item("modularity (module count)", 1.5 if m["modules"] >= 10 else 0.75, 1.5,
              f"{m['modules']} modules, {m['module_loc']} lines"),
        _item("largest module stays reviewable", 1.0 if m["largest_module_lines"] <= 1200 else 0.0,
              1.0, f"{m['largest_module'] or 'n/a'} = {m['largest_module_lines']} lines (cap 1200)"),
        _item("test-file density", 1.0 if m["test_files"] >= max(1, m["modules"] / 2) else 0.5,
              1.0, f"{m['test_files']} test files / {m['modules']} modules"),
        _item("test functions", min(1.5, m["test_functions"] / 60 * 1.5), 1.5,
              f"{m['test_functions']} test functions (full credit at 60)"),
        _item("docs", (0.5 if m["has_readme"] else 0.0) + (0.5 if m["has_invariants"] else 0.0),
              1.0, f"README={m['has_readme']}, invariant docs (CLAUDE.md Architecture)={m['has_invariants']}"),
        _item("module docstrings", 0.5 if m["docstring_fraction"] >= 0.8 else 0.0, 0.5,
              f"{m['docstring_fraction']:.0%} of modules documented"),
        _item("CI runs tests", 1.5 if m["has_ci"] else 0.0, 1.5, f"CI-with-pytest={m['has_ci']}"),
        _item("dependency hygiene", 1.0 if m["runtime_deps"] <= 2 else 0.5 if m["runtime_deps"] <= 4 else 0.0,
              1.0, f"{m['runtime_deps']} runtime dependencies"),
        _item("future annotations", 1.0 if m["annotations_fraction"] >= 0.8 else 0.5 if m["annotations_fraction"] >= 0.5 else 0.0,
              1.0, f"{m['annotations_fraction']:.0%} of modules"),
    ]
    return _section(items)


def score_accuracy(m: dict, eval_payload: dict | None, live: bool) -> dict:
    categories = len(m.get("eval_categories") or [])
    cases = int(m.get("eval_cases") or 0)
    metrics = (eval_payload or {}).get("metrics") or {}
    ran = bool(metrics)
    items = [
        _item("eval category coverage", min(3.0, categories * 0.6), 3.0,
              f"{categories} categories: {', '.join(m.get('eval_categories') or []) or 'none'}"),
        _item("eval case count", min(2.0, cases / 10 * 2), 2.0,
              f"{cases} known-answer cases (full credit at 10)"),
        _item("harness integrity", 1.0 if ran else 0.0, 1.0,
              "offline harness produced parseable metrics" if ran else "eval harness did not run"),
    ]
    if live and ran:
        avg = (float(metrics.get("detect_rate", 0)) + float(metrics.get("evidence_rate", 0))
               + float(metrics.get("dismissal_rate", 0))) / 3
        items.append(_item("live-model accuracy", 4.0 * avg, 4.0,
                           f"detect {metrics.get('detect_rate')} / evidence "
                           f"{metrics.get('evidence_rate')} / dismissal "
                           f"{metrics.get('dismissal_rate')} over {metrics.get('cases', 0)} cases"))
    else:
        items.append(_item("live-model accuracy", 0.0, 4.0,
                           "live eval not run this week — accuracy above the offline harness "
                           "is unmeasured (rerun with --live to record it)"))
    return _section(items)


def score_improvement(imp: dict) -> dict:
    commits = int(imp.get("commits_count") or 0)
    insertions = int(imp.get("insertions") or 0)
    test_delta = imp.get("test_delta")
    eval_delta = imp.get("eval_case_delta")
    tests_pass = imp.get("tests_pass")
    items = [
        _item("commits since baseline", min(3.0, commits / 10 * 3), 3.0,
              f"{commits} commit(s) since {imp.get('base')}"),
        _item("code growth", min(2.0, insertions / 500 * 2), 2.0,
              f"{insertions} insertions across {imp.get('files_changed', 0)} file(s)"),
        _item("test growth", 2.0 if (test_delta or 0) >= 10 else 1.0 if (test_delta or 0) >= 1 else 0.0,
              2.0, "baseline week (deltas start with the next scorecard)" if test_delta is None
                   else f"{test_delta:+d} test functions"),
        _item("eval-case growth", 1.5 if (eval_delta or 0) >= 1 else 0.0, 1.5,
              "baseline week (deltas start with the next scorecard)" if eval_delta is None
              else f"{eval_delta:+d} eval cases"),
        _item("tests pass", 1.5 if tests_pass else 0.0, 1.5,
              "pytest passed" if tests_pass else "pytest failed or was not run"),
    ]
    return _section(items)


def grade(overall: float) -> str:
    if overall >= 9:
        return "A"
    if overall >= 8:
        return "B"
    if overall >= 7:
        return "C"
    if overall >= 6:
        return "D"
    return "E"


def build_card(root: Path, *, live: bool = False, note: str = "", run_tests: bool = True,
               eval_payload: dict | None = None, base_url: str | None = None,
               model: str | None = None, api_key: str | None = None) -> dict:
    metrics = collect_metrics(root)
    prev = latest_score(root, before_week=metrics["week"])
    if eval_payload is None:
        eval_payload = run_eval(root, live, base_url, model, api_key)
    improvement = collect_improvement(root, prev, metrics, run_tests=run_tests)
    sections = {
        "architecture": score_architecture(metrics),
        "accuracy": score_accuracy(metrics, eval_payload, live),
        "improvement": score_improvement(improvement),
    }
    overall = round(sum(WEIGHTS[k] * sections[k]["score"] for k in WEIGHTS), 1)
    return {
        "week": metrics["week"],
        "date": metrics["date"],
        "version": metrics["version"],
        "git_head": metrics["git_head"],
        "rubric_version": RUBRIC_VERSION,
        "scoring_start": SCORING_START,
        "weights": WEIGHTS,
        "metrics": metrics,
        "sections": sections,
        "overall": overall,
        "grade": grade(overall),
        "eval": {"mode": "live" if live else "stub",
                 "ran": bool((eval_payload or {}).get("metrics")),
                 "metrics": (eval_payload or {}).get("metrics"),
                 "cases": (eval_payload or {}).get("cases")},
        "improvement_basis": improvement,
        "note": note,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ------------------------------------------------------------- storage

def scorecards_dir(root: Path) -> Path:
    return root / "dmesg_agent" / "scorecards"


def latest_score(root: Path | None = None, before_week: str | None = None) -> dict | None:
    """Newest recorded card; with before_week, only earlier weeks count as a
    baseline (re-recording the current week must not compare against itself)."""
    directory = scorecards_dir(root) if root else Path(__file__).resolve().parent / "scorecards"
    if not directory.is_dir():
        return None
    cards = sorted(directory.glob("*.json"))
    if before_week:
        cards = [p for p in cards if p.stem < before_week]
    if not cards:
        return None
    try:
        return json.loads(cards[-1].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def format_for_check(card: dict) -> str:
    s = card.get("sections", {})
    return (f"software score: {card.get('overall')}/10 ({card.get('week')}, "
            f"v{card.get('version')}) — architecture {s.get('architecture', {}).get('score')} "
            f"· accuracy {s.get('accuracy', {}).get('score')} · improvement "
            f"{s.get('improvement', {}).get('score')}; basis: SCORECARD.md "
            f"(history starts {card.get('scoring_start', SCORING_START)})")


def record(root: Path, card: dict) -> Path:
    directory = scorecards_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{card['week']}.json"
    path.write_text(json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_markdown(root)
    return path


def _write_markdown(root: Path) -> None:
    directory = scorecards_dir(root)
    cards = []
    for path in sorted(directory.glob("*.json")):
        try:
            cards.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    lines = [
        "# dmesg-agent weekly scorecard",
        "",
        f"Scoring starts with {SCORING_START}. Each week a maintainer records one card with "
        "`dmesg-agent score --record [--live] --note \"...\"`; the machine-readable basis "
        "lives in `dmesg_agent/scorecards/<week>.json`. Users installing any release inherit "
        "this history — the score starts from the first recorded week, not from their install date.",
        "",
        "| Week | Version | Overall | Architecture | Accuracy | Improvement | Grade |",
        "|---|---|---|---|---|---|---|",
    ]
    for card in reversed(cards):
        s = card.get("sections", {})
        lines.append(f"| {card.get('week')} | {card.get('version')} | {card.get('overall')} "
                     f"| {s.get('architecture', {}).get('score')} "
                     f"| {s.get('accuracy', {}).get('score')} "
                     f"| {s.get('improvement', {}).get('score')} | {card.get('grade')} |")
    lines.append("")
    for card in reversed(cards):
        s = card.get("sections", {})
        lines.append(f"## {card.get('week')} — {card.get('overall')}/10 ({card.get('grade')})")
        lines.append("")
        lines.append(f"Recorded {card.get('date')} · version {card.get('version')} · head "
                     f"{card.get('git_head') or 'n/a'} · eval mode {card.get('eval', {}).get('mode')}")
        if card.get("note"):
            lines.append(f"Note: {card['note']}")
        lines.append("")
        for key in ("architecture", "accuracy", "improvement"):
            sec = s.get(key, {})
            lines.append(f"### {key.capitalize()} — {sec.get('score')}/10")
            lines.append("")
            for item in sec.get("items", []):
                lines.append(f"- {item['item']}: {item['points']}/{item['max']} — {item['evidence']}")
            lines.append("")
        imp = card.get("improvement_basis", {})
        commits = imp.get("commits") or []
        if commits:
            lines.append("Improvement evidence (commits since baseline):")
            lines.append("")
            for commit in commits[:12]:
                lines.append(f"- `{commit}`")
            lines.append("")
    (root / "SCORECARD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------- CLI

def _print_card(card: dict) -> None:
    s = card["sections"]
    print(f"dmesg-agent scorecard — {card['week']} (v{card['version']}, head "
          f"{card['git_head'] or 'n/a'})")
    print(f"  eval mode: {card['eval']['mode']}")
    for key in ("architecture", "accuracy", "improvement"):
        sec = s[key]
        print(f"\n{key.capitalize()}: {sec['score']}/10  (weight {WEIGHTS[key]:.0%})")
        for item in sec["items"]:
            print(f"  - {item['item']}: {item['points']}/{item['max']} — {item['evidence']}")
    print(f"\nOverall: {card['overall']}/10  (grade {card['grade']})")
    if card.get("note"):
        print(f"Note: {card['note']}")


def score_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dmesg-agent score",
        description="compute (and optionally record) the weekly software scorecard")
    parser.add_argument("--record", action="store_true",
                        help="write dmesg_agent/scorecards/<week>.json and SCORECARD.md")
    parser.add_argument("--live", action="store_true",
                        help="run the eval harness against the live model (slow; real accuracy)")
    parser.add_argument("--note", default="", help="maintainer note stored with this week's card")
    parser.add_argument("--no-tests", action="store_true", help="skip the pytest run")
    parser.add_argument("--base-url"); parser.add_argument("--model"); parser.add_argument("--api-key")
    parser.add_argument("--json", action="store_true", help="emit the card as JSON")
    parser.add_argument("--root", help=argparse.SUPPRESS)  # testing hook
    args = parser.parse_args(argv)

    root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    if not (root / "dmesg_agent").is_dir():
        print(f"error: no source checkout at {root} (score needs dmesg_agent/ and tests/)",
              file=sys.stderr)
        return 2
    card = build_card(root, live=args.live, note=args.note, run_tests=not args.no_tests,
                      base_url=args.base_url, model=args.model, api_key=args.api_key)
    if args.record:
        path = record(root, card)
        print(f"recorded {path.relative_to(root)} and SCORECARD.md "
              "(commit both so the history enters the repository)", file=sys.stderr)
    if args.json:
        print(json.dumps(card, ensure_ascii=False, indent=2))
    else:
        _print_card(card)
        prev = latest_score(root, before_week=card["week"])
        if prev:
            print(f"\nLast recorded: {prev['week']} {prev['overall']}/10 "
                  f"(this week's delta {card['overall'] - prev['overall']:+.1f})")
    return 0
