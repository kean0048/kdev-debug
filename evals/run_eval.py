#!/usr/bin/env python3
"""Eval harness: measure how well the pipeline pinpoints known issues.

Each case is a directory under evals/cases/<name>/ with:
  log.txt        — the input log
  expected.json  — {id, description, expect:{subsystem[], severity[], any_keywords[]},
                    must_not_dismiss[] }
Subsystem/severity/keyword lists are OR-groups: a hit on any listed value counts.

Scoring per case — sashiko-benchmark-style three-state classification
(src/benchmark.rs DETECTED / PARTIALLY_DETECTED / MISSED):
  DETECTED : a *confirmed finding* whose subsystem matches expect.subsystem,
             whose text matches any_keywords, severity is in expect.severity,
             and every quote verified verbatim.
  PARTIAL  : the issue was spotted but in the inconclusive tier, or severity
             is wrong, or some evidence failed verbatim verification.
  MISSED   : not located at all.
Plus noise: findings emitted per case vs expected_count (default 1) —
sashiko tracks findings/patch signal-to-noise; we track findings/case.

Headline metrics:
  detected_rate / partial_rate / missed_rate (sum to 1)
  detect_rate    = (detected + partial) / cases   (what --min-locate gates on)
  evidence_rate  = cases with no fabricated quote / cases
  dismissal_rate = cases honoring must_not_dismiss / cases
  noise_rate     = total findings emitted / total expected bugs

Modes:
  --live            call the configured LLM endpoint for each case (real eval)
  (default, offline) use a built-in stub that echoes the log's own signatures,
                    so the harness + scoring are unit-testable with no network.

Usage:
  python evals/run_eval.py                 # offline self-test (stub answers)
  python evals/run_eval.py --live [--base-url ... --model ... --api-key ...]
  python evals/run_eval.py --live --ab     # also run each case with the full log (no
                                           # triage prefilter) to measure triage's value
Exit code: non-zero if detect_rate drops below --min-locate (default 0.0, so the
offline run never fails CI on model quality — only on harness errors).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases"

# Make the package importable when run as a script from anywhere.
sys.path.insert(0, str(HERE.parent))

from dmesg_agent.analyze import run_analysis  # noqa: E402
from dmesg_agent.collectors.base import RawBundle  # noqa: E402
from dmesg_agent.config import load_config  # noqa: E402
from dmesg_agent.llm import Client  # noqa: E402
from dmesg_agent.triage import find_blocks, render_blocks  # noqa: E402
from dmesg_agent.verify import verify_result  # noqa: E402


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s).lower())


def _item_text(item: dict) -> str:
    return _norm(" ".join(str(item.get(k, "")) for k in
                          ("title", "root_cause_hypothesis", "hypothesis", "signal_reason")))


def score_case(result: dict, expect: dict) -> dict:
    """Returns {"status": DETECTED|PARTIAL|MISSED, severity_ok, evidence_ok,
    dismissal_ok, findings_emitted, detail}."""
    exp = expect.get("expect", {})
    want_subs = [_norm(s) for s in exp.get("subsystem", [])]
    want_sev = [_norm(s) for s in exp.get("severity", [])]
    want_kw = [_norm(k) for k in exp.get("any_keywords", [])]

    located = None
    located_tier = ""
    for tier in ("findings", "inconclusive_concerns"):
        for item in result.get(tier, []) or []:
            if not isinstance(item, dict):
                continue
            sub = _norm(item.get("subsystem", ""))
            sub_ok = any(w in sub or sub in w for w in want_subs) if want_subs else True
            kw_ok = any(k in _item_text(item) for k in want_kw) if want_kw else True
            if sub_ok and kw_ok:
                located = item
                located_tier = tier
                break
        if located:
            break

    sev_ok = bool(located) and (not want_sev
                                or _norm(located.get("severity", located.get("estimated_severity", ""))) in want_sev)

    # anti-hallucination: any evidence marked verified=False anywhere is a miss
    quotes_total = quotes_passed = 0
    for tier in ("findings", "inconclusive_concerns"):
        for item in result.get(tier, []) or []:
            for ev in (item.get("evidence") or []):
                if isinstance(ev, dict) and "verified" in ev:
                    quotes_total += 1
                    quotes_passed += 1 if ev.get("verified") else 0
    for d in result.get("dismissed_concerns") or []:
        if isinstance(d, dict) and "quote_verified" in d:
            quotes_total += 1
            quotes_passed += 1 if d.get("quote_verified") else 0
    no_halluc = quotes_total == 0 or quotes_passed == quotes_total

    if located is None:
        status = "MISSED"
    elif located_tier == "findings" and sev_ok and no_halluc:
        status = "DETECTED"
    else:
        status = "PARTIAL"

    # must-not-dismiss: none of these phrases should appear in a verified dismissal
    not_dismissed = True
    for phrase in expect.get("must_not_dismiss", []) or []:
        p = _norm(phrase)
        for d in result.get("dismissed_concerns") or []:
            if isinstance(d, dict) and p in _norm(d.get("counter_evidence_quote", "")):
                not_dismissed = False
    return {
        "status": status,
        "severity_ok": sev_ok,
        "evidence_ok": no_halluc,
        "dismissal_ok": not_dismissed,
        "findings_emitted": len([x for x in (result.get("findings") or []) if isinstance(x, dict)]),
        "expected_count": int(expect.get("expected_count", 1)),
        "detail": (located.get("title", "") if located else "NOT LOCATED"),
    }


# --- offline stub client: emits a schema-valid answer derived from log signatures ---

_SIG_TO = [
    (r"out of memory|oom-kill", "memory", "OOM killed a process", ["oom", "out of memory"]),
    (r"nvme.*timeout|I/O .*timeout|blk_update_request|medium error", "storage", "storage I/O timeout/error", ["io", "nvme", "error"]),
    (r"ring .*timeout|gpu reset|amdgpu", "gpu", "GPU ring timeout / reset", ["gpu", "ring"]),
    (r"soft lockup|hung_task|blocked for more than", "locking", "CPU lockup / hung task", ["lockup"]),
    (r"failed to start|main process exited|entered failed state", "service", "failed systemd unit", ["systemd", "failed"]),
    (r"No space left|ENOSPC", "disk-space", "filesystem full", ["space"]),
]


class StubClient:
    last_finish_reason = None

    def __init__(self, log_lines):
        self._lines = log_lines

    def chat(self, messages, retries: int = 0, stream_cb=None):
        blob = _norm("\n".join(self._lines))
        findings = []
        for rx, sub, title, kws in _SIG_TO:
            if re.search(rx, blob):  # rx patterns are lowercase; blob is normalized
                quote = next((l for l in self._lines if re.search(rx, l, re.IGNORECASE)), "")
                findings.append({
                    "title": title, "subsystem": sub, "severity": "high",
                    "severity_explanation": "stub", "root_cause_hypothesis": title,
                    "evidence": [{"line": self._lines.index(quote) + 1 if quote else 1,
                                  "quote": quote, "why": "stub"}],
                    "causal_chain": "stub", "next_steps": ["stub"],
                })
        return json.dumps({"summary": "stub", "findings": findings,
                           "inconclusive_concerns": [], "dismissed_concerns": []})


def run_case(case_dir: Path, client, triage: bool = True) -> dict:
    log_text = (case_dir / "log.txt").read_text()
    expect = json.loads((case_dir / "expected.json").read_text())
    lines = log_text.splitlines()
    if triage:
        blocks_text = render_blocks(lines, find_blocks(lines))
    else:
        blocks_text = log_text  # A/B: hand the whole log over, no prefilter
    bundle = RawBundle(dmesg_text=log_text, kernel_version="eval", distro="eval", source="eval")
    result, _ = run_analysis(client, bundle, blocks_text, "", lines, retries=0)
    if not isinstance(result, dict):
        return {"status": "MISSED", "severity_ok": False, "evidence_ok": False,
                "dismissal_ok": False, "findings_emitted": 0, "expected_count": 1,
                "detail": "no valid JSON from model"}
    verify_result(result, lines)
    return score_case(result, expect)


def aggregate(rows: dict[str, dict]) -> dict:
    n = len(rows) or 1
    det = sum(1 for r in rows.values() if r["status"] == "DETECTED")
    par = sum(1 for r in rows.values() if r["status"] == "PARTIAL")
    mis = sum(1 for r in rows.values() if r["status"] == "MISSED")
    expected_total = sum(r.get("expected_count", 1) for r in rows.values()) or 1
    emitted = sum(r.get("findings_emitted", 0) for r in rows.values())
    return {
        "cases": len(rows),
        "detected": det, "partial": par, "missed": mis,
        "detected_rate": round(det / n, 3),
        "partial_rate": round(par / n, 3),
        "missed_rate": round(mis / n, 3),
        "detect_rate": round((det + par) / n, 3),
        "evidence_rate": round(sum(r["evidence_ok"] for r in rows.values()) / n, 3),
        "dismissal_rate": round(sum(r["dismissal_ok"] for r in rows.values()) / n, 3),
        "noise_rate": round(emitted / expected_total, 2),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="run_eval")
    ap.add_argument("--live", action="store_true", help="call the real LLM endpoint")
    ap.add_argument("--base-url"); ap.add_argument("--model"); ap.add_argument("--api-key")
    ap.add_argument("--json", action="store_true", help="emit metrics as JSON")
    ap.add_argument("--min-locate", type=float, default=0.0,
                    help="fail (exit 1) if detect_rate is below this (live runs)")
    ap.add_argument("--ab", action="store_true",
                    help="also run every case with triage disabled and compare metrics")
    args = ap.parse_args(argv)

    cases = sorted([p for p in CASES.iterdir() if (p / "expected.json").exists()])
    if not cases:
        print(f"no cases under {CASES}", file=sys.stderr)
        return 1

    client = None
    if args.live:
        cfg = load_config(base_url=args.base_url, model=args.model, api_key=args.api_key)
        client = Client(cfg)

    def make_client(case):
        if args.live:
            return client
        return StubClient((case / "log.txt").read_text().splitlines())

    rows: dict[str, dict] = {}
    for case in cases:
        rows[case.name] = run_case(case, make_client(case))

    metrics = aggregate(rows)
    ab_metrics = None
    if args.ab:
        ab_rows = {case.name: run_case(case, make_client(case), triage=False) for case in cases}
        ab_metrics = aggregate(ab_rows)
    if args.json:
        payload = {"metrics": metrics, "cases": rows}
        if ab_metrics is not None:
            payload["metrics_no_triage"] = ab_metrics
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("case            status    severity  evidence  dismissal")
        for name, r in rows.items():
            print(f"{name:<15} {r['status']:<9} {str(r['severity_ok']):<9} "
                  f"{str(r['evidence_ok']):<9} {str(r['dismissal_ok']):<10}  {r['detail']}")
        print("\nmetrics:", json.dumps(metrics))
        if ab_metrics is not None:
            print("metrics (no triage):", json.dumps(ab_metrics))

    if args.live and metrics["detect_rate"] < args.min_locate:
        print(f"FAIL: detect_rate {metrics['detect_rate']} < {args.min_locate}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
