"""Analysis orchestration v2: first-pass three-tier routing → deep collection for
inconclusive concerns → verdict re-verification."""

from __future__ import annotations

import json

from .collectors.base import RawBundle
from .llm import parse_json_response
from .playbooks import run_deep
from .prompts import build_messages, build_verdict_messages, feedback_message
from .verify import _match, normalize


def _quote_exists(quote: str, norm_lines: list[str]) -> bool:
    q = normalize(str(quote))
    return bool(q) and any(_match(q, ln) for ln in norm_lines)


def _check_evidences(items: list, field: str, label: str, norm_lines: list[str], errors: list[str]) -> None:
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{label}[{i}] must be an object")
            continue
        if not item.get("title"):
            errors.append(f"{label}[{i}] is missing title")
        evs = item.get("evidence") or []
        if not evs:
            errors.append(f"{label}[{i}] is missing evidence: every conclusion or suspicion must carry verbatim log evidence")
        for j, ev in enumerate(evs):
            q = ev.get("quote", "") if isinstance(ev, dict) else ""
            if not _quote_exists(q, norm_lines):
                errors.append(
                    f"{label}[{i}].evidence[{j}] quote was not found verbatim in the original log; "
                    f"copy it verbatim from the provided data or remove it: {str(q)[:80]!r}"
                )
        if field and not str(item.get(field, "")).strip():
            errors.append(f"{label}[{i}] is missing {field} (a required field of the three-tier routing)")


def validate_analysis(result: dict, corpus_lines: list[str]) -> list[str]:
    """corpus = original log lines + collected scan/prefetch output lines."""
    errors: list[str] = []
    norm = [normalize(l) for l in corpus_lines]
    if not str(result.get("summary", "")).strip():
        errors.append("missing summary")
    if not isinstance(result.get("findings"), list):
        errors.append("findings must be an array (may be empty)")
    else:
        _check_evidences(result["findings"], "", "findings", norm, errors)
    if not isinstance(result.get("inconclusive_concerns"), list):
        errors.append("inconclusive_concerns must be an array (may be empty)")
    else:
        _check_evidences(result["inconclusive_concerns"], "verification_question",
                         "inconclusive_concerns", norm, errors)
    for i, d in enumerate(result.get("dismissed_concerns") or []):
        if not isinstance(d, dict) or not _quote_exists(d.get("counter_evidence_quote", ""), norm):
            errors.append(
                f"dismissed_concerns[{i}] must give counter_evidence_quote (a verbatim counter-quote "
                f"from the log); never dismiss without evidence — move it to inconclusive instead"
            )
    return errors


def run_analysis(client, bundle: RawBundle, blocks_text: str, prefetch_text: str,
                 log_lines: list[str], source_text: str = "", retries: int = 1,
                 scan_text: str = "", make_stream=None) -> tuple[dict | None, str]:
    """First-pass analysis; on validation failure, feed the exact error list back
    for one retry (sashiko feedback-retry). log_lines doubles as the evidence
    corpus: pass log lines plus any collected scan/prefetch output lines so
    evidence quoted from collections is valid."""
    msgs = build_messages(bundle, blocks_text, prefetch_text, source_text, scan_text)
    result, answer = None, ""
    for attempt in range(retries + 1):
        cb = make_stream(f"analysis attempt {attempt + 1}") if make_stream else None
        answer = client.chat(msgs, stream_cb=cb)
        result = parse_json_response(answer)
        errors = validate_analysis(result, log_lines) if result is not None else ["output is not a valid JSON object"]
        if not errors:
            return result, answer
        if attempt < retries:
            msgs += feedback_message(errors, answer)
    return result, answer


def _concern_text(c: dict) -> str:
    return " ".join(str(c.get(k, "")) for k in
                    ("title", "subsystem", "signal_reason", "hypothesis", "verification_question"))


def deep_dive(client, executor, result: dict, log_lines: list[str],
              bundle: RawBundle, max_concerns: int = 5,
              extra_corpus: list[str] | None = None, make_stream=None) -> tuple[dict, list[str]]:
    """Returns (result, corpus). Per inconclusive concern: playbook collection
    (with sudo prompts) → verdict → merged back into result.

    corpus = original log + all collected output, used for final evidence verification.
    All collection commands come from the whitelist playbooks; the model's
    verification_question is only used to pick subsystems — commands proposed by
    the model are never executed directly (log-injection defense).
    """
    concerns = [c for c in (result.get("inconclusive_concerns") or []) if isinstance(c, dict)]
    corpus = list(log_lines) + (extra_corpus or [])
    outcome = {"confirmed": 0, "dismissed": 0, "inconclusive": 0, "skipped": 0}

    for c in concerns[:max_concerns]:
        evidences = run_deep(executor, _concern_text(c))
        for ev in evidences:
            corpus.extend(ev.output.splitlines())
        msgs = build_verdict_messages(c, evidences, bundle)
        verdict, answer = None, ""
        for attempt in range(2):
            cb = make_stream(f"verdict: {c.get('title', '')[:40]}") if make_stream else None
            answer = client.chat(msgs, stream_cb=cb)
            verdict = parse_json_response(answer)
            errors = validate_verdict(verdict, corpus)
            if not errors:
                break
            if attempt == 0:
                msgs += feedback_message(errors, answer)
        if verdict is None or verdict.get("verdict") not in ("confirmed", "dismissed", "inconclusive"):
            outcome["skipped"] += 1
            c["deep_dive"] = {"status": "failed", "collected": [e.as_dict() for e in evidences]}
            continue

        verdict["collected"] = [e.as_dict() for e in evidences]
        c["deep_dive"] = verdict
        v = verdict["verdict"]
        outcome[v] += 1
        if v == "confirmed":
            finding = {
                "title": c.get("title", ""),
                "subsystem": c.get("subsystem", ""),
                "severity": verdict.get("updated_severity", c.get("estimated_severity", "medium")),
                "severity_explanation": verdict.get("reason", ""),
                "root_cause_hypothesis": verdict.get("updated_root_cause", c.get("hypothesis", "")),
                "evidence": verdict.get("evidence", c.get("evidence", [])),
                "causal_chain": c.get("signal_reason", ""),
                "next_steps": verdict.get("next_steps", []),
                "deep_confirmed": True,
                "deep_dive": verdict,
            }
            result.setdefault("findings", []).append(finding)
        elif v == "dismissed":
            evs = verdict.get("evidence") or []
            quote = str(evs[0].get("quote", "")) if evs and isinstance(evs[0], dict) else str(verdict.get("reason", ""))
            result.setdefault("dismissed_concerns", []).append({
                "title": c.get("title", ""),
                "counter_evidence_quote": quote,
                "why_not_a_problem": verdict.get("reason", ""),
                "deep_dismissed": True,
                "deep_dive": verdict,
            })
        if v != "inconclusive":
            result["inconclusive_concerns"] = [x for x in result.get("inconclusive_concerns", [])
                                               if x is not c]

    result["deep_dive_summary"] = {"attempted": min(len(concerns), max_concerns), **outcome}
    return result, corpus
    return result


def validate_verdict(verdict: dict | None, corpus_lines: list[str]) -> list[str]:
    if verdict is None:
        return ["output is not a valid JSON object"]
    errors: list[str] = []
    if verdict.get("verdict") not in ("confirmed", "dismissed", "inconclusive"):
        errors.append('the verdict field must be one of "confirmed"/"dismissed"/"inconclusive"')
    norm = [normalize(l) for l in corpus_lines]
    evs = verdict.get("evidence") or []
    if verdict.get("verdict") in ("confirmed", "dismissed") and not evs:
        errors.append("confirmed/dismissed must provide evidence (verbatim quotes from the original log or collected output)")
    for j, ev in enumerate(evs):
        q = ev.get("quote", "") if isinstance(ev, dict) else ""
        if not _quote_exists(q, norm):
            errors.append(
                f"evidence[{j}] quote was not found verbatim in the original log or collected output: {str(q)[:80]!r}"
            )
    return errors
