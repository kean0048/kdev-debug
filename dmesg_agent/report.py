"""Markdown report renderer v2: three-tier routing + deep-collection evidence."""

from __future__ import annotations

from .collectors.base import RawBundle
from .triage import Block
from .verify import VerifySummary

SEVERITY = {"critical": "🔴 critical", "high": "🟠 high", "medium": "🟡 medium", "low": "⚪ low"}


def _esc(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence_table(evidences) -> list[str]:
    lines = ["", "| Verified | Line | Log excerpt | Why it is evidence |", "|---|---|---|---|"]
    for ev in evidences:
        if not isinstance(ev, dict):
            continue
        mark = "✅" if ev.get("verified") else "⚠"
        line = str(ev.get("line", ev.get("source", "?")))
        if ev.get("actual_line") and str(ev.get("actual_line")) != line:
            line += f" (actually {ev['actual_line']})"
        lines.append(f"| {mark} | {line} | {_esc(ev.get('quote', ''))} | {_esc(ev.get('why', ''))} |")
    return lines


def render(result: dict | None, bundle: RawBundle, summary: VerifySummary,
           blocks: list[Block], raw_text: str = "", prefetch_used: bool = False,
           deep_used: bool = False, source_text: str = "", srcmap_version: str = "",
           scan_used: bool = False, scan_text: str = "") -> str:
    out: list[str] = ["# dmesg AI diagnosis report", ""]
    out.append(f"- Source: `{bundle.source}`  Kernel: {bundle.kernel_version}  Distro: {bundle.distro}")
    out.append(f"- Pipeline: prefilter {len(blocks)} segments"
               f"{' → proactive system scan' if scan_used else ''}"
               f"{' → prefetched context' if prefetch_used else ''}"
               f" → LLM three-tier analysis{' → deep verification' if deep_used else ''} → evidence check")
    rate = summary.rate if summary.total else "no evidence quoted"
    out.append(f"- **Evidence verification: {rate} quotes passed verbatim matching**" +
               (f" ({summary.line_mismatch} with an off-by-N line number; content confirmed)"
                if summary.line_mismatch else ""))
    out.append("")

    if result is not None and result.get("_repaired_truncation"):
        out.append("> ⚠ The model output was truncated and the JSON was auto-repaired; "
                   "the last conclusion may be incomplete.")
        out.append("")

    if result is None:
        out.append("> ⚠ The model did not return conforming JSON. Raw output below — read it manually:\n")
        out.append("```text")
        out.append(raw_text.strip() or "(empty)")
        out.append("```")
        return "\n".join(out)

    out.append("## Overall conclusion\n")
    out.append(str(result.get("summary", "(none)")))
    out.append("")

    dd = result.get("deep_dive_summary")
    if dd:
        out.append(f"- Deep verification: {dd.get('attempted', 0)} attempted → "
                   f"confirmed {dd.get('confirmed', 0)}, dismissed {dd.get('dismissed', 0)},"
                   f" still inconclusive {dd.get('inconclusive', 0)}"
                   + (f", failed {dd.get('skipped', 0)}" if dd.get("skipped") else ""))
        out.append("")

    kb = result.get("knowledge")
    if isinstance(kb, dict) and kb.get("matches"):
        out.append("## Case library (shadow mode)\n")
        out.append(f"> {len(kb['matches'])} finding(s) fingerprinted into the per-host case "
                   f"library (host `{kb.get('host', '?')}`, {kb.get('new_cases', 0)} new "
                   f"case(s), {kb.get('recurrences', 0)} recurrence(s)). Shadow mode records "
                   "matches without changing the analysis; confirm a case with "
                   "`dmesg-agent cases confirm <id>` to prepare the future fast path.")
        out.append("")
        out.append("| Finding | Case | Match | Status | Seen | First seen |")
        out.append("|---|---|---|---|---|---|")
        for m in kb["matches"]:
            idx = m.get("finding_index")
            label = f"#{idx + 1}" if isinstance(idx, int) else "?"
            tier = str(m.get("tier", "?"))
            if tier == "fuzzy" and m.get("similar_case_id"):
                tier = f"similar to #{m['similar_case_id']} ({m.get('score', '?')})"
            out.append(f"| {label} {_esc(m.get('title', ''))} | #{m.get('case_id', '?')} "
                       f"| {tier} | {m.get('status', '?')} | {m.get('occurrences', '?')} "
                       f"| {m.get('first_seen', '?')} |")
        out.append("")

    findings = result.get("findings", [])
    if findings:
        out.append("## Confirmed issues\n")
        for i, f in enumerate(findings, 1):
            if not isinstance(f, dict):
                continue
            sev = SEVERITY.get(str(f.get("severity", "")).lower(), str(f.get("severity", "?")))
            tag = " 🔍 confirmed by deep verification" if f.get("deep_confirmed") else ""
            out.append(f"### {i}. {sev} | {f.get('title', 'Untitled issue')}{tag}")
            out.append(f"- Subsystem: {f.get('subsystem', '?')}")
            if f.get("evidence_verified") is False:
                out.append("- ⚠ **None of the evidence could be verified against the original log — treat this conclusion with suspicion**")
            rec = f.get("recurrence")
            if rec:
                out.append(f"- 🔁 Recurrence: seen {rec.get('count', 1)} times on this host "
                           f"(first seen {rec.get('first_seen', '?')})")
            case = f.get("case")
            if isinstance(case, dict):
                extras = []
                if case.get("similar_case_id"):
                    extras.append(f"similar to case #{case['similar_case_id']}")
                if case.get("regression"):
                    extras.append("⚠ regression after being marked fixed")
                suffix = f" — {', '.join(extras)}" if extras else ""
                out.append(f"- 🗂 Case #{case.get('id', '?')} ({case.get('tier', '?')} match, "
                           f"status {case.get('status', '?')}, "
                           f"{case.get('occurrences', '?')} occurrence(s){suffix})")
            if f.get("severity_explanation"):
                out.append(f"- Severity rationale: {f['severity_explanation']}")
            out.append(f"- Root-cause hypothesis: {f.get('root_cause_hypothesis', '(none)')}")
            out.extend(_evidence_table(f.get("evidence", [])))
            if f.get("causal_chain"):
                out.append(f"\n- Causal chain: {f['causal_chain']}")
            steps = f.get("next_steps") or []
            if steps:
                out.append("- How to fix / next actions:")
                for s in steps:
                    out.append(f"  - {s}")
            out.append("")
    else:
        out.append("## No confirmed issues\n")

    inconclusives = [c for c in (result.get("inconclusive_concerns") or []) if isinstance(c, dict)]
    if inconclusives:
        out.append("## Open suspicious signals\n")
        for i, c in enumerate(inconclusives, 1):
            est = SEVERITY.get(str(c.get("estimated_severity", "")).lower(), str(c.get("estimated_severity", "?")))
            out.append(f"### {i}. {est}? | {c.get('title', '')}")
            out.append(f"- Subsystem: {c.get('subsystem', '?')}")
            out.append(f"- Signal: {c.get('signal_reason', '(none)')}")
            out.append(f"- Hypothesis: {c.get('hypothesis', '(none)')}")
            out.append(f"- Needed for a verdict: {c.get('verification_question', '(the model did not say)')}")
            out.extend(_evidence_table(c.get("evidence", [])))
            ddv = c.get("deep_dive") or {}
            if ddv:
                v = ddv.get("verdict", "failed")
                icon = {"confirmed": "🔍→confirmed", "dismissed": "🔍→dismissed",
                        "inconclusive": "🔍→still inconclusive"}.get(v, "🔍→failed")
                out.append(f"- Deep verification: {icon} — {ddv.get('reason', '')}")
            out.append("")

    dismissed = [d for d in (result.get("dismissed_concerns") or []) if isinstance(d, dict)]
    non_issues = result.get("non_issues") or []
    if dismissed or non_issues:
        out.append("## Judged benign / dismissed signals\n")
        for d in dismissed:
            mark = "✅" if d.get("quote_verified") else "⚠"
            tag = "(dismissed by deep verification)" if d.get("deep_dismissed") else ""
            out.append(f"- {mark} {d.get('title', '')}{tag}: {d.get('why_not_a_problem', '')}"
                       f"\n  - Counter-evidence: `{_esc(d.get('counter_evidence_quote', ''))[:120]}`")
        for n in non_issues:
            out.append(f"- {n}")
        out.append("")

    if scan_text:
        out.append("## Appendix: proactive system scan / forensics data\n")
        out.append(scan_text)
        out.append("")

    if source_text:
        out.append("## Appendix: call-trace source correlation\n")
        if srcmap_version and srcmap_version not in bundle.kernel_version:
            out.append(f"> ⚠ Source tree version {srcmap_version} does not match the running kernel "
                       f"{bundle.kernel_version}; function bodies may be offset.\n")
        out.append(source_text)
        out.append("")

    _deep_appendix(out, result)

    return "\n".join(out)


def _deep_appendix(out: list[str], result: dict) -> None:
    sections = []
    for c in (result.get("inconclusive_concerns") or []) + (result.get("findings") or []) \
            + (result.get("dismissed_concerns") or []):
        if isinstance(c, dict) and c.get("deep_dive", {}).get("collected"):
            sections.append((c.get("title", ""), c["deep_dive"]["collected"]))
    if not sections:
        return
    out.append("## Appendix: deep-collection data\n")
    for title, collected in sections:
        out.append(f"### {title}")
        for ev in collected:
            status = {"ok": "✅", "skipped": "⏭", "empty": "∅"}[ev.get("status", "ok")]
            out.append(f"\n{status} `$ {ev['cmd']}`")
            out.append(f"- Purpose: {ev.get('why', '')}")
            if ev.get("output"):
                body = ev["output"]
                if not ev["output"].startswith("("):
                    body = "\n".join(ev["output"].splitlines()[:15])
                out.append("```text")
                out.append(body)
                out.append("```")
        out.append("")
