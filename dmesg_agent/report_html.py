"""Self-contained single-file HTML report (no external assets, no scripts).

Every dynamic value is HTML-escaped. The layout is verdict-first: health
banner → findings cards → open signals → case library → timeline → appendices.
Print-friendly so it can be exported to PDF and shared.
"""

from __future__ import annotations

from html import escape

from .collectors.base import RawBundle
from .report import SEV_RANK, build_verdict, _footer
from .triage import Block
from .verify import VerifySummary

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans",
       Helvetica, Arial, sans-serif; margin: 0 auto; max-width: 980px; padding: 32px 20px 64px;
       color: #1d2939; line-height: 1.55; background: #fff; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 34px 0 12px; }
h3 { font-size: 16px; margin: 0 0 8px; }
.meta { color: #667085; font-size: 13px; }
.chips { margin-top: 10px; }
.chips span { display: inline-block; background: #f2f4f7; border-radius: 999px;
              padding: 2px 10px; margin: 0 6px 6px 0; font-size: 12px; color: #344054; }
.banner { border-radius: 12px; padding: 18px 20px; margin: 20px 0; border: 1px solid; }
.banner .health { margin: 0 0 4px; font-size: 21px; font-weight: 700; letter-spacing: .2px; }
.banner.critical { background: #fef3f2; border-color: #fda29b; color: #7a271a; }
.banner.warning { background: #fffaeb; border-color: #fec84b; color: #7a2e0e; }
.banner.attention { background: #fffaeb; border-color: #fedf89; color: #7a2e0e; }
.banner.ok { background: #ecfdf3; border-color: #75e0a7; color: #054f31; }
.banner.unknown, .banner.no-data { background: #f4f3ff; border-color: #d9d6fe; color: #3e1c96; }
.banner ol { margin: 8px 0 0; padding-left: 22px; }
.banner li { margin: 3px 0; }
.actions-title { font-weight: 700; margin-top: 12px; }
.card { border: 1px solid #eaecf0; border-radius: 12px; padding: 18px 20px; margin: 16px 0;
        box-shadow: 0 1px 2px rgba(16,24,40,.05); }
.badge { display: inline-block; border-radius: 8px; padding: 2px 8px; font-size: 12px;
         font-weight: 600; text-transform: uppercase; }
.badge.critical { background: #fee4e2; color: #b42318; }
.badge.high { background: #fef0c7; color: #b54708; }
.badge.medium { background: #fef7c3; color: #b25e09; }
.badge.low { background: #f2f4f7; color: #475467; }
.badge.unknown { background: #f2f4f7; color: #475467; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 13.5px; }
th, td { border: 1px solid #eaecf0; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f9fafb; font-weight: 600; }
code { background: #f2f4f7; border-radius: 4px; padding: 1px 4px; font-size: 12.5px;
       font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { background: #101828; color: #f2f4f7; padding: 12px; border-radius: 8px;
      overflow-x: auto; font-size: 12.5px; line-height: 1.4; }
.details, details { margin: 12px 0; }
summary { cursor: pointer; font-weight: 600; color: #344054; }
.timeline { list-style: none; padding-left: 0; border-left: 3px solid #d0d5dd; margin-left: 8px; }
.timeline li { margin: 0 0 12px 20px; position: relative; }
.timeline li::before { content: ""; position: absolute; left: -27px; top: 6px; width: 10px;
                       height: 10px; border-radius: 50%; background: #667085; }
.timeline .names { font-size: 12px; color: #667085; margin-left: 8px; }
.timeline code { display: block; margin-top: 4px; }
.verified { color: #067647; font-weight: 600; }
.unverified { color: #b42318; font-weight: 600; }
.footer { margin-top: 44px; color: #667085; font-size: 12.5px;
          border-top: 1px solid #eaecf0; padding-top: 12px; }
@media print { body { max-width: none; padding: 0; } .card, .banner { break-inside: avoid; } }
"""


def _e(value) -> str:
    return escape(str(value), quote=True)


def _trim(text, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _sev(value) -> str:
    value = str(value).lower()
    return value if value in ("critical", "high", "medium", "low") else "unknown"


def _evidence_table(evidences) -> str:
    rows = []
    for ev in evidences:
        if not isinstance(ev, dict):
            continue
        mark = ('<span class="verified">verified</span>' if ev.get("verified")
                else '<span class="unverified">unverified</span>')
        line = str(ev.get("line", ev.get("source", "?")))
        rows.append(f"<tr><td>{mark}</td><td>{_e(line)}</td>"
                    f"<td><code>{_e(ev.get('quote', ''))}</code></td>"
                    f"<td>{_e(ev.get('why', ''))}</td></tr>")
    if not rows:
        return ""
    return ("<table><thead><tr><th>Verification</th><th>Line</th><th>Log excerpt</th>"
            "<th>Why it is evidence</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _banner(verdict: dict) -> str:
    css = verdict["health"].lower().replace(" ", "-")
    top = "".join(
        f"<li><span class=\"badge {_sev(item['severity'])}\">{_e(item['severity'])}</span> "
        f"{_e(item['title'])} <span class=\"meta\">({_e(item['subsystem'])})</span></li>"
        for item in verdict["top"])
    actions = ""
    if verdict["actions"]:
        actions = '<div class="actions-title">DO NOW</div><ol>' + "".join(
            f"<li>{_e(a)}</li>" for a in verdict["actions"]) + "</ol>"
    chips = "".join(f"<span>{_e(c)}</span>" for c in verdict["chips"])
    return (f'<div class="banner {css}"><div class="health">HEALTH: {_e(verdict["health"])} — '
            f'{_e(verdict["headline"])}</div>'
            + (f"<ol>{top}</ol>" if top else "") + actions
            + (f'<div class="chips">{chips}</div>' if chips else "") + "</div>")


def _finding_card(index: int, f: dict, kb: dict) -> str:
    sev = _sev(f.get("severity"))
    tags = []
    rec = f.get("recurrence")
    if rec:
        tags.append(f"🔁 seen {rec.get('count', 1)}× (first {rec.get('first_seen', '?')})")
    case = f.get("case")
    if isinstance(case, dict):
        tags.append(f"case #{case.get('id', '?')} · {case.get('tier', '?')} · "
                    f"{case.get('status', '?')}")
        if case.get("regression"):
            tags.append("⚠ regression after fix")
    parts = [f'<article class="card"><h3><span class="badge {sev}">{_e(sev)}</span> '
             f"{index}. {_e(f.get('title', 'Untitled issue'))}</h3>",
             f'<div class="meta">Subsystem: {_e(f.get("subsystem", "?"))}'
             + (f" · {' · '.join(_e(t) for t in tags)}" if tags else "") + "</div>"]
    if f.get("evidence_verified") is False:
        parts.append('<p class="unverified">None of the evidence could be verified against the '
                     "original log — treat this conclusion with suspicion.</p>")
    if f.get("severity_explanation"):
        parts.append(f"<p><strong>Severity rationale:</strong> {_e(f['severity_explanation'])}</p>")
    parts.append(f"<p><strong>Root cause:</strong> {_e(f.get('root_cause_hypothesis', '(none)'))}</p>")
    parts.append(_evidence_table(f.get("evidence", [])))
    if f.get("causal_chain"):
        parts.append(f"<p><strong>Causal chain:</strong> {_e(f['causal_chain'])}</p>")
    steps = f.get("next_steps") or []
    if steps:
        parts.append("<p><strong>How to fix / next actions:</strong></p><ol>"
                     + "".join(f"<li>{_e(s)}</li>" for s in steps) + "</ol>")
    parts.append("</article>")
    return "".join(parts)


def _timeline(blocks: list[Block], lines: list[str]) -> str:
    if not blocks:
        return ""
    items = []
    for block in blocks[:12]:
        first = lines[block.start - 1] if 0 < block.start <= len(lines) else ""
        items.append(f'<li><code>L{block.start}–{block.end}</code>'
                     f'<span class="names">{_e(", ".join(block.names))}</span>'
                     f"<code>{_e(_trim(first, 240))}</code></li>")
    more = (f'<li><span class="meta">… {len(blocks) - 12} more segment(s)</span></li>'
            if len(blocks) > 12 else "")
    return f"<h2>Timeline of suspicious segments</h2><ol class='timeline'>{''.join(items)}{more}</ol>"


def _deep_details(result: dict) -> str:
    sections = []
    for c in (result.get("inconclusive_concerns") or []) + (result.get("findings") or []) \
            + (result.get("dismissed_concerns") or []):
        if not isinstance(c, dict) or not c.get("deep_dive", {}).get("collected"):
            continue
        body = []
        for ev in c["deep_dive"]["collected"]:
            status = {"ok": "✅", "skipped": "⏭", "empty": "∅"}.get(ev.get("status", "ok"), "•")
            output = ev.get("output") or ""
            body.append(f"<h4>{status} <code>$ {_e(ev['cmd'])}</code></h4>"
                        f"<div class='meta'>Purpose: {_e(ev.get('why', ''))}</div>"
                        f"<pre>{_e(_trim(output, 4000))}</pre>")
        sections.append(f"<details><summary>{_e(c.get('title', '?'))} — "
                        f"{len(c['deep_dive']['collected'])} collection(s)</summary>"
                        + "".join(body) + "</details>")
    if not sections:
        return ""
    return "<h2>Appendix: deep-collection data</h2>" + "".join(sections)


def render_html(result: dict | None, bundle: RawBundle, summary: VerifySummary,
                blocks: list[Block], lines: list[str], raw_text: str = "",
                prefetch_used: bool = False, deep_used: bool = False,
                scan_used: bool = False, scan_text: str = "",
                changes_text: str = "", source_text: str = "",
                srcmap_version: str = "") -> str:
    verdict = build_verdict(result, summary)
    title = "dmesg AI diagnosis report"
    out = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
           f"<title>{_e(title)}</title><style>{CSS}</style></head><body>",
           f"<h1>{_e(title)}</h1>",
           f'<div class="meta">{_e(bundle.source)} · kernel {_e(bundle.kernel_version)} · '
           f"distro {_e(bundle.distro)}</div>",
           _banner(verdict)]

    rate = summary.rate if summary.total else "no evidence quoted"
    pipeline = ["prefilter"]
    if scan_used:
        pipeline.append("system scan")
    if changes_text:
        pipeline.append("system-change correlation")
    if prefetch_used:
        pipeline.append("prefetch")
    pipeline.append("3-tier analysis")
    if deep_used:
        pipeline.append("deep verification")
    pipeline.append("evidence check")
    out.append(f'<div class="meta">Pipeline: {_e(" → ".join(pipeline))} · '
               f"evidence verified {_e(rate)}</div>")

    if result is None:
        out.append('<h2>Raw model output</h2><pre>' + _e(raw_text.strip() or "(empty)") + "</pre>")
        out.append(f'<div class="footer">{_e(_footer())}</div></body></html>')
        return "".join(out)

    out.append(f"<h2>Overall conclusion</h2><p>{_e(result.get('summary', '(none)'))}</p>")

    kb = result.get("knowledge") or {}
    diff = kb.get("diff") if isinstance(kb, dict) else None
    if isinstance(diff, dict):
        new = ", ".join(t.get("title", "") for t in diff.get("new") or []) or "none"
        resolved = ", ".join(t.get("title", "") for t in diff.get("resolved") or []) or "none"
        out.append(f"<p><strong>Since the previous run:</strong> "
                   f"{len(diff.get('new') or [])} new ({_e(new)}), "
                   f"{len(diff.get('resolved') or [])} resolved ({_e(resolved)}), "
                   f"{len(diff.get('ongoing') or [])} ongoing.</p>")

    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    out.append("<h2>Confirmed issues</h2>")
    if findings:
        findings.sort(key=lambda f: SEV_RANK.get(str(f.get("severity", "")).lower(), 9))
        out.extend(_finding_card(i, f, kb) for i, f in enumerate(findings, 1))
    else:
        out.append("<p>No confirmed issues.</p>")

    inconclusives = [c for c in (result.get("inconclusive_concerns") or [])
                     if isinstance(c, dict)]
    if inconclusives:
        out.append("<h2>Open suspicious signals</h2>")
        for i, c in enumerate(inconclusives, 1):
            est = _sev(c.get("estimated_severity"))
            out.append(f'<article class="card"><h3><span class="badge {est}">{_e(est)}?</span> '
                       f"{i}. {_e(c.get('title', ''))}</h3>"
                       f"<p><strong>Signal:</strong> {_e(c.get('signal_reason', '(none)'))}<br>"
                       f"<strong>Hypothesis:</strong> {_e(c.get('hypothesis', '(none)'))}<br>"
                       f"<strong>Needed for a verdict:</strong> "
                       f"{_e(c.get('verification_question', '(not stated)'))}</p>"
                       + _evidence_table(c.get("evidence", [])))
            ddv = c.get("deep_dive") or {}
            if ddv:
                out.append(f"<p><strong>Deep verification:</strong> "
                           f"{_e(ddv.get('verdict', 'failed'))} — {_e(ddv.get('reason', ''))}</p>")
            out.append("</article>")

    dismissed = [d for d in (result.get("dismissed_concerns") or []) if isinstance(d, dict)]
    non_issues = result.get("non_issues") or []
    if dismissed or non_issues:
        out.append("<h2>Judged benign / dismissed signals</h2><ul>")
        for d in dismissed:
            mark = "✅" if d.get("quote_verified") else "⚠"
            out.append(f"<li>{mark} {_e(d.get('title', ''))}: {_e(d.get('why_not_a_problem', ''))}"
                       f"<br><code>{_e(_trim(d.get('counter_evidence_quote', ''), 200))}</code></li>")
        for n in non_issues:
            out.append(f"<li>{_e(n)}</li>")
        out.append("</ul>")

    matches = kb.get("matches") if isinstance(kb, dict) else None
    if matches:
        out.append("<h2>Case library (shadow mode)</h2><table><thead><tr><th>Finding</th>"
                   "<th>Case</th><th>Match</th><th>Status</th><th>Seen</th><th>First seen</th>"
                   "</tr></thead><tbody>")
        for m in matches:
            idx = m.get("finding_index")
            label = f"#{idx + 1}" if isinstance(idx, int) else "?"
            out.append(f"<tr><td>{_e(label)} {_e(m.get('title', ''))}</td>"
                       f"<td>#{_e(m.get('case_id', '?'))}</td><td>{_e(m.get('tier', '?'))}</td>"
                       f"<td>{_e(m.get('status', '?'))}</td><td>{_e(m.get('occurrences', '?'))}</td>"
                       f"<td>{_e(m.get('first_seen', '?'))}</td></tr>")
        out.append("</tbody></table>")

    out.append(_timeline(blocks, lines))

    facts = [f for f in (result.get("facts") or []) if isinstance(f, dict)]
    if facts:
        rows = "".join(
            f"<tr><td>{_e(str(f.get('kind', '?')))}</td>"
            f"<td><code>{_e(str(f.get('key', '?')))}</code></td>"
            f"<td>{_e(str(f.get('value', '')))}{(' · line ' + str(f['line'])) if f.get('line') else ''}</td></tr>"
            for f in facts)
        out.append("<details open><summary>Appendix: deterministic facts "
                   "(rule-extracted)</summary><table><thead><tr><th>Kind</th><th>Key</th>"
                   f"<th>Value</th></tr></thead><tbody>{rows}</tbody></table></details>")

    if changes_text:
        out.append("<details><summary>Appendix: system changes around the fault</summary>"
                   f"<pre>{_e(_trim(changes_text, 8000))}</pre></details>")
    if scan_text:
        out.append("<details><summary>Appendix: proactive system scan / forensics data</summary>"
                   f"<pre>{_e(_trim(scan_text, 8000))}</pre></details>")
    if source_text:
        warn = ""
        if srcmap_version and srcmap_version not in bundle.kernel_version:
            warn = ("<p class='unverified'>Source tree version does not match the running "
                    "kernel; function bodies may be offset.</p>")
        out.append("<details><summary>Appendix: call-trace source correlation</summary>"
                   + warn + f"<pre>{_e(_trim(source_text, 8000))}</pre></details>")
    out.append(_deep_details(result))

    out.append(f'<div class="footer">{_e(_footer())}</div></body></html>')
    return "".join(out)
