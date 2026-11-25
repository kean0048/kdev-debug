"""Markdown 报告渲染 v2:三段式 + 深度采集证据。"""

from __future__ import annotations

from .collectors.base import RawBundle
from .triage import Block
from .verify import VerifySummary

SEVERITY = {"critical": "🔴 critical", "high": "🟠 high", "medium": "🟡 medium", "low": "⚪ low"}


def _esc(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence_table(evidences) -> list[str]:
    lines = ["", "| 验证 | 行号 | 日志原文 | 为什么是证据 |", "|---|---|---|---|"]
    for ev in evidences:
        if not isinstance(ev, dict):
            continue
        mark = "✅" if ev.get("verified") else "⚠"
        line = str(ev.get("line", ev.get("source", "?")))
        if ev.get("actual_line") and str(ev.get("actual_line")) != line:
            line += f"(实际 {ev['actual_line']})"
        lines.append(f"| {mark} | {line} | {_esc(ev.get('quote', ''))} | {_esc(ev.get('why', ''))} |")
    return lines


def render(result: dict | None, bundle: RawBundle, summary: VerifySummary,
           blocks: list[Block], raw_text: str = "", prefetch_used: bool = False,
           deep_used: bool = False, source_text: str = "", srcmap_version: str = "") -> str:
    out: list[str] = ["# dmesg AI 诊断报告", ""]
    out.append(f"- 来源:`{bundle.source}`  内核:{bundle.kernel_version}  发行版:{bundle.distro}")
    out.append(f"- 流水线:预过滤 {len(blocks)} 个片段"
               f"{' → 预采集上下文' if prefetch_used else ''}"
               f" → LLM 三段分析{' → 深度核验' if deep_used else ''} → 证据校验")
    rate = summary.rate if summary.total else "无证据引用"
    out.append(f"- **证据验证:{rate} 条通过逐字比对**" +
               (f"(其中 {summary.line_mismatch} 条行号有偏差,内容已核实)" if summary.line_mismatch else ""))
    out.append("")

    if result is not None and result.get("_repaired_truncation"):
        out.append("> ⚠ 模型输出被截断,JSON 已自动修复,最后一条结论可能不完整。")
        out.append("")

    if result is None:
        out.append("> ⚠ 模型未返回符合约定的 JSON,以下为原始输出,请人工判读:\n")
        out.append("```text")
        out.append(raw_text.strip() or "(空)")
        out.append("```")
        return "\n".join(out)

    out.append("## 总体结论\n")
    out.append(str(result.get("summary", "(无)")))
    out.append("")

    dd = result.get("deep_dive_summary")
    if dd:
        out.append(f"- 深度核验:尝试 {dd.get('attempted', 0)} 项 → "
                   f"确认 {dd.get('confirmed', 0)},排除 {dd.get('dismissed', 0)},"
                   f"仍存疑 {dd.get('inconclusive', 0)}"
                   + (f",失败 {dd.get('skipped', 0)}" if dd.get("skipped") else ""))
        out.append("")

    findings = result.get("findings", [])
    if findings:
        out.append("## 确认的问题\n")
        for i, f in enumerate(findings, 1):
            if not isinstance(f, dict):
                continue
            sev = SEVERITY.get(str(f.get("severity", "")).lower(), str(f.get("severity", "?")))
            tag = " 🔍 深度核验确认" if f.get("deep_confirmed") else ""
            out.append(f"### {i}. {sev} | {f.get('title', '未命名问题')}{tag}")
            out.append(f"- 子系统:{f.get('subsystem', '?')}")
            if f.get("evidence_verified") is False:
                out.append("- ⚠ **所有证据均未在原始日志中核实——结论存疑**")
            if f.get("severity_explanation"):
                out.append(f"- 严重度依据:{f['severity_explanation']}")
            out.append(f"- 根因假设:{f.get('root_cause_hypothesis', '(无)')}")
            out.extend(_evidence_table(f.get("evidence", [])))
            if f.get("causal_chain"):
                out.append(f"\n- 因果链:{f['causal_chain']}")
            steps = f.get("next_steps") or []
            if steps:
                out.append("- 下一步:")
                for s in steps:
                    out.append(f"  - {s}")
            out.append("")
    else:
        out.append("## 未发现确认的问题\n")

    inconclusives = [c for c in (result.get("inconclusive_concerns") or []) if isinstance(c, dict)]
    if inconclusives:
        out.append("## 待验证的可疑信号\n")
        for i, c in enumerate(inconclusives, 1):
            est = SEVERITY.get(str(c.get("estimated_severity", "")).lower(), str(c.get("estimated_severity", "?")))
            out.append(f"### {i}. {est}? | {c.get('title', '')}")
            out.append(f"- 子系统:{c.get('subsystem', '?')}")
            out.append(f"- 信号:{c.get('signal_reason', '(无)')}")
            out.append(f"- 假设:{c.get('hypothesis', '(无)')}")
            out.append(f"- 定论需要:{c.get('verification_question', '(模型未给出)')}")
            out.extend(_evidence_table(c.get("evidence", [])))
            ddv = c.get("deep_dive") or {}
            if ddv:
                v = ddv.get("verdict", "failed")
                icon = {"confirmed": "🔍→确认", "dismissed": "🔍→排除", "inconclusive": "🔍→仍存疑"}.get(v, "🔍→失败")
                out.append(f"- 深度核验:{icon} — {ddv.get('reason', '')}")
            out.append("")

    dismissed = [d for d in (result.get("dismissed_concerns") or []) if isinstance(d, dict)]
    non_issues = result.get("non_issues") or []
    if dismissed or non_issues:
        out.append("## 判定为噪音/已排除的信号\n")
        for d in dismissed:
            mark = "✅" if d.get("quote_verified") else "⚠"
            tag = "(深度核验排除)" if d.get("deep_dismissed") else ""
            out.append(f"- {mark} {d.get('title', '')}{tag}:{d.get('why_not_a_problem', '')}"
                       f"\n  - 反证:`{_esc(d.get('counter_evidence_quote', ''))[:120]}`")
        for n in non_issues:
            out.append(f"- {n}")
        out.append("")

    if source_text:
        out.append("## 附录:call trace 源码关联\n")
        if srcmap_version and srcmap_version not in bundle.kernel_version:
            out.append(f"> ⚠ 源码树版本 {srcmap_version} 与运行内核 {bundle.kernel_version} 不一致,函数体可能有偏移。\n")
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
    out.append("## 附录:深度采集数据\n")
    for title, collected in sections:
        out.append(f"### {title}")
        for ev in collected:
            status = {"ok": "✅", "skipped": "⏭", "empty": "∅"}[ev.get("status", "ok")]
            out.append(f"\n{status} `$ {ev['cmd']}`")
            out.append(f"- 目的:{ev.get('why', '')}")
            if ev.get("output"):
                body = ev["output"]
                if not ev["output"].startswith("("):
                    body = "\n".join(ev["output"].splitlines()[:15])
                out.append("```text")
                out.append(body)
                out.append("```")
        out.append("")
