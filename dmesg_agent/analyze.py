"""分析编排 v2:首轮三段路由 → inconclusive 深度采集 → verdict 再核验。"""

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
            errors.append(f"{label}[{i}] 必须是对象")
            continue
        if not item.get("title"):
            errors.append(f"{label}[{i}] 缺 title")
        evs = item.get("evidence") or []
        if not evs:
            errors.append(f"{label}[{i}] 缺 evidence:任何结论/怀疑都必须带逐字引用的日志证据")
        for j, ev in enumerate(evs):
            q = ev.get("quote", "") if isinstance(ev, dict) else ""
            if not _quote_exists(q, norm_lines):
                errors.append(
                    f"{label}[{i}].evidence[{j}] 的 quote 无法在原始日志中逐字找到,请原文复制或删除:"
                    f" {str(q)[:80]!r}"
                )
        if field and not str(item.get(field, "")).strip():
            errors.append(f"{label}[{i}] 缺 {field}(三段路由的关键字段)")


def validate_analysis(result: dict, log_lines: list[str]) -> list[str]:
    errors: list[str] = []
    norm = [normalize(l) for l in log_lines]
    if not str(result.get("summary", "")).strip():
        errors.append("缺 summary")
    if not isinstance(result.get("findings"), list):
        errors.append("findings 必须是数组(可为空)")
    else:
        _check_evidences(result["findings"], "", "findings", norm, errors)
    if not isinstance(result.get("inconclusive_concerns"), list):
        errors.append("inconclusive_concerns 必须是数组(可为空)")
    else:
        _check_evidences(result["inconclusive_concerns"], "verification_question",
                         "inconclusive_concerns", norm, errors)
    for i, d in enumerate(result.get("dismissed_concerns") or []):
        if not isinstance(d, dict) or not _quote_exists(d.get("counter_evidence_quote", ""), norm):
            errors.append(
                f"dismissed_concerns[{i}] 必须给 counter_evidence_quote(日志中逐字反证);无证据不许排除,应移入 inconclusive"
            )
    return errors


def run_analysis(client, bundle: RawBundle, blocks_text: str, prefetch_text: str,
                 log_lines: list[str], source_text: str = "", retries: int = 1) -> tuple[dict | None, str]:
    """首轮分析,校验失败带精确错误回灌重试(sashiko feedback-retry)。"""
    msgs = build_messages(bundle, blocks_text, prefetch_text, source_text)
    result, answer = None, ""
    for attempt in range(retries + 1):
        answer = client.chat(msgs)
        result = parse_json_response(answer)
        errors = validate_analysis(result, log_lines) if result is not None else ["输出不是合法的 JSON 对象"]
        if not errors:
            return result, answer
        if attempt < retries:
            msgs += feedback_message(errors, answer)
    return result, answer


def _concern_text(c: dict) -> str:
    return " ".join(str(c.get(k, "")) for k in
                    ("title", "subsystem", "signal_reason", "hypothesis", "verification_question"))


def deep_dive(client, executor, result: dict, log_lines: list[str],
              bundle: RawBundle, max_concerns: int = 5) -> tuple[dict, list[str]]:
    """返回 (result, corpus)。对 inconclusive 逐条:playbook 采集(含 sudo 弹窗)→ verdict → 合并回 result。

    corpus = 原始日志 + 全部采集输出,供最终证据校验。
    采集命令全部来自白名单 playbook;模型的 verification_question 只用于选择子系统,
    不能直接执行模型提出的命令(日志注入防护)。
    """
    concerns = [c for c in (result.get("inconclusive_concerns") or []) if isinstance(c, dict)]
    corpus = list(log_lines)
    outcome = {"confirmed": 0, "dismissed": 0, "inconclusive": 0, "skipped": 0}

    for c in concerns[:max_concerns]:
        evidences = run_deep(executor, _concern_text(c))
        for ev in evidences:
            corpus.extend(ev.output.splitlines())
        msgs = build_verdict_messages(c, evidences, bundle)
        verdict, answer = None, ""
        for attempt in range(2):
            answer = client.chat(msgs)
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
        return ["输出不是合法的 JSON 对象"]
    errors: list[str] = []
    if verdict.get("verdict") not in ("confirmed", "dismissed", "inconclusive"):
        errors.append('verdict 字段必须是 "confirmed"/"dismissed"/"inconclusive" 之一')
    norm = [normalize(l) for l in corpus_lines]
    evs = verdict.get("evidence") or []
    if verdict.get("verdict") in ("confirmed", "dismissed") and not evs:
        errors.append("confirmed/dismissed 必须给出 evidence(逐字引用原始日志或采集输出)")
    for j, ev in enumerate(evs):
        q = ev.get("quote", "") if isinstance(ev, dict) else ""
        if not _quote_exists(q, norm):
            errors.append(
                f"evidence[{j}] 的 quote 无法在原始日志或采集输出中逐字找到: {str(q)[:80]!r}"
            )
    return errors
