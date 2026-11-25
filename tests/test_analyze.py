import json

from dmesg_agent.analyze import deep_dive, run_analysis, validate_analysis, validate_verdict
from dmesg_agent.collectors.base import RawBundle
from dmesg_agent.executors import ExecResult

LOG = [
    "[ 2345.679000] Out of memory: Killed process 12345 (chrome)",
    "[ 4567.890123] nvme nvme0: I/O 12 (QID 1) Q 0x0 timeout, reset controller",
]
OOM_QUOTE = "Out of memory: Killed process 12345 (chrome)"
NVME_QUOTE = "nvme nvme0: I/O 12 (QID 1) Q 0x0 timeout, reset controller"


def good_result():
    return {
        "summary": "ok",
        "findings": [{"title": "OOM", "subsystem": "内存", "severity": "high",
                      "evidence": [{"line": 1, "quote": OOM_QUOTE, "why": "w"}]}],
        "inconclusive_concerns": [{"title": "NVMe 故障?", "subsystem": "存储", "estimated_severity": "high",
                                   "signal_reason": "timeout", "hypothesis": "ssd 坏",
                                   "evidence": [{"line": 2, "quote": NVME_QUOTE, "why": "w"}],
                                   "verification_question": "需要 smartctl 看介质错误"}],
        "dismissed_concerns": [{"title": "i8042", "counter_evidence_quote": OOM_QUOTE, "why": "无关噪音"}],
    }


class FakeClient:
    last_finish_reason = None

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def chat(self, messages):
        self.calls.append(messages)
        return self.answers.pop(0) if self.answers else json.dumps({"error": "no more answers"})


class FakeExecutor:
    name, can_collect = "fake", True

    def __init__(self, outs):
        self.outs = outs
        self.runs = []

    def run(self, cmd, sudo=False, timeout=30):
        self.runs.append((cmd, sudo))
        out = self.outs.get(cmd)
        if out is None:
            return ExecResult(ok=True, out="")
        return ExecResult(ok=True, out=out)

    def close(self):
        pass


def test_validate_passes_good():
    assert validate_analysis(good_result(), LOG) == []


def test_validate_fabricated_quote():
    r = good_result()
    r["findings"][0]["evidence"][0]["quote"] = "kernel panic: made up"
    errors = validate_analysis(r, LOG)
    assert any("kernel panic" in e for e in errors)


def test_validate_needs_verification_question():
    r = good_result()
    del r["inconclusive_concerns"][0]["verification_question"]
    assert any("verification_question" in e for e in validate_analysis(r, LOG))


def test_validate_dismissed_needs_counter_evidence():
    r = good_result()
    r["dismissed_concerns"][0]["counter_evidence_quote"] = "no such line"
    assert any("反证" in e for e in validate_analysis(r, LOG))


def test_run_analysis_retries_with_feedback():
    bad = json.dumps({"summary": "x", "findings": [{"title": "t", "evidence": [{"quote": "nope"}]}],
                      "inconclusive_concerns": [], "dismissed_concerns": []})
    client = FakeClient([bad, json.dumps(good_result())])
    result, _ = run_analysis(client, RawBundle(dmesg_text=""), "", "", LOG, retries=1)
    assert client.calls[-1][-1]["role"] == "user"
    assert "nope" in client.calls[-1][-1]["content"]
    assert result["summary"] == "ok"


def test_deep_dive_confirms_concern():
    collected_out = "Reallocated_Sector_Ct   142\nCurrent_Pending_Sector 8"
    verdict = {
        "verdict": "confirmed", "reason": "SMART 显示坏道",
        "updated_root_cause": "SSD 介质劣化", "updated_severity": "critical",
        "evidence": [{"source": "smartctl", "quote": "Reallocated_Sector_Ct   142", "why": "坏道增长"}],
        "next_steps": ["备份换盘"],
    }
    r = good_result()
    # deep 会按 concern 文本匹配 storage playbook,伪造其命令输出
    from dmesg_agent.playbooks import DEEP_BY_SUBSYSTEM
    outs = {c.cmd: (collected_out if "smartctl" in c.cmd else "") for c in DEEP_BY_SUBSYSTEM["storage"]}
    ex = FakeExecutor(outs)
    client = FakeClient([json.dumps(verdict)])
    result, corpus = deep_dive(client, ex, r, LOG, RawBundle(dmesg_text="", source="fake"), max_concerns=5)
    assert result["findings"][-1]["deep_confirmed"] is True
    assert result["findings"][-1]["severity"] == "critical"
    assert result["inconclusive_concerns"] == []
    assert result["deep_dive_summary"]["confirmed"] == 1
    assert any("Reallocated" in l for l in corpus)


def test_deep_dive_dismiss():
    verdict = {"verdict": "dismissed", "reason": "计数全零,盘健康",
               "evidence": [{"source": "c", "quote": "Reallocated 0", "why": "无坏道"}],
               "next_steps": []}
    from dmesg_agent.playbooks import DEEP_BY_SUBSYSTEM
    outs = {c.cmd: ("Reallocated 0\n" if "smartctl" in c.cmd else "") for c in DEEP_BY_SUBSYSTEM["storage"]}
    r = good_result()
    client = FakeClient([json.dumps(verdict)])
    result, _ = deep_dive(client, FakeExecutor(outs), r, LOG, RawBundle(dmesg_text="", source="fake"))
    assert result["dismissed_concerns"][-1]["deep_dismissed"] is True
    assert not any(c.get("title") == "NVMe 故障?" for c in result["inconclusive_concerns"])


def test_deep_dive_bad_verdict_retries_then_fails_gracefully():
    r = good_result()
    client = FakeClient(["garbage", "still garbage"])
    result, _ = deep_dive(client, FakeExecutor({}), r, LOG, RawBundle(dmesg_text="", source="fake"))
    assert result["deep_dive_summary"]["skipped"] == 1
    assert len(result["inconclusive_concerns"]) == 1  # 保留,不丢


def test_validate_verdict_quote_from_collection():
    v = {"verdict": "confirmed", "evidence": [{"quote": "some collected line"}]}
    assert any("quote" in e for e in validate_verdict(v, ["nothing"]))
    assert validate_verdict(v, ["[x] some collected line"]) == []
