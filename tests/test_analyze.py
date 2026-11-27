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
        "findings": [{"title": "OOM", "subsystem": "memory", "severity": "high",
                      "evidence": [{"line": 1, "quote": OOM_QUOTE, "why": "w"}],
                      "next_steps": ["raise the container memory limit or add swap"]}],
        "inconclusive_concerns": [{"title": "NVMe failure?", "subsystem": "storage", "estimated_severity": "high",
                                   "signal_reason": "timeout", "hypothesis": "failing ssd",
                                   "evidence": [{"line": 2, "quote": NVME_QUOTE, "why": "w"}],
                                   "verification_question": "need smartctl to check media errors"}],
        "dismissed_concerns": [{"title": "i8042", "counter_evidence_quote": OOM_QUOTE, "why": "irrelevant noise"}],
    }


class FakeClient:
    last_finish_reason = None

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def chat(self, messages, stream_cb=None):
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
    assert any("counter_evidence_quote" in e for e in validate_analysis(r, LOG))


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
        "verdict": "confirmed", "reason": "SMART shows reallocated sectors",
        "updated_root_cause": "SSD media degradation", "updated_severity": "critical",
        "evidence": [{"source": "smartctl", "quote": "Reallocated_Sector_Ct   142", "why": "growing reallocated count"}],
        "next_steps": ["back up and replace the disk"],
    }
    r = good_result()
    # deep matches the storage playbook from the concern text; fake its command outputs
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
    verdict = {"verdict": "dismissed", "reason": "all counters zero, disk healthy",
               "evidence": [{"source": "c", "quote": "Reallocated 0", "why": "no bad sectors"}],
               "next_steps": []}
    from dmesg_agent.playbooks import DEEP_BY_SUBSYSTEM
    outs = {c.cmd: ("Reallocated 0\n" if "smartctl" in c.cmd else "") for c in DEEP_BY_SUBSYSTEM["storage"]}
    r = good_result()
    client = FakeClient([json.dumps(verdict)])
    result, _ = deep_dive(client, FakeExecutor(outs), r, LOG, RawBundle(dmesg_text="", source="fake"))
    assert result["dismissed_concerns"][-1]["deep_dismissed"] is True
    assert not any(c.get("title") == "NVMe failure?" for c in result["inconclusive_concerns"])


def test_deep_dive_second_round_routes_by_stated_gap():
    inconclusive = {
        "verdict": "inconclusive",
        "reason": "SMART is clean; check memory pressure and OOM history",
        "evidence": [], "next_steps": [],
    }
    confirmed = {
        "verdict": "confirmed", "reason": "the OOM killer did run",
        "updated_root_cause": "memory exhaustion",
        "updated_severity": "high",
        "evidence": [{"source": "log", "quote": OOM_QUOTE, "why": "victim"}],
        "next_steps": ["reduce memory usage or add swap"],
    }
    from dmesg_agent.playbooks import DEEP_BY_SUBSYSTEM
    outs = {}
    for sub in ("storage", "memory"):
        for c in DEEP_BY_SUBSYSTEM[sub]:
            outs[c.cmd] = "Reallocated 0" if "smartctl" in c.cmd else ""
    ex = FakeExecutor(outs)
    client = FakeClient([json.dumps(inconclusive), json.dumps(confirmed)])
    result, _ = deep_dive(client, ex, good_result(), LOG,
                          RawBundle(dmesg_text="", source="fake"), max_rounds=2)
    assert result["findings"][-1]["deep_confirmed"] is True
    assert result["deep_dive_summary"]["rounds"] == 2
    dd = result["findings"][-1]["deep_dive"]
    assert len(dd["rounds"]) == 2
    assert any("oom-kill" in cmd for cmd in dd["rounds"][1]["commands"])


def test_deep_dive_bad_verdict_retries_then_fails_gracefully():
    r = good_result()
    client = FakeClient(["garbage", "still garbage"])
    result, _ = deep_dive(client, FakeExecutor({}), r, LOG, RawBundle(dmesg_text="", source="fake"))
    assert result["deep_dive_summary"]["skipped"] == 1
    assert len(result["inconclusive_concerns"]) == 1  # kept, not dropped


def test_validate_verdict_quote_from_collection():
    v = {"verdict": "confirmed", "updated_severity": "high",
         "next_steps": ["replace the disk"],
         "evidence": [{"quote": "some collected line"}]}
    assert any("quote" in e for e in validate_verdict(v, ["nothing"]))
    assert validate_verdict(v, ["[x] some collected line"]) == []


def test_validate_finding_requires_severity_and_fix():
    r = good_result()
    del r["findings"][0]["severity"]
    assert any("severity" in e for e in validate_analysis(r, LOG))
    r = good_result()
    r["findings"][0]["severity"] = "urgent"  # not a legal level
    assert any("severity" in e for e in validate_analysis(r, LOG))
    r = good_result()
    r["findings"][0]["next_steps"] = []
    assert any("next_steps" in e for e in validate_analysis(r, LOG))


def test_validate_confirmed_verdict_requires_actionable_steps():
    v = {"verdict": "confirmed", "updated_severity": "high", "next_steps": [],
         "evidence": [{"quote": "x"}]}
    assert any("next_steps" in e for e in validate_verdict(v, ["x"]))
    v = {"verdict": "confirmed", "next_steps": ["do it"], "evidence": [{"quote": "x"}]}
    assert any("updated_severity" in e for e in validate_verdict(v, ["x"]))


def test_run_analysis_passes_scan_text_into_prompt():
    good = json.dumps({"summary": "ok", "findings": [], "inconclusive_concerns": [],
                       "dismissed_concerns": []})
    client = FakeClient([good])
    result, _ = run_analysis(client, RawBundle(dmesg_text=""), "", "", LOG,
                             scan_text="### $ systemctl --failed\nUNIT1.service loaded failed")
    assert result["summary"] == "ok"
    user_msg = client.calls[0][1]["content"]
    assert "Proactive system scan" in user_msg and "systemctl --failed" in user_msg


def test_run_analysis_injects_case_history():
    good = json.dumps({"summary": "ok", "findings": [], "inconclusive_concerns": [],
                       "dismissed_concerns": []})
    client = FakeClient([good])
    run_analysis(client, RawBundle(dmesg_text=""), "", "", LOG,
                 history_text="- #7 [confirmed] storage: sda I/O failure (seen x3)")
    user_msg = client.calls[0][1]["content"]
    assert "Case history on this host" in user_msg
    assert "#7" in user_msg and "sda I/O failure" in user_msg


def test_run_analysis_injects_deterministic_facts():
    good = json.dumps({"summary": "ok", "findings": [], "inconclusive_concerns": [],
                       "dismissed_concerns": []})
    client = FakeClient([good])
    run_analysis(client, RawBundle(dmesg_text=""), "", "", LOG,
                 facts_text="- [oom] chrome: killed 2 time(s)")
    user_msg = client.calls[0][1]["content"]
    assert "Deterministic facts" in user_msg
    assert "do not contradict" in user_msg
    assert "chrome" in user_msg


def test_render_history_bounds_output():
    from dmesg_agent.prompts import render_history
    h = {"last_run": {"ts": "t", "summary": "s" * 1000, "findings": 2,
                      "verified_pass": 3, "verified_total": 4},
         "cases": [{"id": 1, "title": "x" * 500, "subsystem": "storage",
                    "status": "confirmed", "occurrences": 2, "last_seen": "t"}]}
    text = render_history(h, max_chars=150)
    assert "history truncated" in text
    assert len(text) < 220
