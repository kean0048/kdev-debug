import json

from dmesg_agent.extractor import (compact_message, extract_issue,
                                   validate_extraction)

LOG_LINE = "[ 456.789] nvme nvme0: I/O 12 QID 1 timeout, reset controller"


class FakeClient:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []
        self.last_model = "fake-model"

    def chat(self, messages, retries=2, stream_cb=None):
        self.calls.append(messages)
        return self.answers.pop(0) if self.answers else "{}"


def test_validate_keeps_only_verbatim_snippets():
    obj = {
        "symptom": "nvme timeout",
        "log_snippets": [LOG_LINE, "invented line: controller exploded"],
        "root_cause": "controller reset race",
        "fix": {"commit": "abc1234"},
        "confidence": 0.8,
    }
    data, errors = validate_extraction(
        obj, "subject\nFixes: abc1234\n" + LOG_LINE)
    assert errors == []
    assert data["log_snippets"] == [LOG_LINE]
    assert data["_dropped_snippets"] == 1
    assert data["fix"] == {"commit": "abc1234"}


def test_validate_rejects_empty_extraction():
    data, errors = validate_extraction({"symptom": "", "root_cause": "",
                                        "fix": {}, "log_snippets": []}, "text")
    assert data is None and errors


def test_validate_fix_string_and_confidence_clamp():
    data, errors = validate_extraction(
        {"symptom": "s", "root_cause": "r", "fix": "backport abc123",
         "confidence": 3.0}, "text")
    assert errors == []
    assert data["fix"] == {"workaround": "backport abc123"}
    assert data["confidence"] == 1.0


def test_extract_issue_valid_and_retry():
    valid = json.dumps({
        "symptom": "nvme timeout", "log_snippets": [LOG_LINE],
        "root_cause": "reset race", "fix": {"upgrade_to": "6.12.121"},
        "confidence": 0.9,
    })
    client = FakeClient(["not json", valid])
    data = extract_issue(client, "nvme timeout", LOG_LINE)
    assert data["root_cause"] == "reset race"
    assert data["fix"]["upgrade_to"] == "6.12.121"
    assert len(client.calls) == 2
    assert "output is not a valid JSON object" in client.calls[1][-1]["content"]


def test_extract_issue_gives_up_after_retry():
    client = FakeClient(["nope", "still nope"])
    assert extract_issue(client, "x", "") is None
    assert len(client.calls) == 2


def test_compact_message_drops_diff_and_keeps_trailers():
    body = ("explain the race\n\n"
            "diff --git a/drivers/nvme/x.c b/drivers/nvme/x.c\n"
            "+some patch line\n\nFixes: abc123def456\n")
    text = compact_message("nvme: fix reset race", body)
    assert "some patch line" not in text
    assert "Fixes: abc123def456" in text


def test_validate_keeps_fix_pointers_verbatim():
    source = ("subject\nSee https://lore.kernel.org/all/msg1/ and bug 1234567\n"
              "Fixes: abc1234\n" + LOG_LINE)
    data, errors = validate_extraction(
        {"symptom": "s", "root_cause": "r", "confidence": 0.5,
         "fix": {"commit": "abc1234",
                 "url": "https://lore.kernel.org/all/msg1/",
                 "bug": "1234567"},
         "log_snippets": []}, source)
    assert errors == []
    assert data["fix"]["url"] == "https://lore.kernel.org/all/msg1/"
    assert data["fix"]["bug"] == "1234567"


def test_validate_drops_hallucinated_fix_pointers():
    data, errors = validate_extraction(
        {"symptom": "s", "root_cause": "r",
         "fix": {"url": "https://evil.example/x", "bug": "9999999"},
         "log_snippets": []}, "nothing like that here")
    assert errors == []
    assert data["fix"] == {}
    assert data["_dropped_fix_commit"] == 2


def test_snippets_are_bounded_to_four_times_200():
    line = "[1.0] " + "x" * 600
    data, errors = validate_extraction(
        {"symptom": "s", "log_snippets": [line] * 6, "root_cause": "",
         "fix": {}, "confidence": 0.1}, line)
    assert errors == []
    assert len(data["log_snippets"]) == 4
    assert all(len(snippet) == 200 for snippet in data["log_snippets"])


def test_validate_drops_hallucinated_commit():
    data, errors = validate_extraction(
        {"symptom": "s", "root_cause": "r",
         "fix": {"commit": "deadbeef1234"}, "log_snippets": []},
        "no commit hash in this text")
    assert errors == []
    assert "commit" not in data["fix"]
    assert data["_dropped_fix_commit"] == 1
