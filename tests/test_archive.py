import json

import pytest

import dmesg_agent.archive as archive
from dmesg_agent.archive import (RecordingClient, build_archive, load_run_archive,
                                 write_run_archive)
from dmesg_agent.collectors.base import RawBundle
from dmesg_agent.triage import Block


class _Inner:
    last_finish_reason = "stop"
    last_model = "test-model"

    def chat(self, messages, retries=2, stream_cb=None):
        return '{"summary": "ok"}'


class _Bad:
    last_finish_reason = None
    last_model = None

    def chat(self, messages, retries=2, stream_cb=None):
        raise RuntimeError("boom")


def test_recording_client_records_exchange():
    rc = RecordingClient(_Inner())
    assert rc.chat([{"role": "user", "content": "hi"}]) == '{"summary": "ok"}'
    assert rc.last_model == "test-model"
    assert rc.exchanges[0]["answer"] == '{"summary": "ok"}'
    assert rc.exchanges[0]["messages"][0]["content"] == "hi"
    assert rc.exchanges[0]["finish_reason"] == "stop"


def test_recording_client_records_error_and_reraises():
    rc = RecordingClient(_Bad())
    with pytest.raises(RuntimeError, match="boom"):
        rc.chat([])
    assert "RuntimeError: boom" in rc.exchanges[0]["error"]


def _payload(run_uuid="u1", text="[ 1.0] EXT4-fs error (device sda1)"):
    bundle = RawBundle(dmesg_text=text, kernel_version="7.0.0", distro="Ubuntu",
                       source="file:test.log")
    return build_archive(
        run_uuid=run_uuid, host="pgx", bundle=bundle,
        blocks=[Block(start=1, end=1, names=["fs-error"])], blocks_text="1: x",
        exchanges=[{"messages": [], "answer": "{}"}], result={"summary": "s"},
        verify={"total": 1, "passed": 1, "line_mismatch": 0}, argv=["--file", "test.log"],
        base_url="http://llm", model="m")


def test_write_and_load_archive(tmp_path):
    path = write_run_archive(_payload(), root=tmp_path)
    data = load_run_archive(path)
    assert data["run_uuid"] == "u1"
    assert data["host"] == "pgx"
    assert data["result"]["summary"] == "s"
    assert data["verify"]["passed"] == 1
    assert data["blocks"][0]["names"] == ["fs-error"]
    assert (path.stat().st_mode & 0o777) == 0o600


def test_archive_prunes_oldest(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_RUNS", 2)
    for i in range(3):
        write_run_archive(_payload(run_uuid=f"u{i}"), root=tmp_path)
    files = list(tmp_path.glob("*.json.gz"))
    assert len(files) == 2
    uuids = {json.loads(__import__("gzip").open(f, "rt").read())["run_uuid"] for f in files}
    assert "u0" not in uuids  # oldest pruned
    assert {"u1", "u2"} == uuids


def test_archive_truncates_huge_log(monkeypatch):
    monkeypatch.setattr(archive, "MAX_LOG_CHARS", 100)
    payload = _payload(text="x" * 500)
    assert payload["dmesg_truncated"] is True
    assert "archive truncated middle" in payload["dmesg"]
