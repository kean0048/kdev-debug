"""Per-run archive: persist the complete evidence trail for later replay.

A diagnosis is only as trustworthy as the inputs that produced it. This module
records every LLM request/response exchange plus the triage/collection context
and the final result, under ``$XDG_DATA_HOME/dmesg-agent/runs``. Archives are
gzip-compressed JSON (0600) and pruned to the newest ``MAX_RUNS`` entries.

The run_uuid is shared with the knowledge library's ``runs`` table, so a case
can be traced back to the exact exchange that created it.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .paths import data_dir

MAX_RUNS = 200
MAX_LOG_CHARS = 2_000_000  # keep the archive bounded; head+tail beyond this
_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class RecordingClient:
    """Transparent wrapper that records every ``chat`` exchange.

    Forwards attribute access (``last_finish_reason``, ``cfg``) to the wrapped
    client, so callers need no changes beyond wrapping.
    """

    def __init__(self, inner):
        self.inner = inner
        self.exchanges: list[dict] = []

    @property
    def last_finish_reason(self):
        return getattr(self.inner, "last_finish_reason", None)

    @property
    def last_model(self):
        return getattr(self.inner, "last_model", None)

    def chat(self, messages: list[dict], retries: int = 2, stream_cb=None) -> str:
        entry: dict = {
            "messages": messages,
            "streamed": stream_cb is not None,
            "model": self.last_model,
        }
        try:
            answer = self.inner.chat(messages, retries=retries, stream_cb=stream_cb)
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"
            self.exchanges.append(entry)
            raise
        entry["answer"] = answer
        entry["finish_reason"] = self.last_finish_reason
        entry["model"] = self.last_model
        self.exchanges.append(entry)
        return answer

    def __getattr__(self, name):
        return getattr(self.inner, name)


def default_archive_dir() -> Path:
    return data_dir() / "runs"


def new_run_uuid() -> str:
    return uuid.uuid4().hex


def _bounded_log(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_LOG_CHARS:
        return text, False
    keep = MAX_LOG_CHARS // 2
    return (text[:keep] + "\n... [archive truncated middle] ...\n" + text[-keep:]), True


def build_archive(*, run_uuid: str, host: str, bundle, blocks, blocks_text: str,
                  prefetch_text: str = "", scan_text: str = "", changes_text: str = "",
                  source_text: str = "", facts_text: str = "",
                  exchanges: list[dict] | None = None,
                  result: dict | None = None, verify: dict | None = None,
                  argv: list[str] | None = None, error: str | None = None,
                  base_url: str = "", model: str = "") -> dict:
    dmesg, truncated = _bounded_log(bundle.dmesg_text)
    return {
        "schema": 1,
        "version": __version__,
        "run_uuid": run_uuid,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "argv": list(argv if argv is not None else sys.argv[1:]),
        "host": host,
        "source": bundle.source,
        "kernel": bundle.kernel_version,
        "distro": bundle.distro,
        "base_url": base_url,
        "model": model,
        "dmesg": dmesg,
        "dmesg_truncated": truncated,
        "blocks": [{"start": b.start, "end": b.end, "names": list(b.names)} for b in blocks],
        "blocks_text": blocks_text,
        "prefetch_text": prefetch_text,
        "scan_text": scan_text,
        "changes_text": changes_text,
        "source_text": source_text,
        "facts_text": facts_text,
        "exchanges": exchanges or [],
        "result": result,
        "verify": verify,
        "error": error,
    }


def write_run_archive(payload: dict, root: Path | None = None) -> Path:
    root = Path(root) if root is not None else default_archive_dir()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = _SAFE_RE.sub("_", str(payload.get("host") or "unknown"))[:40].strip("._-") or "unknown"
    uid = str(payload.get("run_uuid") or new_run_uuid())[:12]
    path = root / f"{stamp}-{host}-{uid}.json.gz"
    tmp = path.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    _prune(root)
    return path


def _prune(root: Path) -> None:
    files = sorted(root.glob("*.json.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[MAX_RUNS:]:
        try:
            old.unlink()
        except OSError:
            pass


def load_run_archive(path: str | Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)
