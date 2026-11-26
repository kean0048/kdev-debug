"""Cross-run recurrence tracking (sashiko bug-tracking ideas, zero-token tier).

Each confirmed finding gets a fingerprint from its normalized content words
(subsystem + title + root-cause words, stopwords removed). A new finding is
"the same bug" when its word-set has Jaccard similarity >= 0.5 with a stored
entry on the same host — no LLM involved, exactly sashiko's tier-1/tier-2
idea applied to log diagnosis instead of git history.

State: one JSON file under XDG_STATE_HOME (default ~/.local/state/), mode
0600, atomically replaced, capped to the most recently seen entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

JACCARD_SAME = 0.5
MAX_ENTRIES = 500
STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "being", "been",
    "of", "in", "on", "at", "to", "for", "with", "and", "or", "but", "not",
    "this", "that", "these", "those", "it", "its", "may", "might", "can",
    "could", "would", "should", "has", "have", "had", "from", "by", "as",
    "due", "likely", "possible", "probably", "seen", "issue", "problem",
    "error", "errors", "failure", "failures", "failed", "suspected",
}

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")


def _words(*texts: str) -> frozenset[str]:
    blob = " ".join(t.lower() for t in texts if t)
    return frozenset(w for w in _WORD_RE.findall(blob)
                     if len(w) > 1 and w not in STOPWORDS)


def fingerprint(subsystem: str, title: str, root_cause: str) -> str:
    core = _words(subsystem, title) or _words(root_cause)
    return hashlib.sha256(" ".join(sorted(core)).encode()).hexdigest()[:16]


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def state_path() -> Path:
    root = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(root) / "dmesg-agent" / "recurrence.json"


def _load(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def record_recurrences(result: dict, host: str, now: str | None = None) -> None:
    """Mutate result: annotate findings with recurrence info and persist the
    store. Findings seen before get f['recurrence'] = {count, first_seen}."""
    stamp = now or time.strftime("%Y-%m-%dT%H:%M:%S")
    path = state_path()
    data = _load(path)
    host_entries: dict = data.setdefault(host, {})

    for f in result.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        sub = str(f.get("subsystem", ""))
        title = str(f.get("title", ""))
        cause = str(f.get("root_cause_hypothesis", ""))
        fp = fingerprint(sub, title, cause)
        w_new = _words(sub, title, cause)

        entry = host_entries.get(fp)
        if entry is None:
            # near-duplicate merge: same bug, different wording
            for other_fp, other in host_entries.items():
                if _jaccard(w_new, frozenset(other.get("words", []))) >= JACCARD_SAME:
                    entry = other
                    fp = other_fp
                    break
        if entry is None:
            host_entries[fp] = {
                "title": title[:120], "subsystem": sub,
                "words": sorted(w_new)[:40],
                "first_seen": stamp, "last_seen": stamp, "count": 1,
            }
        else:
            entry["count"] = int(entry.get("count", 1)) + 1
            entry["last_seen"] = stamp
            entry["words"] = sorted(w_new)[:40]
            # only recurring findings carry the field: "seen before" is the
            # actionable signal; brand-new findings would always get count=1
            f["recurrence"] = {"count": entry["count"],
                               "first_seen": entry.get("first_seen", stamp)}

    # prune oldest by last_seen
    if len(host_entries) > MAX_ENTRIES:
        keep = sorted(host_entries.items(),
                      key=lambda kv: kv[1].get("last_seen", ""), reverse=True)[:MAX_ENTRIES]
        data[host] = dict(keep)
    _save(path, data)
