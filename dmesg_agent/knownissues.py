"""Global known-issue knowledge base: community ground truth distilled to a
small, MMU-style three-level index.

    L1 subsystem    (storage / memory / gpu / ...)   from playbooks mapping
    L2 fault_class  (oom / nvme / ata / ...)          from triage signatures
    L3 fingerprint  (struct key: sig + dev + codes)   exact-match, then token sim

Storage is deliberately tiny: each record keeps the index (fingerprint + a
bounded token set), a one-line summary, and an external pointer (url /
message-id). The full thread / patch text is never stored. Duplicate sources
of the same fingerprint merge into one record with multiple URLs.

This module is core (the store + classifier); `dmesg-agent learn` (command
plugin) feeds it and `known_issue_lookup` (context plugin) queries it.
"""

from __future__ import annotations

import json
import sqlite3
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .knowledge import evidence_fingerprint
from .paths import data_dir
from .playbooks import SIGNATURE_TO_SUBSYSTEM, subsystems_from_text
from .triage import SIGNATURES

MAX_TOKENS = 40
TITLE_LEN = 140
ROOT_CAUSE_LEN = 200
FIX_LEN = 120

_LOG_RE = re.compile(r"\[\s*\d+\.\d+\]|^NVRM:| kernel: |^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}")

# Quality gate: drop bulk review series cover letters and release announcements.
_RELEASE_RE = re.compile(
    r"^(?:re:\s*)?Linux \d+\.\d+(?:\.\d+)?(?:-rc\d+)?(?:\s+review)?\s*$", re.I)
_COVER_RE = re.compile(r"\b0+/\d+\b")  # [PATCH 0/2], [PATCH 6.12 000/816], …
_REJECT_RE = re.compile(
    r"\[(?:GIT\s+)?PULL\]|^(?:\[ANNOUNCE\]|FAILED: patch|Fwd:)|"
    r"\b(?:yocto|oe-core|scarthgap|linux-yocto|cve|digest)\b|"
    r"\bupdate(?:s)? to v?\d+\.\d+", re.I)
_CI_RE = re.compile(r"CI[.\s_-]?Hooks|CI=2EHooks|CI check|patchwork|series starting with", re.I)
_L1_PRIORITY = ("storage", "memory", "gpu", "hardware", "network", "usb",
                "thermal", "locking", "firmware", "power", "service",
                "userspace", "disk-space", "package", "net-config", "performance")
_SPECIFIC_RE = re.compile(
    r"\b(?:nvme|nvmet|ata\d*|sata|scsi|ext4|xfs|btrfs|amdgpu|nvidia|nvrm|"
    r"xhci|usb|iwlwifi|drm|block)\b", re.I)
_GENERIC_CLASSES = {"unclassified", "driver", "fault", "sanitizer", "warning"}


def is_noise_issue(title: str, body: str, classification: Classification) -> bool:
    """Reject mails that are not concrete issues.

    Filters seen on real lore searches: release announcements, stable-review
    cover letters (000/816), Yocto/OE version bumps, GIT PULL/ANNOUNCE mails,
    and pure discussion with no log line and only a generic signature. Specific
    patches / classified issues (nvme, ata, ext4, …) are kept.
    """
    t = (title or "").strip()
    if _RELEASE_RE.match(t) or _COVER_RE.search(t) or _REJECT_RE.search(t) \
            or _CI_RE.search(t):
        return True
    if not classification.has_log and classification.fault_class in _GENERIC_CLASSES:
        if _SPECIFIC_RE.search(t):
            return False
        core = classification.core or {}
        if not core.get("dev") and not core.get("codes"):
            return True
    return False


def _ordered_signatures(text: str) -> list[str]:
    """Signature names in order of first appearance (subject/first line wins)."""
    hits: list[tuple[int, str]] = []
    for name, pat in SIGNATURES:
        m = pat.search(text or "")
        if m:
            hits.append((m.start(), name))
    hits.sort()
    return [name for _, name in hits]


def series_key(title: str) -> str:
    """Normalize a patch-series title so v1/v2/v3 and Re: mails collapse.

    `[PATCH v3 1/2] nvmet-tcp: validate …` and `Re: [PATCH v2 2/2] nvmet-tcp:
    validate …` both map to `nvmet-tcp: validate …`.
    """
    s = (title or "").strip()
    s = re.sub(r"^(?:re:\s*)+", "", s, flags=re.I)
    while s.startswith("["):
        end = s.find("]")
        if end < 0:
            break
        s = s[end + 1:].lstrip()
    s = re.sub(r"^(?:v\d+\s+)?\d+/\d+\s*:?\s*", "", s, flags=re.I)
    return re.sub(r"\s+", " ", s).strip().lower()[:160]


@dataclass
class Classification:
    """Result of the deterministic tokenize→signature→subsystem→fingerprint rule."""
    subsystems: list[str]
    fault_classes: list[str]
    subsystem: str       # primary (first hit) for the L1 index
    fault_class: str     # primary for the L2 index
    fingerprint: str
    core: dict
    tokens: list[str]
    has_log: bool


def _looks_like_log_line(line: str) -> bool:
    return bool(_LOG_RE.search(line or ""))


def classify_text(title: str, body: str = "") -> Classification:
    """Classify raw issue text using the SAME rules as diagnosis.

    Reuses `knowledge.evidence_fingerprint`, which runs triage SIGNATURES and
    the device/error-code extractors, so an ingested issue lands in exactly the
    same signature/fingerprint space a live dmesg does.
    """
    full = "\n".join(x for x in (title, body) if x)
    fp = evidence_fingerprint([full])
    core = fp.core or {}
    ordered = _ordered_signatures(full)
    # Primary class follows the FIRST signal in the text (usually the subject /
    # first log line). A patch thread may quote an unrelated "Failed to start"
    # line later; that stays as a secondary label, not the primary class.
    fault_classes = ordered or list(core.get("sig") or [])
    sig_subs: list[str] = []
    for name in fault_classes:
        sub = SIGNATURE_TO_SUBSYSTEM.get(name)
        if sub and sub not in sig_subs:
            sig_subs.append(sub)
    # signature-derived subsystems are deterministic and win; keyword matching
    # is only a fallback for signature-less text (it is noisy: "link" matches
    # both network links and SATA links).
    if sig_subs:
        subs = sig_subs
    else:
        core_subs = [s for s in (core.get("subsystem") or []) if s != "misc"]
        subs = core_subs or sorted(subsystems_from_text(full))
    has_log = any(_looks_like_log_line(l) for l in (full or "").splitlines()[:200])
    primary_sub = subs[0] if subs else "unclassified"
    primary_fc = fault_classes[0] if fault_classes else "unclassified"
    # A patch subject naming a concrete subsystem (nvmet, ata, ext4, …) is a
    # better L1 bucket than a generic quoted signature (hardware/service).
    title_subs = subsystems_from_text(title)
    if title_subs and primary_sub in ("unclassified", "hardware", "service",
                                      "disk-space", "userspace", "power"):
        chosen = min(title_subs, key=lambda s: _L1_PRIORITY.index(s)
                     if s in _L1_PRIORITY else 99)
        if chosen != primary_sub:
            primary_sub = chosen
            for name in fault_classes:
                if SIGNATURE_TO_SUBSYSTEM.get(name) == primary_sub:
                    primary_fc = name
                    break
            else:
                primary_fc = "unclassified"
    return Classification(
        subsystems=subs,
        fault_classes=fault_classes,
        subsystem=primary_sub,
        fault_class=primary_fc,
        fingerprint=fp.value,
        core=core,
        tokens=fp.tokens[:MAX_TOKENS],
        has_log=has_log,
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  series_key TEXT NOT NULL DEFAULT '',
  urls_json TEXT NOT NULL DEFAULT '[]',
  subsystem TEXT NOT NULL DEFAULT '',
  fault_class TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  core_json TEXT NOT NULL DEFAULT '{}',
  tokens_json TEXT NOT NULL DEFAULT '[]',
  title TEXT NOT NULL DEFAULT '',
  symptom TEXT NOT NULL DEFAULT '',
  root_cause TEXT NOT NULL DEFAULT '',
  fix_json TEXT NOT NULL DEFAULT '{}',
  log_snippets_json TEXT NOT NULL DEFAULT '[]',
  confidence REAL NOT NULL DEFAULT 0.0,
  extracted INTEGER NOT NULL DEFAULT 0,
  extracted_at TEXT NOT NULL DEFAULT '',
  extraction_model TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unknown',
  ingested_at TEXT NOT NULL,
  UNIQUE(source, source_id)
);
CREATE INDEX IF NOT EXISTS idx_ki_class ON known_issues(subsystem, fault_class);
CREATE INDEX IF NOT EXISTS idx_ki_fp ON known_issues(fingerprint);
CREATE INDEX IF NOT EXISTS idx_ki_series ON known_issues(series_key);
CREATE TABLE IF NOT EXISTS ingest_cursor (
  source TEXT PRIMARY KEY,
  watermark TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class KnownIssueStore:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else data_dir() / "known-issues.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._conn = sqlite3.connect(str(self.db_path), timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        cols = {row[1] for row in self._conn.execute(
            "PRAGMA table_info(known_issues)")}
        migrations = {
            "series_key": "TEXT NOT NULL DEFAULT ''",
            "symptom": "TEXT NOT NULL DEFAULT ''",
            "log_snippets_json": "TEXT NOT NULL DEFAULT '[]'",
            "extracted": "INTEGER NOT NULL DEFAULT 0",
            "extracted_at": "TEXT NOT NULL DEFAULT ''",
            "extraction_model": "TEXT NOT NULL DEFAULT ''",
        }
        for name, ddl in migrations.items():
            if name not in cols:  # migrate an earlier stage-1 DB
                self._conn.execute(f"ALTER TABLE known_issues ADD COLUMN {name} {ddl}")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ki_series ON known_issues(series_key)")
        self._conn.commit()
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- ingest

    def upsert(self, *, source: str, source_id: str, url: str, title: str,
               classification: Classification, root_cause: str = "",
               fix: dict | None = None, confidence: float = 0.0,
               status: str = "unknown", series_key: str = "") -> bool:
        """Insert or dedupe. Returns True when a NEW row was created.

        Dedup rules, in order: (source, source_id) idempotency; the same
        normalized patch-series title (v1/v2/v3 + Re:) merges; the same
        structural fingerprint (cross-source) merges. Merged rows collect URLs.
        """
        row = self._conn.execute(
            "SELECT id, urls_json FROM known_issues WHERE source=? AND source_id=?",
            (source, source_id)).fetchone()
        if row is not None:
            return False
        fix = fix or {}
        title = (title or "")[:TITLE_LEN]
        root_cause = (root_cause or "")[:ROOT_CAUSE_LEN]
        for k in ("commit", "upgrade_to", "workaround"):
            if fix.get(k):
                fix[k] = str(fix[k])[:FIX_LEN]
        dup = None
        if series_key:
            dup = self._conn.execute(
                "SELECT id, urls_json FROM known_issues WHERE series_key=? LIMIT 1",
                (series_key,)).fetchone()
        if dup is None:
            dup = self._conn.execute(
                "SELECT id, urls_json FROM known_issues WHERE fingerprint=? LIMIT 1",
                (classification.fingerprint,)).fetchone()
        if dup is not None:
            urls = json.loads(dup["urls_json"])
            if url and url not in urls:
                urls.append(url)
                self._conn.execute("UPDATE known_issues SET urls_json=? WHERE id=?",
                                   (json.dumps(urls, ensure_ascii=False), dup["id"]))
                self._conn.commit()
            return False
        self._conn.execute(
            "INSERT INTO known_issues(source, source_id, series_key, urls_json, "
            "subsystem, fault_class, fingerprint, core_json, tokens_json, title, "
            "root_cause, fix_json, confidence, status, ingested_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (source, source_id, series_key,
             json.dumps([url] if url else [], ensure_ascii=False),
             classification.subsystem, classification.fault_class,
             classification.fingerprint,
             json.dumps(classification.core, ensure_ascii=False),
             json.dumps(classification.tokens, ensure_ascii=False),
             title, root_cause, json.dumps(fix, ensure_ascii=False),
             float(confidence), status, _now()))
        self._conn.commit()
        return True

    # ---------------------------------------------------------------- cursor

    def get_watermark(self, source: str) -> str:
        row = self._conn.execute(
            "SELECT watermark FROM ingest_cursor WHERE source=?", (source,)).fetchone()
        return row["watermark"] if row else ""

    def set_watermark(self, source: str, watermark: str) -> None:
        self._conn.execute(
            "INSERT INTO ingest_cursor(source, watermark, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(source) DO UPDATE SET watermark=excluded.watermark, "
            "updated_at=excluded.updated_at",
            (source, str(watermark), _now()))
        self._conn.commit()

    # ---------------------------------------------------------------- query

    def list(self, subsystem: str | None = None, fault_class: str | None = None,
             limit: int = 100) -> list[dict]:
        sql = ("SELECT id, source, source_id, urls_json, subsystem, fault_class, "
               "fingerprint, title, symptom, root_cause, fix_json, confidence, "
               "extracted, status, ingested_at FROM known_issues")
        clauses, params = [], []
        if subsystem:
            clauses.append("subsystem=?")
            params.append(subsystem)
        if fault_class:
            clauses.append("fault_class=?")
            params.append(fault_class)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, limit))
        rows = self._conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["urls"] = json.loads(d.pop("urls_json"))
            d["fix"] = json.loads(d.pop("fix_json"))
            out.append(d)
        return out

    def get(self, issue_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM known_issues WHERE id=?", (issue_id,)).fetchone()
        return self._row_dict(row) if row else None

    def get_by_source_id(self, source: str, source_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM known_issues WHERE source=? AND source_id=?",
            (source, source_id)).fetchone()
        return self._row_dict(row) if row else None

    def get_by_series_key(self, key: str) -> dict | None:
        if not key:
            return None
        row = self._conn.execute(
            "SELECT * FROM known_issues WHERE series_key=? LIMIT 1", (key,)).fetchone()
        return self._row_dict(row) if row else None

    @staticmethod
    def _row_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["urls"] = json.loads(d.pop("urls_json"))
        d["core"] = json.loads(d.pop("core_json"))
        d["tokens"] = json.loads(d.pop("tokens_json"))
        d["fix"] = json.loads(d.pop("fix_json"))
        d["log_snippets"] = json.loads(d.pop("log_snippets_json"))
        return d

    def set_extraction(self, issue_id: int, *, symptom: str, root_cause: str,
                       fix: dict, log_snippets: list[str], confidence: float,
                       model: str = "") -> None:
        fix = fix or {}
        for k in ("commit", "upgrade_to", "workaround"):
            if fix.get(k):
                fix[k] = str(fix[k])[:FIX_LEN]
        self._conn.execute(
            "UPDATE known_issues SET symptom=?, root_cause=?, fix_json=?, "
            "log_snippets_json=?, confidence=?, extracted=1, extracted_at=?, "
            "extraction_model=? WHERE id=?",
            (str(symptom or "")[:ROOT_CAUSE_LEN], str(root_cause or "")[:ROOT_CAUSE_LEN],
             json.dumps(fix, ensure_ascii=False),
             json.dumps(list(log_snippets or [])[:8], ensure_ascii=False),
             max(0.0, min(1.0, float(confidence or 0.0))), _now(), model, issue_id))
        self._conn.commit()

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM known_issues").fetchone()[0]

    def stats(self) -> dict:
        """Per-level bucket counts: the taxonomy tree."""
        l1 = [dict(r) for r in self._conn.execute(
            "SELECT subsystem, COUNT(*) n FROM known_issues GROUP BY subsystem "
            "ORDER BY n DESC").fetchall()]
        l2 = [dict(r) for r in self._conn.execute(
            "SELECT subsystem, fault_class, COUNT(*) n FROM known_issues "
            "GROUP BY subsystem, fault_class ORDER BY n DESC LIMIT 50").fetchall()]
        return {"total": self.count(), "subsystems": l1, "classes": l2}


def default_store_path() -> Path:
    return data_dir() / "known-issues.db"
