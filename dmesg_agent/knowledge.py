"""Cross-run case library (sashiko bug-store ideas), shadow mode by default.

Every confirmed finding is reduced to a *structural fingerprint* built from its
verbatim evidence quotes: matched log-signature classes + device tokens + error
codes + subsystem routing. Volatile values (timestamps, PIDs, sectors, hex
addresses) are normalized away, so the same fault on the same host maps to the
same fingerprint across boots while different fault classes stay apart.

Findings without usable evidence fall back to the original content-word
fingerprint (subsystem + title + root cause), preserving the zero-token
recurrence behaviour of the previous tracker.

Shadow mode: matches are recorded and annotated, but never change the
analysis. A later release turns exact matches against ``confirmed`` cases into
a fast path (LLM judges only the delta versus the stored case).

Storage: SQLite at ``$XDG_DATA_HOME/dmesg-agent/knowledge.db`` (0600).
Override with ``--knowledge-db`` or ``DMESG_AGENT_KNOWLEDGE_DB``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .playbooks import subsystems_from_signatures
from .triage import SIGNATURES

DEFAULT_FUZZY = 0.65   # similar-case recall threshold (evidence fingerprints)
TEXT_MERGE = 0.5       # near-duplicate merge threshold (text fallback, legacy)
MAX_CASES_PER_HOST = 2000

STATUSES = ("candidate", "confirmed", "dismissed", "fixed")

# ---------------------------------------------------------------- regexes

_TS_RE = re.compile(r"^\s*\[[^\]]*\]\s*")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_NUM_RE = re.compile(r"\b\d+\b")
_CODE_RE = re.compile(r"\b(serr|emask|errno)\s*[:=]?\s*(0x[0-9a-fA-F]+|-?\d+)", re.IGNORECASE)
_DEV_RE = re.compile(
    r"\b(ata\d+(?:\.\d+)?|nvme\d+(?:n\d+)?(?:p\d+)?|sd[a-z]+\d*|dm-\d+|md\d+|loop\d+"
    r"|wl[a-z0-9]+|enp\d+s\d+|eth\d+)\b", re.IGNORECASE)
_SYM_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\+0x")
_MOD_RE = re.compile(r"\[([a-z0-9_\-]+)\]")
_WORD_RE = re.compile(r"[a-z][a-z0-9_.+-]{2,}")

# legacy text-fingerprint semantics (kept identical to the old tracker)
_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "being", "been",
    "of", "in", "on", "at", "to", "for", "with", "and", "or", "but", "not",
    "this", "that", "these", "those", "it", "its", "may", "might", "can",
    "could", "would", "should", "has", "have", "had", "from", "by", "as",
    "due", "likely", "possible", "probably", "seen", "issue", "problem",
    "error", "errors", "failure", "failures", "failed", "suspected",
}
_TEXT_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.+-]*")


class KnowledgeError(Exception):
    pass


# ------------------------------------------------------------ fingerprints

@dataclass
class Fingerprint:
    kind: str                 # "evidence" | "text"
    value: str                # sha256 hex, first 16 chars (exact-match key)
    core: dict = field(default_factory=dict)
    tokens: list[str] = field(default_factory=list)


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def text_words(*texts: str) -> frozenset[str]:
    blob = " ".join(t.lower() for t in texts if t)
    return frozenset(w for w in _TEXT_WORD_RE.findall(blob)
                     if len(w) > 1 and w not in _STOPWORDS)


def _normalize(text: str) -> str:
    text = _TS_RE.sub("", text.strip()).lower()
    text = _HEX_RE.sub(" <hex> ", text)
    text = _NUM_RE.sub(" <n> ", text)
    return text


def evidence_fingerprint(quotes: list[str]) -> Fingerprint:
    """Structural fingerprint from verbatim log lines (deterministic)."""
    text = "\n".join(quotes)
    sig = sorted({name for name, pat in SIGNATURES if pat.search(text)})
    devices = sorted({m.group(1).lower() for m in _DEV_RE.finditer(text)})
    codes: set[str] = set()
    for m in _CODE_RE.finditer(text):
        word, val = m.group(1).lower(), m.group(2)
        if val.lower().startswith("0x"):
            codes.add(f"{word}={int(val, 16)}")
        elif word == "errno":
            codes.add(f"errno={int(val)}")
    subsystems = set(subsystems_from_signatures(set(sig)))
    for d in devices:
        if d.startswith(("ata", "sd", "nvme", "dm-", "md", "loop")):
            subsystems.add("storage")
        elif d.startswith(("eth", "enp", "wl")):
            subsystems.add("network")

    # collapse partition/device suffixes for fuzzy recall (ata6.00 → ata6,
    # nvme0n1p1 → nvme0n1) so device-number drift does not dilute similarity
    tokens: set[str] = set(sig) | set(codes)
    for d in devices:
        tokens.add(re.sub(r"p\d+$", "", re.sub(r"\.\d+$", "", d)))
    tokens |= {s.lower() for s in _SYM_RE.findall(text)}
    tokens |= {m.lower() for m in _MOD_RE.findall(text)}
    for word in _WORD_RE.findall(_normalize(text)):
        word = word.rstrip(".+-_")
        if len(word) >= 3 and word not in _STOPWORDS:
            tokens.add(word)

    if sig or devices or codes:
        core = {"kind": "struct", "subsystem": sorted(subsystems) or ["misc"],
                "sig": sig, "dev": devices, "codes": sorted(codes)}
    else:
        words = sorted({w for w in _WORD_RE.findall(_normalize(text))
                        if w not in _STOPWORDS and not w.isdigit()})[:12]
        core = {"kind": "words", "subsystem": sorted(subsystems) or ["misc"], "words": words}
    value = hashlib.sha256(
        json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return Fingerprint(kind="evidence", value=value, core=core,
                       tokens=sorted(tokens)[:80])


def text_fingerprint(subsystem: str, title: str, root_cause: str) -> Fingerprint:
    """Legacy content-word fingerprint for findings without log evidence."""
    words = text_words(subsystem, title) or text_words(root_cause)
    core = {"kind": "text", "subsystem": subsystem, "words": sorted(words)}
    value = hashlib.sha256(" ".join(sorted(core["words"])).encode()).hexdigest()[:16]
    return Fingerprint(kind="text", value=value, core=core,
                       tokens=sorted(words)[:80])


def fingerprint_for_finding(finding: dict) -> Fingerprint | None:
    quotes = [str(ev.get("quote", "")) for ev in (finding.get("evidence") or [])
              if isinstance(ev, dict) and str(ev.get("quote", "")).strip()]
    if quotes:
        return evidence_fingerprint(quotes)
    fp = text_fingerprint(str(finding.get("subsystem", "")),
                          str(finding.get("title", "")),
                          str(finding.get("root_cause_hypothesis", "")))
    return fp if fp.tokens else None


# ------------------------------------------------------------------- store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_host TEXT NOT NULL,
  fp_kind TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  core_json TEXT NOT NULL,
  tokens_json TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  subsystem TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'candidate',
  root_cause TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  kernel TEXT NOT NULL DEFAULT '',
  occurrences INTEGER NOT NULL DEFAULT 0,
  UNIQUE(scope_host, fp_kind, fingerprint)
);
CREATE TABLE IF NOT EXISTS occurrences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  run_uuid TEXT NOT NULL,
  ts TEXT NOT NULL,
  kernel TEXT NOT NULL DEFAULT '',
  tier TEXT NOT NULL,
  score REAL NOT NULL DEFAULT 1.0,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE(case_id, run_uuid)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_uuid TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  host TEXT NOT NULL,
  kernel TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  findings INTEGER NOT NULL DEFAULT 0,
  verified_pass INTEGER NOT NULL DEFAULT 0,
  verified_total INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cases_host ON cases(scope_host, last_seen);
"""


def default_db_path() -> Path:
    root = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(root) / "dmesg-agent" / "knowledge.db"


def resolve_db_path(cli_path: str | None = None) -> Path:
    if cli_path:
        return Path(cli_path)
    env = os.environ.get("DMESG_AGENT_KNOWLEDGE_DB")
    return Path(env) if env else default_db_path()


def _connect(path: Path) -> sqlite3.Connection:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(str(path), timeout=10)
    except OSError as e:
        raise KnowledgeError(f"cannot open knowledge base {path}: {e}") from e
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_run(db_path, host: str, result: dict, *, kernel: str = "", source: str = "",
               now: str | None = None, fuzzy_threshold: float = DEFAULT_FUZZY,
               verified: tuple[int, int] = (0, 0), run_uuid: str | None = None) -> dict:
    """Upsert every finding into the case library (shadow mode).

    Mutates each finding with ``f["recurrence"]`` (kept compatible with the
    previous tracker) and ``f["case"]``. Returns a summary dict meant for
    ``result["knowledge"]`` and the Markdown report.
    """
    ts = now or _now()
    run_uuid = run_uuid or uuid.uuid4().hex
    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    matches: list[dict] = []
    seen: dict[tuple[str, str], dict] = {}
    new_cases = 0
    conn = _connect(Path(db_path))
    try:
        for idx, f in enumerate(findings):
            fp = fingerprint_for_finding(f)
            if fp is None:
                continue
            key = (fp.kind, fp.value)
            if key in seen:
                info = dict(seen[key], finding_index=idx, title=str(f.get("title", "")))
                matches.append(info)
                _annotate(f, info)
                continue
            info, created = _match_or_create(
                conn, host, fp, f, ts, kernel, run_uuid, fuzzy_threshold)
            if created:
                new_cases += 1
            info.update(finding_index=idx, title=str(f.get("title", "")))
            seen[key] = info
            matches.append(info)
            _annotate(f, info)

        conn.execute(
            "INSERT OR IGNORE INTO runs(run_uuid, ts, host, kernel, source, summary, "
            "findings, verified_pass, verified_total) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_uuid, ts, host, kernel, source, str(result.get("summary", ""))[:4000],
             len(findings), int(verified[0]), int(verified[1])))
        _prune(conn, host)
        conn.commit()
    except sqlite3.Error as e:
        raise KnowledgeError(f"knowledge base update failed: {e}") from e
    finally:
        conn.close()

    return {
        "mode": "shadow",
        "db": str(db_path),
        "host": host,
        "run_uuid": run_uuid,
        "matches": matches,
        "new_cases": new_cases,
        "recurrences": sum(1 for m in matches
                           if m["tier"] in ("exact", "merged") and m["occurrences"] >= 2),
    }


def _match_or_create(conn: sqlite3.Connection, host: str, fp: Fingerprint, finding: dict,
                     ts: str, kernel: str, run_uuid: str,
                     fuzzy_threshold: float) -> tuple[dict, bool]:
    row = conn.execute(
        "SELECT * FROM cases WHERE scope_host=? AND fp_kind=? AND fingerprint=?",
        (host, fp.kind, fp.value)).fetchone()
    tier, score, similar_id, created, regression = "exact", 1.0, None, False, False

    if row is None:
        best: tuple[int, float] | None = None
        for cand in conn.execute(
                "SELECT id, tokens_json FROM cases WHERE scope_host=? AND fp_kind=?",
                (host, fp.kind)):
            cand_score = _jaccard(set(fp.tokens), set(json.loads(cand["tokens_json"])))
            if cand_score >= fuzzy_threshold and (best is None or cand_score > best[1]):
                best = (cand["id"], cand_score)
        if fp.kind == "text" and best and best[1] >= TEXT_MERGE:
            # legacy behaviour: reworded finding = same bug
            row = conn.execute("SELECT * FROM cases WHERE id=?", (best[0],)).fetchone()
            tier, score = "merged", best[1]
        else:
            cur = conn.execute(
                "INSERT INTO cases(scope_host, fp_kind, fingerprint, core_json, tokens_json, "
                "title, subsystem, severity, status, root_cause, first_seen, last_seen, "
                "kernel, occurrences) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (host, fp.kind, fp.value, json.dumps(fp.core, ensure_ascii=False),
                 json.dumps(fp.tokens), str(finding.get("title", ""))[:300],
                 str(finding.get("subsystem", ""))[:120],
                 str(finding.get("severity", ""))[:20], "candidate",
                 str(finding.get("root_cause_hypothesis", ""))[:2000], ts, ts, kernel))
            row = conn.execute("SELECT * FROM cases WHERE id=?",
                               (cur.lastrowid,)).fetchone()
            created = True
            tier = "fuzzy" if best else "new"
            score = best[1] if best else 0.0
            similar_id = best[0] if best else None
    elif row["status"] == "fixed":
        conn.execute("UPDATE cases SET status='candidate' WHERE id=?", (row["id"],))
        regression = True

    quotes = [str(ev.get("quote", "")) for ev in (finding.get("evidence") or [])
              if isinstance(ev, dict) and str(ev.get("quote", "")).strip()]
    cur = conn.execute(
        "INSERT OR IGNORE INTO occurrences(case_id, run_uuid, ts, kernel, tier, score, "
        "evidence_json) VALUES(?,?,?,?,?,?,?)",
        (row["id"], run_uuid, ts, kernel, tier, float(score),
         json.dumps(quotes, ensure_ascii=False)))
    if cur.rowcount:
        conn.execute(
            "UPDATE cases SET occurrences=occurrences+1, last_seen=?, kernel=?, "
            "title=CASE WHEN title='' THEN ? ELSE title END, "
            "subsystem=CASE WHEN subsystem='' THEN ? ELSE subsystem END, "
            "severity=CASE WHEN severity='' THEN ? ELSE severity END, "
            "root_cause=CASE WHEN root_cause='' THEN ? ELSE root_cause END WHERE id=?",
            (ts, kernel, str(finding.get("title", ""))[:300],
             str(finding.get("subsystem", ""))[:120],
             str(finding.get("severity", ""))[:20],
             str(finding.get("root_cause_hypothesis", ""))[:2000], row["id"]))

    row = conn.execute("SELECT * FROM cases WHERE id=?", (row["id"],)).fetchone()
    info = {
        "case_id": row["id"],
        "tier": tier,
        "score": round(float(score), 3),
        "status": row["status"],
        "occurrences": row["occurrences"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "regression": regression,
        "similar_case_id": similar_id,
    }
    return info, created


def _annotate(finding: dict, info: dict) -> None:
    if info["occurrences"] >= 2:
        finding["recurrence"] = {"count": info["occurrences"],
                                 "first_seen": info["first_seen"]}
    finding["case"] = {
        "id": info["case_id"],
        "status": info["status"],
        "tier": info["tier"],
        "occurrences": info["occurrences"],
        "regression": info["regression"],
        "similar_case_id": info["similar_case_id"],
    }


def _prune(conn: sqlite3.Connection, host: str) -> None:
    count = conn.execute("SELECT COUNT(*) FROM cases WHERE scope_host=?",
                         (host,)).fetchone()[0]
    if count > MAX_CASES_PER_HOST:
        conn.execute(
            "DELETE FROM cases WHERE id IN (SELECT id FROM cases WHERE scope_host=? "
            "ORDER BY last_seen ASC LIMIT ?)", (host, count - MAX_CASES_PER_HOST))


# -------------------------------------------------------------- cases CLI

def _status_update(db_path: Path, case_id: int, status: str) -> int:
    conn = _connect(db_path)
    try:
        cur = conn.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
        conn.commit()
        if cur.rowcount == 0:
            print(f"error: case #{case_id} not found", file=sys.stderr)
            return 1
    finally:
        conn.close()
    print(f"case #{case_id} → {status}")
    return 0


def cases_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dmesg-agent cases",
        description="inspect and manage the per-host case library (shadow mode)")
    parser.add_argument("--db", help="knowledge base path "
                                     "(default: $XDG_DATA_HOME/dmesg-agent/knowledge.db)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    subparsers = []
    lst = sub.add_parser("list", help="list cases")
    lst.add_argument("--host", help="only this host")
    lst.add_argument("--status", choices=STATUSES)
    lst.add_argument("--limit", type=int, default=30)
    subparsers.append(lst)
    show = sub.add_parser("show", help="show one case with its recent occurrences")
    show.add_argument("id", type=int)
    subparsers.append(show)
    for name, help_text in (("confirm", "mark a case confirmed (eligible for the future fast path)"),
                            ("dismiss", "mark a case dismissed (known noise)"),
                            ("fixed", "mark a case fixed (a recurrence will reopen it)")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("id", type=int)
        subparsers.append(sp)
    for sp in subparsers:
        # accept --db after the subcommand too (SUPPRESS: never override the
        # top-level value when the flag is absent)
        sp.add_argument("--db", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    db_path = resolve_db_path(args.db)
    if not db_path.exists() and args.cmd != "list":
        print(f"no knowledge base at {db_path} yet — run an analysis first")
        return 1

    if args.cmd in ("confirm", "dismiss", "fixed"):
        status = {"confirm": "confirmed", "dismiss": "dismissed", "fixed": "fixed"}[args.cmd]
        return _status_update(db_path, args.id, status)

    conn = _connect(db_path)
    try:
        if args.cmd == "list":
            sql = ("SELECT id, scope_host, status, occurrences, last_seen, subsystem, title "
                   "FROM cases")
            clauses, params = [], []
            if args.host:
                clauses.append("scope_host=?")
                params.append(args.host)
            if args.status:
                clauses.append("status=?")
                params.append(args.status)
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY last_seen DESC LIMIT ?"
            params.append(max(1, args.limit))
            rows = conn.execute(sql, params).fetchall()
            if not rows:
                print("(no cases)")
                return 0
            print(f"{'ID':>5}  {'STATUS':<10} {'OCC':>3}  {'LAST SEEN':<20} HOST")
            print(f"{'':>5}  {'':<10} {'':>3}  {'':<20} SUBSYSTEM / TITLE")
            for r in rows:
                print(f"{r['id']:>5}  {r['status']:<10} {r['occurrences']:>3}  "
                      f"{r['last_seen']:<20} {r['scope_host']}")
                print(f"{'':>5}  {r['subsystem'] or '?'} / {r['title'][:100]}")
            return 0

        row = conn.execute("SELECT * FROM cases WHERE id=?", (args.id,)).fetchone()
        if row is None:
            print(f"error: case #{args.id} not found", file=sys.stderr)
            return 1
        print(f"case #{row['id']}  [{row['status']}]  host={row['scope_host']}")
        print(f"  title:      {row['title']}")
        print(f"  subsystem:  {row['subsystem'] or '?'}   severity: {row['severity'] or '?'}")
        print(f"  occurrences:{row['occurrences']}  first: {row['first_seen']}  "
              f"last: {row['last_seen']}  kernel: {row['kernel'] or '?'}")
        print(f"  root cause: {row['root_cause'] or '(none)'}")
        print(f"  fingerprint({row['fp_kind']}): {row['fingerprint']}")
        print(f"  core: {json.dumps(json.loads(row['core_json']), ensure_ascii=False)}")
        print("  recent occurrences:")
        for occ in conn.execute(
                "SELECT ts, tier, score, evidence_json FROM occurrences "
                "WHERE case_id=? ORDER BY id DESC LIMIT 5", (args.id,)):
            print(f"  - {occ['ts']} via {occ['tier']} (score {occ['score']})")
            for quote in json.loads(occ["evidence_json"])[:2]:
                print(f"      | {str(quote)[:140]}")
        return 0
    finally:
        conn.close()
