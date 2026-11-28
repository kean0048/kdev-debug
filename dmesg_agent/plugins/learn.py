"""Command plugin `dmesg-agent learn`: ingest community issues into the
known-issue store, distilled by the shared tokenize→classify→fingerprint rules.

Stage 1 source: local mbox files (lore.kernel.org / public-inbox). Incremental
ingestion is idempotent (seen-ids + the store's (source, source_id) unique key);
`--since` gates by the mail Date header.
"""

from __future__ import annotations

import argparse
import email
import gzip
import mailbox
import os
import shutil
import sys
import tempfile
import time
from email.header import decode_header, make_header
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from .. import __version__
from ..config import load_config
from ..extractor import extract_issue
from ..knownissues import (KnownIssueStore, classify_text, is_noise_issue,
                           series_key as series_key_for)
from ..llm import Client, LLMError
from ..providers import provider_choices
from ..trackers import fetch_bugzilla, fetch_gitlab, fetch_launchpad
from . import register

LORE_UA = f"dmesg-agent/{__version__} (+Kean Ren <renhai2.k@gmail.com>)"
LORE_SEARCH_URL = "https://lore.kernel.org/all/?{query}&x=m"


def _lore_request(query: str, full_threads: bool = False):
    """Build the POST request for lore's search-mbox form.

    lore ignores x=m on GETs and serves the mbox from a POST button; no
    message-id is needed to download all search results.
    """
    url = LORE_SEARCH_URL.format(query=urllib.parse.urlencode({"q": query}))
    form = {"x": "full threads"} if full_threads else {"z": "results only"}
    data = urllib.parse.urlencode(form).encode()
    headers = {
        "User-Agent": LORE_UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/gzip, application/mbox, */*",
    }
    return url, data, headers


def fetch_lore_search(query: str, full_threads: bool = False,
                      max_mb: int = 128, timeout: int = 120,
                      progress=None) -> str:
    """POST a lore search, stream the mbox to a temp file, return its path.

    ``progress(bytes_so_far)`` is called after each chunk so a long download is
    visible. The caller removes the file. HTML responses (lore sometimes serves
    its search page instead of the mbox) are rejected after the first chunk.
    """
    url, data, headers = _lore_request(query, full_threads)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    cap = max(1, max_mb) * 1024 * 1024
    fd, tmp_path = tempfile.mkstemp(suffix=".mbox")
    os.close(fd)
    total = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ctype = ""
            try:
                ctype = (resp.headers.get("Content-Type") or "").lower()
            except Exception:
                pass
            if "text/html" in ctype:
                raise ValueError("lore returned an HTML page instead of mbox "
                                 "(narrow the query or retry)")
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    if total == 0:
                        head = chunk[:512].lstrip().lower()
                        if head.startswith(b"<html") or head.startswith(b"<!doctype html"):
                            raise ValueError("lore returned an HTML page instead of "
                                             "mbox (narrow the query or retry)")
                    total += len(chunk)
                    if total > cap:
                        raise ValueError(
                            f"lore search mbox exceeds {max_mb} MB — narrow the query "
                            f"or raise --max-download-mb")
                    out.write(chunk)
                    if progress:
                        progress(total)
    except urllib.error.HTTPError as e:
        Path(tmp_path).unlink(missing_ok=True)
        raise ValueError(f"lore search failed: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        Path(tmp_path).unlink(missing_ok=True)
        raise ValueError(f"lore search failed: {e.reason}") from e
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    if total == 0:
        Path(tmp_path).unlink(missing_ok=True)
        raise ValueError("lore search returned an empty response")
    return tmp_path


# --------------------------------------------------------------- lore adapter

def _message_body(msg) -> str:
    try:
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
            return "\n".join(parts)
        payload = msg.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if payload else ""
    except Exception:
        return ""


def _mail_date(msg) -> datetime | None:
    raw = msg.get("Date") or ""
    try:
        return email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None


def _decode_subject(value: str) -> str:
    """Decode RFC2047 subjects (e.g. =?utf-8?q?...?=) so CI/patches are readable."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return value.strip()


def _is_html(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(512).lstrip().lower()
    except OSError:
        return False
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def iter_mbox(path: str, source: str = "lore") -> list[dict]:
    """Parse an mbox (mboxrd/mboxo, plain or .gz) into issue dicts.

    Raises ValueError for HTML pages / non-mbox files instead of silently
    returning zero records (a common mistake: lore's search mbox needs
    ``&r&x=m``; plain ``&x=m`` returns the HTML page).
    """
    parse_path = path
    tmp_path: str | None = None
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
        if magic == b"\x1f\x8b":  # gzip-compressed mbox (.mbox.gz)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mbox")
            tmp_path = tmp.name
            tmp.close()
            with gzip.open(path, "rb") as src, open(tmp_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            parse_path = tmp_path
        elif _is_html(path):
            raise ValueError(
                "looks like an HTML page, not an mbox — use lore's "
                "'download mbox.gz' button (a POST form), or a thread URL "
                "ending in /t.mbox.gz")
        issues: list[dict] = []
        mbox = mailbox.mbox(parse_path, create=False)
        try:
            for msg in mbox:
                mid = (msg.get("Message-ID") or "").strip().strip("<>")
                subject = _decode_subject(msg.get("Subject") or "")
                if not mid:
                    continue
                date = _mail_date(msg)
                issues.append({
                    "source": source,
                    "source_id": mid,
                    "url": f"https://lore.kernel.org/all/{mid}/",
                    "title": subject,
                    "body": _message_body(msg),
                    "date": date.isoformat() if date else "",
                })
        finally:
            mbox.close()
        if not issues:
            raise ValueError("no messages parsed — is this an mbox file?")
        return issues
    except OSError as e:
        raise ValueError(f"cannot read mbox: {e}") from e
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)


# ------------------------------------------------------------------- command

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmesg-agent learn",
        description="ingest community issues into the known-issue store")
    p.add_argument("--mbox", metavar="PATH", action="append", default=[],
                   help="lore.kernel.org / public-inbox mbox file (repeatable)")
    p.add_argument("--lore-search", metavar="QUERY", action="append", default=[],
                   help="search lore.kernel.org and download the matching mbox "
                        "(POST form; no message-id needed; repeatable)")
    p.add_argument("--full-threads", action="store_true",
                   help="with --lore-search, download full threads instead of results only")
    p.add_argument("--tracker-query", metavar="QUERY",
                   help="query for the REST trackers (--bugzilla/--launchpad/--gitlab)")
    p.add_argument("--bugzilla", metavar="BASE", action="append", default=[],
                   help="Bugzilla base URL, e.g. https://bugzilla.kernel.org or "
                        "https://bugzilla.redhat.com (repeatable)")
    p.add_argument("--launchpad", action="store_true",
                   help="search Launchpad bugs")
    p.add_argument("--gitlab", metavar="PROJECT_URL", action="append", default=[],
                   help="GitLab project URL, e.g. https://gitlab.gnome.org/GNOME/mutter "
                        "(repeatable)")
    p.add_argument("--tracker-limit", type=int, default=25,
                   help="max issues per tracker source (default 25)")
    p.add_argument("--gitlab-token", default=None,
                   help="GitLab token for private projects (or GITLAB_TOKEN)")
    p.add_argument("--max-download-mb", type=int, default=128,
                   help="cap for one lore search mbox (default 128 MB)")
    p.add_argument("--source", default="lore", help="source label (default: lore)")
    p.add_argument("--extract", action="store_true",
                   help="LLM-extract symptom/root_cause/fix/log_snippets for new records")
    p.add_argument("--max-extract", type=int, default=25, metavar="N",
                   help="max LLM extractions per run (0 = all; default 25)")
    p.add_argument("--provider", choices=provider_choices(),
                   help="LLM provider preset for extraction")
    p.add_argument("--base-url", help="LLM base URL for extraction")
    p.add_argument("--model", help="LLM model for extraction")
    p.add_argument("--api-key", help="LLM API key for extraction")
    p.add_argument("--db", default=None, help="known-issues DB path (default: XDG data dir)")
    p.add_argument("--since", default=None,
                   help="skip mail older than this ISO date (e.g. 2024-01-01)")
    p.add_argument("--limit", type=int, default=0, help="max new issues to ingest (0 = all)")
    p.add_argument("--loop", action="store_true",
                   help="keep re-scanning mboxes (cron-less continuous update)")
    p.add_argument("--interval", type=int, default=3600,
                   help="seconds between --loop scans (default 3600)")
    p.add_argument("--verbose", action="store_true", help="log each classified issue")
    return p


def _maybe_extract(store, issue: dict, client, args, state: dict) -> None:
    """LLM-extract one issue's root cause/fix/snippets if still pending."""
    if client is None or state["disabled"]:
        return
    if args.max_extract and state["attempts"] >= args.max_extract:
        return
    key = series_key_for(issue["title"])
    row = (store.get_by_source_id(issue["source"], issue["source_id"])
           or store.get_by_series_key(key))
    if row is None or row.get("extracted"):
        return
    state["attempts"] += 1
    print(f"  extracting: {issue['title'][:70]}", file=sys.stderr, flush=True)
    try:
        data = extract_issue(client, issue["title"], issue["body"])
    except LLMError as e:
        print(f"warning: extraction failed ({e}); continuing without extraction",
              file=sys.stderr)
        state["disabled"] = True
        return
    except Exception as e:
        print(f"warning: extraction error ({type(e).__name__}: {e}); continuing",
              file=sys.stderr)
        state["disabled"] = True
        return
    if not data:
        print(f"warning: extraction returned unusable JSON for "
              f"{issue['title'][:60]!r}", file=sys.stderr)
        return
    store.set_extraction(
        row["id"], symptom=data.get("symptom", ""),
        root_cause=data.get("root_cause", ""), fix=data.get("fix") or {},
        log_snippets=data.get("log_snippets") or [],
        confidence=data.get("confidence", 0.0),
        model=getattr(client, "last_model", None) or "")
    state["extracted"] += 1
    if args.verbose:
        dropped = data.get("_dropped_snippets", 0)
        bad_fix = data.get("_dropped_fix_commit", 0)
        extra = ""
        if dropped:
            extra += f", {dropped} snippet(s) dropped as non-verbatim"
        if bad_fix:
            extra += f", {bad_fix} unverified fix commit dropped"
        print(f"  extracted: {data.get('root_cause', '')[:90]}{extra}",
              file=sys.stderr)


def _ingest(store: KnownIssueStore, issues: list[dict], args, seen: set[str],
            client=None, state: dict | None = None) -> dict:
    since = datetime.fromisoformat(args.since) if args.since else None
    state = state or {"extracted": 0, "attempts": 0, "disabled": False}
    new = dedup = filtered = 0
    for issue in issues:
        if since and issue["date"]:
            try:
                if datetime.fromisoformat(issue["date"]) < since:
                    continue
            except ValueError:
                pass
        if args.limit and new >= args.limit:
            break
        if issue["source_id"] in seen:
            _maybe_extract(store, issue, client, args, state)
            continue
        seen.add(issue["source_id"])
        cls = classify_text(issue["title"], issue["body"])
        if is_noise_issue(issue["title"], issue["body"], cls):
            filtered += 1
            if args.verbose:
                print(f"  skip noise: {issue['title'][:70]}")
            continue
        created = store.upsert(
            source=issue["source"], source_id=issue["source_id"], url=issue["url"],
            title=issue["title"], classification=cls,
            series_key=series_key_for(issue["title"]))
        new += 1 if created else 0
        dedup += 0 if created else 1
        _maybe_extract(store, issue, client, args, state)
        if args.verbose:
            print(f"  [{cls.subsystem}/{cls.fault_class}] {issue['title'][:70]}")
    return {"new": new, "dedup": dedup, "filtered": filtered}


@register("command", order=20,
          description="ingest community issues (lore mbox) into the known-issue store")
def learn(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    trackers_requested = bool(args.bugzilla or args.launchpad or args.gitlab)
    if not args.mbox and not args.lore_search and not trackers_requested:
        print("error: no input — pass --mbox /path/to/lore.mbox, "
              "--lore-search 'query' (bulk, no message-id needed), or a REST "
              "tracker (--bugzilla/--launchpad/--gitlab with --tracker-query)",
              file=sys.stderr)
        return 2
    if trackers_requested and not args.tracker_query:
        print("error: --tracker-query is required with "
              "--bugzilla/--launchpad/--gitlab", file=sys.stderr)
        return 2
    store = KnownIssueStore(args.db)
    seen: set[str] = set()
    failed = False
    client = None
    state = {"extracted": 0, "attempts": 0, "disabled": False}
    if args.extract:
        cfg = load_config(provider=args.provider, base_url=args.base_url,
                          model=args.model, api_key=args.api_key)
        client = Client(cfg)
        print(f"extraction via {cfg.base_url} ({cfg.model or 'auto-discover'})",
              file=sys.stderr)
    try:
        while True:
            total = {"new": 0, "dedup": 0, "filtered": 0}
            tracker_jobs = ([("bugzilla", base) for base in args.bugzilla]
                            + ([("launchpad", "")] if args.launchpad else [])
                            + [("gitlab", project) for project in args.gitlab])
            for kind, target in tracker_jobs:
                label = target or kind
                print(f"{kind} search: {args.tracker_query!r} at {label} — waiting…",
                      file=sys.stderr, flush=True)
                try:
                    if kind == "bugzilla":
                        issues = fetch_bugzilla(target, args.tracker_query,
                                                limit=args.tracker_limit)
                    elif kind == "launchpad":
                        issues = fetch_launchpad(args.tracker_query,
                                                 limit=args.tracker_limit)
                    else:
                        issues = fetch_gitlab(
                            target, args.tracker_query, limit=args.tracker_limit,
                            token=args.gitlab_token
                            or os.environ.get("GITLAB_TOKEN", ""))
                except ValueError as e:
                    print(f"error: {kind} {label}: {e}", file=sys.stderr)
                    failed = True
                    continue
                if args.verbose:
                    print(f"  {len(issues)} issue(s) from {label}",
                          file=sys.stderr, flush=True)
                res = _ingest(store, issues, args, seen, client=client, state=state)
                total["new"] += res["new"]
                total["dedup"] += res["dedup"]
                total["filtered"] += res["filtered"]
            paths = list(args.mbox)
            temps: list[str] = []
            try:
                for query in args.lore_search:
                    mode = "full threads" if args.full_threads else "results only"
                    print(f"lore search: {query!r} ({mode}) — waiting for lore…",
                          file=sys.stderr, flush=True)
                    last_mb = [0]

                    def _progress(total: int) -> None:
                        mb = total // (1024 * 1024)
                        if mb >= last_mb[0] + 8:
                            last_mb[0] = mb
                            print(f"  downloaded {mb} MB…", file=sys.stderr, flush=True)

                    try:
                        tmp = fetch_lore_search(query, full_threads=args.full_threads,
                                                max_mb=args.max_download_mb,
                                                progress=_progress)
                        try:
                            size = Path(tmp).stat().st_size
                            print(f"  fetched {size / (1024 * 1024):.1f} MB, parsing…",
                                  file=sys.stderr, flush=True)
                        except OSError:
                            pass
                        paths.append(tmp)
                        temps.append(tmp)
                    except ValueError as e:
                        print(f"error: lore search {query!r}: {e}", file=sys.stderr)
                        failed = True
                for path in paths:
                    if not Path(path).exists():
                        print(f"error: mbox not found: {path}", file=sys.stderr)
                        failed = True
                        continue
                    try:
                        issues = iter_mbox(path, source=args.source)
                    except ValueError as e:
                        print(f"error: {path}: {e}", file=sys.stderr)
                        failed = True
                        continue
                    if args.verbose:
                        print(f"  {len(issues)} message(s) parsed from {path}",
                              file=sys.stderr, flush=True)
                    res = _ingest(store, issues, args, seen, client=client, state=state)
                    total["new"] += res["new"]
                    total["dedup"] += res["dedup"]
                    total["filtered"] += res["filtered"]
            finally:
                for tmp in temps:
                    Path(tmp).unlink(missing_ok=True)
            st = store.stats()
            print(f"learn: +{total['new']} new, {total['dedup']} dedup, "
                  f"{total['filtered']} noise filtered, {state['extracted']} extracted "
                  f"({state['attempts']} LLM attempt(s); store: {st['total']} issues, "
                  f"{len(st['subsystems'])} subsystems)")
            if not args.loop:
                break
            time.sleep(max(1, args.interval))
    finally:
        store.close()
    return 2 if failed and not args.loop else 0
