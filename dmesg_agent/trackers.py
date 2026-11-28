"""REST tracker adapters for the known-issue store (stage 3).

Public, read-only APIs only: Bugzilla (bugzilla.kernel.org / Fedora), Launchpad
and GitLab. Each adapter returns issue dicts shaped exactly like the lore mbox
adapter — ``{source, source_id, url, title, body, date}`` — so `learn` runs the
same classification, noise filter, dedup and extraction on them.

No scraping, no user-agent spoofing: a fixed honest User-Agent is sent.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

from . import __version__

TRACKER_UA = f"dmesg-agent/{__version__} (+Kean Ren <renhai2.k@gmail.com>)"
LAUNCHPAD_API = "https://api.launchpad.net/1.0"


def _get_json(url: str, timeout: int = 30, accept: str = "application/json",
              extra_headers: dict | None = None) -> Any:
    headers = {"User-Agent": TRACKER_UA, "Accept": accept}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} from {url}") from e
    except OSError as e:  # URLError, timeouts and socket errors
        raise ValueError(f"cannot reach {url}: {e}") from e
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError as e:
        raise ValueError(f"non-JSON response from {url}") from e


def _iso_date(raw) -> str:
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


# ------------------------------------------------------------------ bugzilla

def fetch_bugzilla(base: str, query: str, limit: int = 25,
                   timeout: int = 30, fetch_comments: bool = True) -> list[dict]:
    """Search a public Bugzilla (kernel.org, Fedora) and read comment 0.

    The reporter's first comment usually carries the kernel log excerpt, which
    is what makes the record classifiable and extractable.
    """
    base = (base or "").strip().rstrip("/")
    if not base:
        raise ValueError("bugzilla base URL is empty")
    params = urllib.parse.urlencode({
        "quicksearch": query,
        "limit": max(1, limit),
        "include_fields": "id,summary,status,resolution,product,component,"
                          "creation_time,last_change_time",
    })
    data = _get_json(f"{base}/rest/bug?{params}", timeout=timeout)
    if not isinstance(data, dict):
        raise ValueError(f"unexpected bugzilla response from {base}")
    host = urllib.parse.urlparse(base).netloc or base
    out: list[dict] = []
    for bug in (data.get("bugs") or [])[:max(1, limit)]:
        bid = bug.get("id")
        if not bid:
            continue
        body_parts = [
            f"Product: {bug.get('product')} / {bug.get('component')}",
            f"Status: {bug.get('status')} {bug.get('resolution') or ''}".strip(),
        ]
        if fetch_comments:
            try:
                comments = _get_json(f"{base}/rest/bug/{bid}/comment", timeout=timeout)
                if isinstance(comments, dict):
                    by_bug = comments.get("bugs") or {}
                    entry = by_bug.get(str(bid)) or by_bug.get(bid) or {}
                    # bugzilla.kernel.org: {"bugs": {"<id>": {"comments": [...]}}}
                    # older/simple servers: {"bugs": {"<id>": [...]}}
                    if isinstance(entry, dict):
                        entries = entry.get("comments") or []
                    elif isinstance(entry, list):
                        entries = entry
                    else:
                        entries = []
                    if entries:
                        body_parts.append(str(entries[0].get("text") or ""))
            except ValueError:
                pass  # comment text is optional; keep the summary record
        out.append({
            "source": f"bugzilla:{host}",
            "source_id": str(bid),
            "url": f"{base}/show_bug.cgi?id={bid}",
            "title": " ".join(str(bug.get("summary") or "").split()),
            "body": "\n".join(body_parts),
            "date": _iso_date(bug.get("creation_time")),
        })
    return out


# ----------------------------------------------------------------- launchpad

def fetch_launchpad(query: str, limit: int = 25, timeout: int = 30) -> list[dict]:
    """Search Launchpad bug tasks, then fetch each bug's title/description."""
    params = urllib.parse.urlencode({
        "ws.op": "searchTasks",
        "search_text": query,
        "ws.size": max(1, limit),
    })
    data = _get_json(f"{LAUNCHPAD_API}/bugs?{params}", timeout=timeout)
    if not isinstance(data, dict):
        raise ValueError("unexpected launchpad search response")
    out: list[dict] = []
    for task in (data.get("entries") or [])[:max(1, limit)]:
        link = task.get("bug_link")
        if not link:
            continue
        try:
            bug = _get_json(link, timeout=timeout)
        except ValueError:
            continue
        if not isinstance(bug, dict):
            continue
        bid = bug.get("id") or str(link).rstrip("/").rsplit("/", 1)[-1]
        task_title = str(task.get("title") or "")
        out.append({
            "source": "launchpad",
            "source_id": str(bid),
            "url": f"https://bugs.launchpad.net/bugs/{bid}",
            "title": " ".join(str(bug.get("title") or task_title).split()),
            "body": task_title + "\n" + str(bug.get("description") or ""),
            "date": _iso_date(bug.get("date_created")),
        })
    return out


# -------------------------------------------------------------------- gitlab

def _parse_gitlab_target(target: str) -> tuple[str, str]:
    """`https://gitlab.gnome.org/GNOME/mutter` -> (base, 'GNOME/mutter')."""
    target = (target or "").strip().rstrip("/")
    if not target:
        raise ValueError("gitlab project URL is empty")
    parsed = urllib.parse.urlparse(
        target if "://" in target else "https://" + target)
    path = parsed.path.strip("/")
    if not parsed.netloc or not path:
        raise ValueError(f"gitlab target must be HOST/GROUP/PROJECT: {target!r}")
    return f"{parsed.scheme}://{parsed.netloc}", path


def fetch_gitlab(project: str, query: str, limit: int = 25,
                 timeout: int = 30, token: str = "") -> list[dict]:
    """Search one GitLab project's issues (open and closed)."""
    base, path = _parse_gitlab_target(project)
    params = urllib.parse.urlencode({
        "search": query,
        "per_page": max(1, min(limit, 100)),
        "scope": "all",
        "state": "all",
        "order_by": "created_at",
        "sort": "desc",
    })
    headers = {"PRIVATE-TOKEN": token} if token else None
    url = f"{base}/api/v4/projects/{urllib.parse.quote(path, safe='')}/issues?{params}"
    data = _get_json(url, timeout=timeout, extra_headers=headers)
    if not isinstance(data, list):
        raise ValueError(f"unexpected gitlab response from {base}")
    host = urllib.parse.urlparse(base).netloc or base
    out: list[dict] = []
    for it in data[:max(1, limit)]:
        iid = it.get("iid")
        if not iid:
            continue
        labels = ", ".join(it.get("labels") or [])
        body = str(it.get("description") or "")
        if labels:
            body = f"Labels: {labels}\n{body}"
        out.append({
            "source": f"gitlab:{host}/{path}",
            "source_id": f"{path}!{iid}",
            "url": str(it.get("web_url") or f"{base}/{path}/-/issues/{iid}"),
            "title": " ".join(str(it.get("title") or "").split()),
            "body": body,
            "date": _iso_date(it.get("created_at")),
        })
    return out
