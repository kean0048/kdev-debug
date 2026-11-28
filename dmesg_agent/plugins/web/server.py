"""Local web UI for offline analysis: upload → background CLI job → report.

Stdlib only (http.server), no external assets, no shell. Each job runs the
normal CLI in a subprocess with an isolated XDG_DATA_HOME for its archive; the
case-library DB is shared so history/fast-path works across jobs.
"""

from __future__ import annotations

import gzip
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ...knowledge import resolve_db_path
from ...paths import data_dir
from ...report import build_verdict
from ...verify import VerifySummary
from .ui import UI_HTML

MAX_UPLOAD = 512 * 1024 * 1024
MAX_JSON = 1_000_000
LOG_TAIL_CHARS = 12_000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_JOB_RE = re.compile(r"^/api/jobs/([0-9a-f]{32})(?:/(report\.md|report\.html|archive|log))?$")
_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_STAGE_RE = re.compile(r"^\[(\d(?:\.\d)?/5|3\.5)\]\s*(.*)$")


def _iso(ts: float | None) -> str | None:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) if ts else None


@dataclass
class Job:
    id: str
    dir: Path
    filename: str
    host_id: str
    issue: str = ""
    kernel: str = ""
    distro: str = ""
    status: str = "created"  # created|uploaded|running|done|failed|cancelled
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    input_path: Path | None = None
    report_md: Path | None = None
    report_html: Path | None = None
    log_path: Path | None = None
    proc: subprocess.Popen | None = None
    exit_code: int | None = None
    cancel_requested: bool = False
    result: dict | None = None
    verify: dict = field(default_factory=dict)
    verdict: dict | None = None
    archive_path: Path | None = None
    error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def read_log(self, max_chars: int = LOG_TAIL_CHARS) -> str:
        if not self.log_path or not self.log_path.exists():
            return ""
        try:
            size = self.log_path.stat().st_size
            with open(self.log_path, "rb") as f:
                if size > max_chars:
                    f.seek(size - max_chars)
                data = f.read()
            return _ANSI_RE.sub("", data.decode("utf-8", errors="replace"))
        except OSError:
            return ""

    def stage(self) -> str:
        for line in reversed(self.read_log(4000).splitlines()):
            m = _STAGE_RE.match(line.strip())
            if m:
                return f"[{m.group(1)}] {m.group(2)[:160]}"
        return ""

    def to_dict(self, include_log: bool = False) -> dict:
        with self.lock:
            d = {
                "id": self.id,
                "status": self.status,
                "filename": self.filename,
                "host_id": self.host_id,
                "created": _iso(self.created),
                "started": _iso(self.started),
                "finished": _iso(self.finished),
                "exit_code": self.exit_code,
                "error": self.error,
                "stage": self.stage(),
                "has_report": bool(self.report_md and self.report_md.exists()),
                "has_html": bool(self.report_html and self.report_html.exists()),
                "has_archive": bool(self.archive_path and self.archive_path.exists()),
            }
            if self.result:
                findings = [f for f in (self.result.get("findings") or [])
                            if isinstance(f, dict)]
                d["result_summary"] = str(self.result.get("summary", ""))
                d["findings"] = [{
                    "title": f.get("title", ""),
                    "subsystem": f.get("subsystem", "?"),
                    "severity": f.get("severity", "?"),
                    "root_cause": f.get("root_cause_hypothesis", ""),
                    "next_steps": f.get("next_steps") or [],
                } for f in findings[:20]]
                d["verify"] = self.verify
                d["verdict"] = self.verdict
            if include_log:
                d["log"] = self.read_log()
            return d


class JobManager:
    def __init__(self, root: Path, runner=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self.runner = runner  # test hook: callable(job) -> exit code
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self._load_existing()

    def _load_existing(self) -> None:
        """Restore job history after a server restart (reports/archives on disk)."""
        try:
            entries = list(self.root.iterdir())
        except OSError:
            return
        for job_dir in entries:
            if not job_dir.is_dir() or not _JOB_ID_RE.match(job_dir.name):
                continue
            meta_path = job_dir / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job = Job(
                id=job_dir.name, dir=job_dir,
                filename=str(meta.get("filename") or "input"),
                host_id=str(meta.get("host_id") or "web"),
                issue=str(meta.get("issue") or ""),
                kernel=str(meta.get("kernel") or ""),
                distro=str(meta.get("distro") or ""),
                created=float(meta.get("created") or job_dir.stat().st_mtime),
                status="done")
            job.input_path = job_dir / "input" if (job_dir / "input").exists() else None
            job.report_md = job_dir / "report.md"
            job.report_html = job_dir / "report.html"
            job.log_path = job_dir / "run.log"
            job.finished = job_dir.stat().st_mtime
            if not (job.report_md.exists() or job.report_html.exists()):
                job.status = "failed"
                job.error = "previous server stopped before this job finished"
            self._load_result(job)
            self.jobs[job.id] = job

    # ------------------------------------------------------------------ jobs
    def create(self, filename: str, issue: str = "", host_id: str = "",
               kernel: str = "", distro: str = "") -> Job:
        jid = uuid.uuid4().hex
        job_dir = self.root / jid
        job_dir.mkdir(mode=0o700)
        try:
            os.chmod(job_dir, 0o700)
        except OSError:
            pass
        safe_name = Path(str(filename or "input")).name[:200] or "input"
        host = re.sub(r"[^A-Za-z0-9._:-]", "_", str(host_id or "web"))[:128] or "web"
        job = Job(id=jid, dir=job_dir, filename=safe_name, host_id=host,
                  issue=str(issue or "")[:100_000], kernel=str(kernel or "")[:200],
                  distro=str(distro or "")[:200])
        (job_dir / "issue.txt").write_text(job.issue, encoding="utf-8")
        (job_dir / "meta.json").write_text(json.dumps({
            "filename": job.filename, "host_id": job.host_id, "kernel": job.kernel,
            "distro": job.distro, "issue": job.issue, "created": job.created},
            ensure_ascii=False),
            encoding="utf-8")
        with self.lock:
            self.jobs[jid] = job
        return job

    def get(self, jid: str) -> Job | None:
        with self.lock:
            return self.jobs.get(jid)

    def list(self) -> list[dict]:
        with self.lock:
            jobs = list(self.jobs.values())
        return [j.to_dict() for j in sorted(jobs, key=lambda j: j.created, reverse=True)]

    # ---------------------------------------------------------------- upload
    def upload_target(self, jid: str) -> tuple[Job, Path, Path]:
        job = self.get(jid)
        if job is None:
            raise KeyError("job not found")
        if job.status not in ("created", "uploaded"):
            raise ValueError("job is not accepting uploads")
        part = job.dir / "input.part"
        return job, part, job.dir / "input"

    def finish_upload(self, job: Job) -> None:
        part = job.dir / "input.part"
        if not part.exists():
            raise ValueError("upload is incomplete")
        final = job.dir / "input"
        os.replace(part, final)
        try:
            os.chmod(final, 0o600)
        except OSError:
            pass
        job.input_path = final
        job.status = "uploaded"

    def save_upload(self, jid: str, body: bytes) -> Job:
        if not body:
            raise ValueError("empty upload")
        if len(body) > MAX_UPLOAD:
            raise ValueError("upload too large")
        job, part, _final = self.upload_target(jid)
        part.write_bytes(body)
        self.finish_upload(job)
        return job

    # ----------------------------------------------------------------- start
    def _cmd(self, job: Job) -> list[str]:
        job.report_md = job.dir / "report.md"
        job.report_html = job.dir / "report.html"
        job.log_path = job.dir / "run.log"
        cmd = [sys.executable, "-m", "dmesg_agent.cli",
               "--file", str(job.input_path),
               "--host-id", job.host_id,
               "-o", str(job.report_md),
               "--html", str(job.report_html),
               "-v",
               "--knowledge-db", str(resolve_db_path(None))]
        if job.kernel:
            cmd += ["--kernel", job.kernel]
        if job.distro:
            cmd += ["--distro", job.distro]
        if job.issue.strip():
            cmd += ["--issue", str(job.dir / "issue.txt")]
        return cmd

    def start(self, jid: str) -> Job:
        job = self.get(jid)
        if job is None:
            raise KeyError("job not found")
        if job.status != "uploaded":
            raise ValueError("upload a file first")
        job.status = "running"
        job.started = time.time()
        job.report_md = job.dir / "report.md"
        job.report_html = job.dir / "report.html"
        job.log_path = job.dir / "run.log"
        if self.runner is not None:
            threading.Thread(target=self._run_fake, args=(job,), daemon=True).start()
            return job
        env = os.environ.copy()
        env["XDG_DATA_HOME"] = str(job.dir / "data")
        env["PYTHONUNBUFFERED"] = "1"
        log = open(job.log_path, "wb")
        try:
            job.proc = subprocess.Popen(
                self._cmd(job), stdout=log, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, env=env, cwd=str(self.root))
        except OSError as e:
            log.close()
            job.error = f"cannot start analysis: {e}"
            job.status = "failed"
            job.finished = time.time()
            return job
        threading.Thread(target=self._monitor, args=(job, log), daemon=True).start()
        return job

    def _run_fake(self, job: Job) -> None:
        try:
            rc = int(self.runner(job))
        except Exception as e:  # test hook must not kill the server
            job.error = f"runner failed: {type(e).__name__}: {e}"
            rc = 1
        self._finalize(job, rc)

    def _monitor(self, job: Job, log) -> None:
        rc = job.proc.wait()
        try:
            log.close()
        except OSError:
            pass
        self._finalize(job, rc)

    def _finalize(self, job: Job, rc: int) -> None:
        with job.lock:
            job.exit_code = rc
            job.finished = time.time()
            if job.cancel_requested or rc == 130:
                job.status = "cancelled"
            elif rc == 0:
                job.status = "done"
            else:
                job.status = "failed"
                if not job.error:
                    tail = job.read_log(600).strip().splitlines()
                    job.error = tail[-1] if tail else f"analysis exited with code {rc}"
            self._load_result(job)

    def _load_result(self, job: Job) -> None:
        runs_dir = job.dir / "data" / "dmesg-agent" / "runs"
        try:
            runs = sorted(runs_dir.glob("*.json.gz"),
                          key=lambda p: p.stat().st_mtime)
        except OSError:
            return
        if not runs:
            return
        try:
            with gzip.open(runs[-1], "rt", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            if not job.error:
                job.error = f"cannot read run archive: {e}"
            return
        result = data.get("result")
        verify = data.get("verify") or {}
        job.archive_path = runs[-1]
        job.verify = verify
        if isinstance(result, dict):
            job.result = result
            summary = VerifySummary(
                total=int(verify.get("total", 0) or 0),
                passed=int(verify.get("passed", 0) or 0),
                line_mismatch=int(verify.get("line_mismatch", 0) or 0))
            job.verdict = build_verdict(result, summary)

    # ---------------------------------------------------------------- cancel
    def cancel(self, jid: str) -> Job:
        job = self.get(jid)
        if job is None:
            raise KeyError("job not found")
        if job.status in ("done", "failed", "cancelled"):
            return job
        job.cancel_requested = True
        proc = job.proc
        if proc is None:
            job.status = "cancelled"
            job.finished = time.time()
            return job
        try:
            proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        return job


# ------------------------------------------------------------------ HTTP

class _Handler(BaseHTTPRequestHandler):
    manager: JobManager
    token: str | None = None
    server_version = "dmesg-agent-web"

    def log_message(self, fmt, *args):  # quiet polling
        pass

    # ------------------------------------------------------------- auth/io
    def _authorized(self, query: dict) -> bool:
        if not self.token:
            return True
        supplied = self.headers.get("X-Auth-Token") or (query.get("token") or [""])[0]
        return hmac.compare_digest(str(supplied or ""), self.token)

    def _send(self, status: int, body: bytes, ctype: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("bad Content-Length")
        if length <= 0 or length > MAX_JSON:
            raise ValueError("request body too large or empty")
        data = self.rfile.read(length)
        obj = json.loads(data)
        if not isinstance(obj, dict):
            raise ValueError("JSON object expected")
        return obj

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if not self._authorized(query):
                return self._error(401, "unauthorized")
            path = parsed.path
            if path in ("/", "/index.html"):
                return self._send(200, UI_HTML.encode("utf-8"), "text/html; charset=utf-8",
                                  {"Content-Security-Policy":
                                   "default-src 'none'; style-src 'unsafe-inline'; "
                                   "script-src 'unsafe-inline'; connect-src 'self'"})
            if path == "/api/jobs":
                return self._json(200, {"jobs": self.manager.list()})
            m = _JOB_RE.match(path)
            if not m:
                return self._error(404, "not found")
            job = self.manager.get(m.group(1))
            if job is None:
                return self._error(404, "job not found")
            action = m.group(2)
            if action is None:
                return self._json(200, job.to_dict(include_log=True))
            if action == "report.md":
                return self._file(job.report_md, "text/markdown; charset=utf-8")
            if action == "report.html":
                return self._file(job.report_html, "text/html; charset=utf-8",
                                  {"Content-Security-Policy":
                                   "default-src 'none'; style-src 'unsafe-inline'; "
                                   "img-src data:"})
            if action == "log":
                return self._file(job.log_path, "text/plain; charset=utf-8")
            if action == "archive":
                if not job.archive_path or not job.archive_path.exists():
                    return self._error(404, "archive not available")
                return self._file(job.archive_path, "application/gzip",
                                  {"Content-Disposition": 'attachment; filename="run.json.gz"'})
            return self._error(404, "not found")
        except Exception as e:
            traceback.print_exc()
            self._error(500, str(e))

    def _file(self, path: Path | None, ctype: str, extra: dict | None = None) -> None:
        if path is None or not path.exists():
            return self._error(404, "file not available")
        data = path.read_bytes()
        self._send(200, data, ctype, extra)

    do_HEAD = do_GET

    # --------------------------------------------------------------- POST
    def do_POST(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if not self._authorized(query):
                return self._error(401, "unauthorized")
            path = parsed.path
            if path == "/api/jobs":
                body = self._read_json()
                job = self.manager.create(
                    filename=str(body.get("filename") or "input"),
                    issue=str(body.get("issue") or ""),
                    host_id=str(body.get("host_id") or "web"),
                    kernel=str(body.get("kernel") or ""),
                    distro=str(body.get("distro") or ""))
                return self._json(201, {"id": job.id})
            m = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/(start|cancel)", path)
            if not m:
                return self._error(404, "not found")
            try:
                if m.group(2) == "start":
                    job = self.manager.start(m.group(1))
                else:
                    job = self.manager.cancel(m.group(1))
            except KeyError:
                return self._error(404, "job not found")
            except ValueError as e:
                return self._error(400, str(e))
            return self._json(200, job.to_dict())
        except (ValueError, json.JSONDecodeError) as e:
            return self._error(400, str(e))
        except Exception as e:
            traceback.print_exc()
            self._error(500, str(e))

    # ---------------------------------------------------------------- PUT
    def do_PUT(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if not self._authorized(query):
                return self._error(401, "unauthorized")
            m = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/file", parsed.path)
            if not m:
                return self._error(404, "not found")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._error(400, "bad Content-Length")
            if length <= 0:
                return self._error(411, "Content-Length required")
            if length > MAX_UPLOAD:
                return self._error(413, "upload too large")
            try:
                job, part, _final = self.manager.upload_target(m.group(1))
            except KeyError:
                return self._error(404, "job not found")
            except ValueError as e:
                return self._error(400, str(e))
            remaining = length
            try:
                with open(part, "wb") as f:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
            except OSError as e:
                part.unlink(missing_ok=True)
                return self._error(500, f"cannot store upload: {e}")
            if remaining:
                part.unlink(missing_ok=True)
                return self._error(400, "incomplete upload")
            self.manager.finish_upload(job)
            return self._json(200, {"id": job.id, "status": job.status})
        except Exception as e:
            traceback.print_exc()
            self._error(500, str(e))


def make_handler(manager: JobManager, token: str | None = None):
    class Handler(_Handler):
        pass
    Handler.manager = manager
    Handler.token = token
    return Handler


def serve(host: str, port: int, token: str | None, job_root: str | None,
          open_browser: bool = True) -> int:
    root = Path(job_root) if job_root else data_dir() / "web" / "jobs"
    manager = JobManager(root)
    handler = make_handler(manager, token)
    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as e:
        print(f"error: cannot listen on {host}:{port}: {e}", file=sys.stderr)
        return 2
    httpd.daemon_threads = True
    actual_port = httpd.server_address[1]
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{display_host}:{actual_port}/" + (f"?token={token}" if token else "")
    print(f"dmesg-agent web: {url}")
    print(f"jobs: {root}  (Ctrl-C to stop)")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    print("\nweb server stopped", file=sys.stderr)
    return 0
