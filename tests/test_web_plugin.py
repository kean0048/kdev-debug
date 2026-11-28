import gzip
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from dmesg_agent.plugins.web.server import JobManager, make_handler


def fake_runner(job):
    (job.dir / "report.md").write_text("# fake report\n", encoding="utf-8")
    (job.dir / "report.html").write_text(
        "<!doctype html><title>fake</title>", encoding="utf-8")
    runs = job.dir / "data" / "dmesg-agent" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    payload = {
        "result": {
            "summary": "fake summary",
            "findings": [{"title": "fake finding", "subsystem": "storage",
                          "severity": "high", "evidence": [], "next_steps": ["fix"]}],
            "inconclusive_concerns": [], "dismissed_concerns": [],
        },
        "verify": {"total": 3, "passed": 2, "line_mismatch": 0},
    }
    with gzip.open(runs / "run.json.gz", "wt", encoding="utf-8") as f:
        json.dump(payload, f)
    return 0


def _wait(manager, job_id, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = manager.get(job_id)
        if job.status in ("done", "failed", "cancelled"):
            return job
        time.sleep(0.02)
    return manager.get(job_id)


def test_jobmanager_runs_fake_job(tmp_path):
    manager = JobManager(tmp_path / "jobs", runner=fake_runner)
    job = manager.create("../../etc/passwd", issue="symptom", host_id="JIRA-1",
                         kernel="6.12", distro="Debian 13")
    assert job.filename == "passwd"          # display name only, no path use
    assert job.dir.parent == manager.root
    manager.save_upload(job.id, b"[1.0] test\n")
    manager.start(job.id)
    done = _wait(manager, job.id)
    assert done.status == "done"
    assert done.result["summary"] == "fake summary"
    assert done.verify == {"total": 3, "passed": 2, "line_mismatch": 0}
    assert done.verdict["health"] == "WARNING"
    assert done.report_md.exists() and done.report_html.exists()
    assert done.archive_path and done.archive_path.exists()


def test_jobmanager_requires_upload(tmp_path):
    manager = JobManager(tmp_path / "jobs", runner=fake_runner)
    job = manager.create("dmesg.txt")
    try:
        manager.start(job.id)
        assert False, "start without upload must fail"
    except ValueError:
        pass


def _server(tmp_path, token=None):
    manager = JobManager(tmp_path / "jobs", runner=fake_runner)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(manager, token))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, manager, f"http://127.0.0.1:{httpd.server_address[1]}"


def test_http_upload_run_and_auth(tmp_path):
    httpd, manager, base = _server(tmp_path, token="secret")
    try:
        # unauthorized
        try:
            urllib.request.urlopen(base + "/", timeout=3)
            assert False, "expected 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401
        assert "dmesg-agent web" in urllib.request.urlopen(
            base + "/?token=secret", timeout=3).read().decode()
        head = urllib.request.Request(base + "/?token=secret", method="HEAD")
        with urllib.request.urlopen(head, timeout=3) as resp:
            assert resp.status == 200 and resp.read() == b""

        meta = {"filename": "../dmesg.txt", "issue": "hangs", "host_id": "JIRA-7",
                "kernel": "6.12.11", "distro": "Debian 13"}
        req = urllib.request.Request(
            base + "/api/jobs", data=json.dumps(meta).encode(), method="POST",
            headers={"Content-Type": "application/json", "X-Auth-Token": "secret"})
        job_id = json.load(urllib.request.urlopen(req, timeout=3))["id"]

        req = urllib.request.Request(
            base + f"/api/jobs/{job_id}/file", data=b"[1.0] test\n", method="PUT",
            headers={"Content-Type": "application/octet-stream",
                     "X-Auth-Token": "secret"})
        assert json.load(urllib.request.urlopen(req, timeout=3))["status"] == "uploaded"

        req = urllib.request.Request(
            base + f"/api/jobs/{job_id}/start", data=b"{}", method="POST",
            headers={"Content-Type": "application/json", "X-Auth-Token": "secret"})
        urllib.request.urlopen(req, timeout=3).read()

        deadline = time.time() + 3
        status = {}
        while time.time() < deadline:
            status = json.load(urllib.request.urlopen(
                base + f"/api/jobs/{job_id}?token=secret", timeout=3))
            if status["status"] in ("done", "failed", "cancelled"):
                break
            time.sleep(0.02)
        assert status["status"] == "done"
        assert status["verdict"]["health"] == "WARNING"
        assert status["verify"]["passed"] == 2

        report = urllib.request.urlopen(
            base + f"/api/jobs/{job_id}/report.md?token=secret", timeout=3).read()
        assert b"fake report" in report
        with urllib.request.urlopen(
                base + f"/api/jobs/{job_id}/report.html?token=secret", timeout=3) as resp:
            assert "default-src 'none'" in resp.headers.get("Content-Security-Policy", "")
        archive = urllib.request.urlopen(
            base + f"/api/jobs/{job_id}/archive?token=secret", timeout=3).read()
        assert archive[:2] == b"\x1f\x8b"

        # bad/unknown job ids are 404, no path access
        try:
            urllib.request.urlopen(base + "/api/jobs/not-a-job?token=secret", timeout=3)
            assert False, "expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_web_registered_as_command():
    from dmesg_agent import plugins as pf
    pf.registry.reset()
    pf.load_plugins()
    assert pf.registry.named("command", "web") is not None


def test_job_history_survives_restart(tmp_path):
    root = tmp_path / "jobs"
    manager = JobManager(root, runner=fake_runner)
    job = manager.create("dmesg.txt", issue="x", host_id="H")
    manager.save_upload(job.id, b"[1.0] x\n")
    manager.start(job.id)
    assert _wait(manager, job.id).status == "done"

    restarted = JobManager(root, runner=fake_runner)
    restored = restarted.get(job.id)
    assert restored is not None
    assert restored.status == "done"
    assert restored.result["summary"] == "fake summary"
    assert any(row["id"] == job.id for row in restarted.list())


def test_web_open_flags():
    from dmesg_agent.plugins.web import build_parser
    p = build_parser()
    assert p.parse_args([]).open_browser is True
    assert p.parse_args(["--open"]).open_browser is True
    assert p.parse_args(["--no-open"]).open_browser is False
    import pytest
    with pytest.raises(SystemExit):
        p.parse_args(["--open", "--no-open"])
