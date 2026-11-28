# Web UI (`dmesg-agent web`)

A command plugin that serves a local single-page UI for offline diagnosis:
upload a log/package + the reporter's description, watch the analysis, and
read/download the report. No extra Python dependencies (stdlib `http.server`),
no build step, no external assets.

```bash
dmesg-agent check                 # provider must be configured first
dmesg-agent web --port 8790 --open
```

Default bind is **127.0.0.1 only**. To listen on another interface:

```bash
dmesg-agent web --host 0.0.0.0 --port 8790
# auto-generates an access token and prints the URL with ?token=…
```

## What the page does

- Upload: dmesg/kern.log, sosreport tar(.xz), `journalctl -o json`/`-o export`,
  or `nvidia-bug-report.log.gz`; optional Jira description, host/ticket id,
  kernel, distro.
- Runs the normal CLI in a background subprocess (offline `--file` pipeline:
  package extraction, facts, issue context, history/fast path, LLM analysis).
- Polls job status: stage (`[4/5] …`), live log tail (including model thinking),
  cancel (SIGINT → the CLI's graceful 130 path).
- Result card: health/headline/chips, findings, evidence-verified count;
  downloads for Markdown, self-contained HTML, raw log, run archive.
- Job history is restored from disk when the server restarts.

## Storage and isolation

- Jobs: `$XDG_DATA_HOME/dmesg-agent/web/jobs/<uuid>/` (fallback per
  `paths.py`), mode 0700; `input`, `issue.txt`, `meta.json`, `run.log`,
  `report.md`, `report.html`.
- Each job gets its own `XDG_DATA_HOME` so its run archive never collides.
- The case-library DB is **shared** (passed explicitly as `--knowledge-db`) so
  host history and the confirmed fast path work across jobs.
- Upload cap: 512 MB. Job ids are server-generated UUIDs; uploaded names are
  display-only (the input path is fixed).

## Security model

- Loopback by default; non-loopback binds require a token (query `?token=` for
  pages/links, `X-Auth-Token` for API calls).
- No shell: jobs are `subprocess` argv lists; the only commands executed are
  the CLI's normal offline pipeline (no live/executor collection).
- Reports are served with `Content-Security-Policy: default-src 'none'`; the
  UI uses `textContent` for all user/log data. The generated HTML report is
  escaped/script-free by the core renderer.
- Logs/reports are plain text endpoints; all file reads are inside the job
  directory.

## Performance note

The page uses the configured provider. With the local Qwen thinking model,
one analysis can take many minutes; to speed up smoke tests, start the server
with thinking disabled:

```bash
DMESG_AGENT_EXTRA_BODY='{"chat_template_kwargs":{"enable_thinking":false}}' \
  dmesg-agent web --port 8790
```

Keep thinking on for real diagnoses (quality tradeoff).

## Plugin behaviour

- Registered as the `command` plugin `web` (`dmesg-agent plugins list`).
- Disable without deleting: `DMESG_AGENT_DISABLE_PLUGINS=web dmesg-agent …`
  (`dmesg-agent web` becomes unavailable; the CLI is unchanged).
- Remove `dmesg_agent/plugins/web/` to drop the feature entirely.
- The web plugin never imports `cli.py`; it invokes
  `python -m dmesg_agent.cli` as a subprocess, so the core pipeline stays the
  single source of truth.

## HTTP API (for scripts)

```
POST /api/jobs                         {filename, issue, host_id, kernel, distro}
PUT  /api/jobs/<id>/file               raw bytes (Content-Length required)
POST /api/jobs/<id>/start
GET  /api/jobs                         list
GET  /api/jobs/<id>                    status + verdict/findings/log tail
POST /api/jobs/<id>/cancel
GET  /api/jobs/<id>/report.md
GET  /api/jobs/<id>/report.html
GET  /api/jobs/<id>/archive            run archive (.json.gz)
GET  /api/jobs/<id>/log                full run log
```

With a token configured, add `X-Auth-Token: <token>` (or `?token=` on GET).
