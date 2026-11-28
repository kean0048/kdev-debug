"""Single-page UI for the web plugin (inline CSS/JS, no external assets)."""

from __future__ import annotations

UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dmesg-agent web</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0f1216; color: #d7dde5;
         font: 14px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  header { display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: baseline;
           padding: 18px 26px; border-bottom: 1px solid #232b35; }
  header h1 { margin: 0; font-size: 19px; letter-spacing: .3px; }
  header .sub { color: #8b98a6; font-size: 13px; }
  main { max-width: 1120px; margin: 0 auto; padding: 18px 22px 40px; }
  .card { background: #161b22; border: 1px solid #26303b; border-radius: 10px;
          padding: 16px 18px; margin: 14px 0; }
  .card h2 { margin: 0 0 10px; font-size: 15px; color: #c9d3de; }
  label { display: block; margin: 10px 0 4px; color: #9aa7b5; font-size: 12px;
          text-transform: uppercase; letter-spacing: .5px; }
  input, textarea { width: 100%; background: #0d1117; color: #e6edf3;
                    border: 1px solid #303a46; border-radius: 6px; padding: 8px 10px;
                    font: inherit; }
  textarea { min-height: 84px; resize: vertical; }
  .row { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  button { background: #2f81f7; color: white; border: 0; border-radius: 6px;
           padding: 8px 16px; font: inherit; cursor: pointer; }
  button:hover { background: #4b93ff; }
  button.secondary { background: #30363d; }
  button.secondary:hover { background: #3b434c; }
  .actions { display: flex; gap: 8px; margin: 10px 0; }
  .muted { color: #8b98a6; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px;
           font-size: 12px; border: 1px solid #39424e; color: #b7c2ce; }
  .badge.running { border-color: #9e6a03; color: #f0b429; }
  .badge.done { border-color: #1f6f3f; color: #4ac26b; }
  .badge.failed, .badge.cancelled { border-color: #7d2a2a; color: #ff7b72; }
  .verdict { border-left: 4px solid #8b98a6; padding: 10px 12px; margin: 8px 0;
             background: #11161c; border-radius: 0 6px 6px 0; }
  .verdict.critical { border-color: #ff6b6b; }
  .verdict.warning { border-color: #f0b429; }
  .verdict.attention { border-color: #d29922; }
  .verdict.ok { border-color: #4ac26b; }
  .verdict .chips { margin-top: 6px; color: #8b98a6; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #222b35;
           vertical-align: top; }
  th { color: #8b98a6; font-weight: 500; font-size: 12px; }
  .sev-critical { color: #ff6b6b; font-weight: 600; }
  .sev-high { color: #f0883e; font-weight: 600; }
  .sev-medium { color: #d29922; }
  .sev-low { color: #9aa7b5; }
  pre { background: #0b0f14; border: 1px solid #222b35; border-radius: 6px;
        padding: 10px; max-height: 360px; overflow: auto; white-space: pre-wrap;
        word-break: break-word; font: 12.5px/1.5 ui-monospace, SFMono-Regular,
        Menlo, Consolas, monospace; }
  .links { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 10px; }
  .links a { color: #58a6ff; text-decoration: none; }
  .links a:hover { text-decoration: underline; }
  .error { color: #ff7b72; white-space: pre-wrap; }
  #jobs tr { border-bottom: 1px solid #222b35; }
  #jobs tr:hover td { background: #11161c; }
  .hint { color: #8b98a6; font-size: 12px; }
  @media (max-width: 720px) { .row { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>dmesg-agent web</h1>
  <span class="sub">offline log / package diagnosis &middot; reports stay on this machine</span>
</header>
<main>
  <section class="card">
    <h2>Analyze a log</h2>
    <form id="job-form">
      <label for="file">Log or diagnostic package</label>
      <input id="file" type="file" required
             accept=".txt,.log,.gz,.xz,.bz2,.tar,.json,.jsonl">
      <div class="hint">dmesg / kern.log, sosreport tar(.xz), journalctl -o json/export,
        nvidia-bug-report.log.gz</div>
      <label for="issue">Reporter's description (optional, from Jira)</label>
      <textarea id="issue" placeholder="symptoms, when it started, reproduction steps…"></textarea>
      <div class="row">
        <div><label for="host">Host / ticket id</label>
          <input id="host" placeholder="JIRA-1234"></div>
        <div><label for="kernel">Kernel (optional)</label>
          <input id="kernel" placeholder="6.12.11"></div>
        <div><label for="distro">Distro (optional)</label>
          <input id="distro" placeholder="Debian 13"></div>
      </div>
      <div class="actions">
        <button type="submit">Analyze</button>
        <span id="upload-status" class="muted"></span>
      </div>
    </form>
  </section>

  <section class="card" id="current" hidden>
    <h2>Current job <span id="status-badge" class="badge"></span></h2>
    <div id="stage" class="muted"></div>
    <div class="actions">
      <button id="cancel" class="secondary" type="button">Cancel</button>
      <button id="refresh" class="secondary" type="button">Refresh</button>
    </div>
    <pre id="log"></pre>
    <div id="result"></div>
  </section>

  <section class="card">
    <h2>Jobs</h2>
    <table id="jobs"></table>
  </section>
</main>
<script>
const token = new URLSearchParams(location.search).get('token') || '';
const authHeaders = token ? {'X-Auth-Token': token} : {};
const tokenQuery = token ? '?token=' + encodeURIComponent(token) : '';
let currentId = null, pollTimer = null;

const $ = id => document.getElementById(id);
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
async function api(path, opts = {}) {
  const headers = Object.assign({}, authHeaders, opts.headers || {});
  const resp = await fetch(path, Object.assign({}, opts, {headers}));
  if (!resp.ok) {
    let msg = await resp.text();
    try { msg = JSON.parse(msg).error || msg; } catch (e) {}
    throw new Error(msg);
  }
  return resp.json();
}
function setStatus(status) {
  const b = $('status-badge');
  b.textContent = status;
  b.className = 'badge ' + status;
}
function link(box, href, label) {
  const a = el('a', '', label);
  a.href = href; a.target = '_blank'; a.rel = 'noopener';
  box.appendChild(a);
}
function renderJob(j) {
  $('current').hidden = false;
  setStatus(j.status || 'unknown');
  $('stage').textContent = j.stage || '';
  $('log').textContent = j.log || '';
  $('log').scrollTop = $('log').scrollHeight;
  const box = $('result');
  box.replaceChildren();
  if (j.error) box.appendChild(el('p', 'error', j.error));
  if (j.verdict) {
    const v = el('div', 'verdict ' + String(j.verdict.health || '').toLowerCase());
    v.appendChild(el('strong', '', j.verdict.health + ' — ' + j.verdict.headline));
    if (j.verdict.chips && j.verdict.chips.length)
      v.appendChild(el('div', 'chips', j.verdict.chips.join(' · ')));
    box.appendChild(v);
  }
  if (j.findings && j.findings.length) {
    const t = el('table');
    const head = el('tr');
    ['Severity', 'Issue', 'Subsystem'].forEach(h => head.appendChild(el('th', '', h)));
    t.appendChild(head);
    j.findings.forEach(f => {
      const tr = el('tr');
      tr.appendChild(el('td', 'sev-' + (f.severity || ''), f.severity || '?'));
      tr.appendChild(el('td', '', f.title || ''));
      tr.appendChild(el('td', '', f.subsystem || '?'));
      t.appendChild(tr);
    });
    box.appendChild(t);
  }
  if (j.verify) box.appendChild(el('p', 'muted',
    'Evidence verified: ' + (j.verify.passed || 0) + '/' + (j.verify.total || 0)));
  const links = el('div', 'links');
  if (j.has_report) link(links, '/api/jobs/' + j.id + '/report.md' + tokenQuery, 'Markdown report');
  if (j.has_html) link(links, '/api/jobs/' + j.id + '/report.html' + tokenQuery, 'HTML report');
  if (j.has_archive) link(links, '/api/jobs/' + j.id + '/archive' + tokenQuery, 'Run archive');
  if (j.id) link(links, '/api/jobs/' + j.id + '/log' + tokenQuery, 'Raw log');
  box.appendChild(links);
}
async function loadJobs() {
  try {
    const {jobs} = await api('/api/jobs');
    const t = $('jobs');
    t.replaceChildren();
    const head = el('tr');
    ['Created', 'Status', 'File', 'Host', 'Health'].forEach(h =>
      head.appendChild(el('th', '', h)));
    t.appendChild(head);
    jobs.forEach(j => {
      const tr = el('tr');
      tr.style.cursor = 'pointer';
      tr.appendChild(el('td', '', j.created || ''));
      tr.appendChild(el('td', '', j.status || ''));
      tr.appendChild(el('td', '', j.filename || ''));
      tr.appendChild(el('td', '', j.host_id || ''));
      tr.appendChild(el('td', '', (j.verdict && j.verdict.health) || ''));
      tr.onclick = () => { currentId = j.id; renderJob(j); poll(); };
      t.appendChild(tr);
    });
  } catch (e) { /* offline or token missing */ }
}
async function poll() {
  if (!currentId) return;
  clearTimeout(pollTimer);
  try {
    const j = await api('/api/jobs/' + currentId);
    renderJob(j);
    if (!['done', 'failed', 'cancelled'].includes(j.status))
      pollTimer = setTimeout(poll, 1500);
    else
      loadJobs();
  } catch (e) {
    $('log').textContent += '\n[web] ' + e.message;
    pollTimer = setTimeout(poll, 3000);
  }
}
$('job-form').addEventListener('submit', async e => {
  e.preventDefault();
  const file = $('file').files[0];
  if (!file) return;
  $('upload-status').textContent = 'creating job…';
  try {
    const meta = {
      filename: file.name,
      issue: $('issue').value,
      host_id: $('host').value || 'web',
      kernel: $('kernel').value,
      distro: $('distro').value
    };
    const {id} = await api('/api/jobs', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(meta)
    });
    $('upload-status').textContent = 'uploading…';
    const up = await fetch('/api/jobs/' + id + '/file', {
      method: 'PUT',
      headers: Object.assign({}, authHeaders, {'Content-Type': 'application/octet-stream'}),
      body: file
    });
    if (!up.ok) throw new Error(await up.text());
    $('upload-status').textContent = 'starting…';
    await api('/api/jobs/' + id + '/start', {method: 'POST'});
    $('upload-status').textContent = '';
    currentId = id;
    $('current').hidden = false;
    poll();
    loadJobs();
  } catch (err) {
    $('upload-status').textContent = 'error: ' + err.message;
  }
});
$('cancel').addEventListener('click', async () => {
  if (!currentId) return;
  try { await api('/api/jobs/' + currentId + '/cancel', {method: 'POST'}); poll(); }
  catch (e) { alert(e.message); }
});
$('refresh').addEventListener('click', poll);
loadJobs();
</script>
</body>
</html>
"""
