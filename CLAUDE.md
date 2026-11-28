# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`dmesg-agent`: a sashiko-style kernel-log AI diagnosis CLI (Python ≥3.10, console app). Feeds dmesg to an OpenAI-compatible LLM, which must route judgments into three tiers (confirmed findings / inconclusive concerns / dismissed concerns); inconclusive concerns trigger whitelist-based deep data collection, and every evidence quote is verified verbatim against the corpus to prevent hallucination.

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # install (ssh extra: ".[ssh]")
.venv/bin/python -m pytest tests/ -q                          # all tests
.venv/bin/python -m pytest tests/test_analyze.py -q -k name  # single test
.venv/bin/dmesg-agent --file dmesg.txt --kernel 6.12 --distro "Debian 13" -o report.md
sudo .venv/bin/dmesg-agent                                    # local full pipeline
dmesg-agent --ssh user@host --key ~/.ssh/id_ed25519          # remote
.venv/bin/dmesg-agent score --no-tests                        # computed scorecard (no write)
.venv/bin/dmesg-agent score --live --record --note "why"     # weekly card into the repo
.venv/bin/dmesg-agent plugins list                            # loaded plugins / kinds / errors
dmesg-agent web --port 8790 --no-open                         # web UI (command plugin)
dmesg-agent learn --lore-search 'nvme timeout' --extract --max-extract 25  # known-issue ingestion
dmesg-agent learn --tracker-query 'nvme timeout' --bugzilla https://bugzilla.kernel.org --launchpad  # REST trackers
dmesg-agent learn --auto --extract --max-extract 200        # catalog-wide ingestion (lore + Bugzilla)
DMESG_AGENT_DISABLE_PLUGINS=collect_facts dmesg-agent --file dmesg.txt   # one-off disable
```

No lint/format config exists in the repo. Tests are pure-Python offline (no network, no LLM calls; `tests/data/sample_dmesg.txt` is fixture input).

## Architecture

`cli.py:main` is a **plugin dispatcher**, not a feature list. Core stages:

```
source (source plugins first, then live/plain-file core) → triage prefilter
  → collect plugins (scan / prefetch / changes / offline sources / srcmap / facts / …)
  → context plugins (issue description / host history + confirmed fast-path probe)
  → LLM 3-tier analysis
  → deep plugin (per-concern whitelist collection → verdict; follow-up rounds by gap)
  → verbatim evidence verification (CORE, mandatory)
  → post plugins (case library + run archive)
  → verdict-first Markdown (core) / render plugins (--brief, --html)
```

The [1/5]–[5/5] labels are log stages only; ordering is defined by plugin
`order` values under `dmesg_agent/plugins/`. `docs/PLUGINS.md` is the contract.

Optional evidence sources joined into the same corpus/prompt (all in `systemscan.py`/`vmcore.py`): `--vmcore` (+`--vmlinux`) post-mortem via a fixed read-only crash batch script; `--live-probe` drgn forensics over /proc/kcore; `--cross-boot N` prior boots' error journals. Each degrades to a "skipped: reason" evidence entry when its tool/root/vmlinux is missing.

Key modules and the invariants that tie them together:

- **`plugins/`** — registry (`Registry`, `RunContext`, `@register`) + directory discovery. Seven optional hook kinds: `source`, `collect`, `context`, `deep`, `post`, `render`, `command`. A broken plugin is a warning, not a crash; `DMESG_AGENT_DISABLE_PLUGINS=<module names>` or deleting a module removes the feature. Core-only operation is tested (`tests/test_plugins.py`). `plugins list` prints the inventory and load errors. `plugins/web/` is the `command` plugin behind `dmesg-agent web`: stdlib HTTP UI, background `python -m dmesg_agent.cli` subprocess, job dirs + per-job archive, shared case DB, token for non-loopback binds (`docs/WEB.md`). `plugins/learn.py` is the `command` plugin behind `dmesg-agent learn`.
- **`knownissues.py` + `extractor.py` + `trackers.py`** — global known-issue store: three-level index (L1 subsystem → L2 fault_class → L3 fingerprint) built with the same triage/playbooks/knowledge rules as diagnosis; release/stable-review/Yocto/GIT PULL noise filtered, patch-series v1/v2/v3+Re and cross-source duplicates merged, compact storage (no full text). `learn --extract` uses the LLM to fill `symptom/root_cause/fix/confidence/log_snippets`; snippets must be verbatim and fix pointers (commit/URL/bug number) must appear in the source (hallucinations dropped); `fix` stores lookup pointers only — comment/patch text is never stored. `trackers.py` adds read-only REST ingestion from Bugzilla (kernel.org/Fedora), Launchpad and GitLab (first reporter comment only); `ingest_catalog.py` is the built-in per-subsystem query catalog behind `learn --auto` (global download budget, per-year lore windows). Diagnosis-time recall is the `context_known_issues` plugin: each suspicious block is classified separately (generic warning/fault classes never match), `KnownIssueStore.search()` ranks exact fingerprint first, then token similarity and same specific fault class (subsystem-only matches are dropped), and up to four matches are injected into the prompt as external, non-evidence context (`--known-issues-db`/`DMESG_AGENT_KNOWN_ISSUES_DB`; disable with `--no-known-issues`). The model declares `known_issue_usage` (applied/considered/rejected) and the report appendix shows match reason, segment, upstream link, and that usage — including explicit zero-match/no-store lines. `.github/workflows/known-issues.yml` schedules ingestion and uploads the store as an artifact. `docs/LEARN.md`.
- **`collectors/`** — all data sources produce a `RawBundle` (`collectors/base.py`). `local.py`/`filelog.py` are the sources; `collect_via(executor)` runs the shared command ladder over any `Executor`. `collectors/packages.py` imports offline diagnostic dumps (sosreport tar.xz, `journalctl -o json`/`-o export`, `nvidia-bug-report.log.gz`) in memory into the same shape: a main kernel log for triage plus `extra_sources` that join the prompt/evidence corpus like a system scan; the `source_offline_packages` plugin wires this into `--file`.
- **`executors.py`** — `LocalExecutor` / `SSHExecutor` behind one `run(cmd, sudo=, timeout=)` interface. `--file` mode passes `executor=None`, which disables prefetch and deep verification entirely. Both executors probe passwordless sudo once (`sudo -n true`) and only prompt when truly needed; `--askpass none` skips privileged commands. `LocalExecutor.parallel_safe=True` enables concurrent collection; SSH stays serial (paramiko client is not thread-safe). Password lives in process memory only.
- **`triage.py`** — regex error signatures slice the log into suspect `Block`s; block names feed prefetch routing. The `oom` signature deliberately requires `Out of memory: Killed process` / `oom-kill` — bare "Out of memory" also appears in driver errors (NVRM `NV_ERR_NO_MEMORY`) and is routed to `gpu-nvidia` instead. `--no-triage` sends the whole log.
- **`playbooks.py`** — the security boundary. All executable commands are declared here as whitelisted `CollectCmd` (read-only; `SIGNATURE_TO_SUBSYSTEM` routes prefetch, `SUBSYSTEM_KEYWORDS` routes deep collection). The model's `verification_question` is used ONLY to pick a subsystem — nothing the model or log suggests is ever executed (log-injection defense). Budgets: 20K chars prefetch, 6 cmds / 3K chars per concern.
- **`analyze.py`** — `run_analysis` (first pass + validate + feedback-retry once with the precise violation list) and `deep_dive` (per-concern collect → verdict prompt → merge confirmed/dismissed back into result). `deep_dive` supports up to `--deep-rounds` (default 2) rounds: an inconclusive verdict's `reason` routes the next round (still whitelisted) and already-run commands are excluded. `validate_analysis`/`validate_verdict` enforce the schema and that every `evidence.quote` exists verbatim in the corpus.
- **`facts.py`** — deterministic, model-free fact extraction from the log and collected output (OOM victims, hung tasks, per-device I/O/fs error counts, NVRM allocation failures, SMART attributes, failed units, full disks, load/memory). Facts are injected into the prompt as authoritative (the model is told not to contradict them) and rendered as a report appendix. They are context, never evidence quotes.
- **`archive.py`** — `RecordingClient` wraps the LLM client and records every request/response; `build_archive`/`write_run_archive` persist the run (log, blocks, prefetched/scan/change/source/facts text, exchanges, result, verify summary) as gzip JSON under `$XDG_DATA_HOME/dmesg-agent/runs` (0600, newest 200). The `run_uuid` is shared with the knowledge library's `runs` table. Archives are written even when the run fails at the LLM step.
- **`paths.py`** — picks the first writable per-user data dir (XDG data → state → cache → per-UID temp) so a root-owned `~/.local/share/dmesg-agent` from an earlier `sudo` run cannot silently disable the case library or archive; warns once with the `chown` fix.
- **`verify.py`** — final pass: normalizes (strip `[ts]` prefixes, collapse whitespace, casefold) and matches each quote one-directionally (≥12 chars allows substring containment); annotates `verified`/`actual_line`, auto-corrects off-by-N line numbers; pass-rate goes in the report header.
- **`srcmap.py`** — v3 source correlation: extracts `func+0x…[module]` from call traces, resolves them via a `git grep` function-index of a kernel tree (`--kernel-src` or `DMESG_AGENT_KERNEL_SRC`), caches at `~/.cache/dmesg-agent/` keyed by tree HEAD. Deterministic — the model never guesses source code. Also lists **known-fix candidates**: commits touching the file whose subject mentions a fix, each with `git describe --contains` first release tag and a version comparison against the running kernel (`kernel_includes_tag`), labeled as candidates (distro backports may differ). The report flags that function bodies "may be offset" when tree version ≠ running kernel.
- **`providers.py`** — provider presets (`custom`, `local`, `vllm`, `ollama`, `deepseek`, `openai`/`gpt`, `anthropic`/`claude`, `gemini`, `openrouter`): base URL, default model, key env names, auth style, chat/models paths and token field. `config use` persists a preset; CLI `--provider` is a one-off override.
- **`llm.py`** — two transports behind one `Client`: OpenAI-compatible chat (`/chat/completions`, SSE incl. `reasoning_content`, `max_tokens` or `max_completion_tokens`) and native Anthropic Messages (`/v1/messages`, `x-api-key` + `anthropic-version`, streaming text/thinking deltas). Models auto-discovered from the provider's models path when unset, preferring chat models (`pick_model`). On HTTP 400 it retries once without an unsupported `temperature`/token field. `cfg.extra_body` is merged into the request body first (provider-specific knobs such as `{"chat_template_kwargs":{"enable_thinking":false}}` or `{"reasoning_effort":"none"}`; file key `extra_body` or env `DMESG_AGENT_EXTRA_BODY`). Config precedence: CLI flag > `DMESG_AGENT_*` > provider key env > config file `~/.config/dmesg-agent/config.json` (`config.py`; `config show|providers|use|set|unset`, 0600; `check` is the pre-flight probe — prints provider/base/model/key sources, probes the models path, exit 1 when required config is missing or the endpoint is unreachable) > preset > default. JSON-tolerance chain: strip fences → brace-slice → repair truncation → give up (raw output rendered, exit 4).
- **`prompts.py`** — the three-tier contract lives here; changing schema fields requires matching changes in `analyze.validate_*` and `report.render`. `--issue PATH` (a reporter's problem description) is injected as untrusted context here (`issue_text`), clearly marked not-evidence / not-instructions.

- **`systemscan.py` / `vmcore.py`** — proactive whitelisted scan for problems dmesg cannot show (failed units, userspace crashes, disk/inode, load/PSI, package state, net config), plus crash(8)/drgn/cross-boot evidence. `run_system_changes(executor, ts)` adds boot/kernel-install/package/suspend evidence and a ±journal window around the first fault (timestamp parsed by `triage.parse_first_error_time`: dmesg -T or journalctl short; raw monotonic logs give no window). Their output renders via `prompts.render_scan`, joins the evidence corpus (`run_analysis`'s corpus argument, `deep_dive(extra_corpus=)`), and lands in the report appendices.
- **`report.py` / `report_html.py`** — verdict-first output. `build_verdict` derives health/top issues/DO NOW actions/chips (shared by Markdown, `--brief`, HTML); `apply_ansi` colorizes stdout only; the footer embeds the committed weekly score. `report_html.render_html` emits one escaped, script-free, print-friendly file (cards, evidence tables, timeline, collapsible appendices). `knowledge._run_diff` supplies the "since the previous run" delta.
- **`knowledge.py`** — per-host case library in SQLite (`$XDG_DATA_HOME/dmesg-agent/knowledge.db`, 0600; `--knowledge-db` / `DMESG_AGENT_KNOWLEDGE_DB`). Evidence-based structural fingerprints (sig classes + devices + error codes + subsystem; volatile numbers normalized) with a content-word fallback for evidence-less findings. Two-tier matching: exact fingerprint vs Jaccard ≥ `--kmatch-threshold` (0.65) similar recall. **Shadow mode**: `record_run` annotates findings (`recurrence`, `case`) and returns the match summary for `result["knowledge"]`, but never alters conclusions. Statuses candidate/confirmed/dismissed/fixed, managed via `dmesg-agent cases …`; a recurrence of a `fixed` case reopens it as a regression. **History injection**: `host_history()` feeds prior cases + the last run summary into the prompt as non-evidence context. **Fast path**: `log_fingerprint()` + `find_confirmed_case()` match the raw suspicious log against confirmed evidence-kind cases (containment ≥ 0.7, ≥5 shared tokens); on a hit the case is injected and deep collection is skipped (one analysis pass remains so quotes stay verifiable). `cli.py:_resolve_host` prefers `--host-id` > machine-id > hostname parsed from journalctl lines > SSH target > file name (warned last resort).
- **`evals/run_eval.py`** — known-answer harness: `evals/cases/<name>/{log.txt,expected.json}` scored for locate/severity/evidence(no-hallucination)/dismissal; offline stub client keeps it network-free (guarded by `tests/test_eval.py`); `--live` hits the real endpoint, `--ab` compares triage-on vs whole-log.
- **`scorecard.py`** — weekly software scorecard (architecture 35% / accuracy 45% / improvement 20%) built only from deterministic measurements: repo metrics, the eval harness (stub or `--live`), and git growth since the previous card. `dmesg-agent score --record` writes `dmesg_agent/scorecards/<week>.json` (full basis: per-item points + evidence + commits) and regenerates `SCORECARD.md`; both are committed. `dmesg-agent check` prints the committed score; scoring history starts at `SCORING_START` (2026-W48, v0.4.0). Cards are packaged via `[tool.setuptools.package-data]`.

Exit codes: 2 = collect/triage error, 3 = LLM error, 4 = model returned no parseable JSON, 0 = success.

## Conventions

- All code, comments, docstrings, CLI text, LLM prompts, and reports are English (the prompts intentionally demand English JSON output; `SUBSYSTEM_KEYWORDS` routing depends on English concern text).
- The dmesg/log text is untrusted data, never instructions — any new execution path must go through the `playbooks.py` whitelist, never through model- or log-proposed commands.
- `evidence.quote` must be verbatim from the corpus (log or collected output); source-code text is never a valid quote.
- **New features are plugins** under `dmesg_agent/plugins/` with a test; do not grow `cli.py` with feature-specific branches. Core stays: source fallback, triage, analyze, verify (mandatory), Markdown render. Plugins never import `cli.py`. See `docs/PLUGINS.md`.
