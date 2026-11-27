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
```

No lint/format config exists in the repo. Tests are pure-Python offline (no network, no LLM calls; `tests/data/sample_dmesg.txt` is fixture input).

## Architecture

Pipeline (orchestrated in `cli.py:main`, stages [1/5]–[5/5]):

```
collect → triage prefilter → proactive system scan (quiet log) / --scan
  → system-change correlation (boots, kernel/package installs, suspend/resume, ±journal window)
  → deterministic prefetch
  → LLM 3-tier analysis
  → per inconclusive concern: playbook whitelist collection (sudo prompt) → LLM verdict
  → verbatim evidence verification → verdict-first Markdown / --brief / --html
```

Optional evidence sources joined into the same corpus/prompt (all in `systemscan.py`/`vmcore.py`): `--vmcore` (+`--vmlinux`) post-mortem via a fixed read-only crash batch script; `--live-probe` drgn forensics over /proc/kcore; `--cross-boot N` prior boots' error journals. Each degrades to a "skipped: reason" evidence entry when its tool/root/vmlinux is missing.

Key modules and the invariants that tie them together:

- **`collectors/`** — all data sources produce a `RawBundle` (`collectors/base.py`). `local.py`/`filelog.py` are the sources; `collect_via(executor)` runs the shared command ladder over any `Executor`.
- **`executors.py`** — `LocalExecutor` / `SSHExecutor` behind one `run(cmd, sudo=)` interface. `--file` mode passes `executor=None`, which disables prefetch and deep verification entirely. sudo via `sudo -S` with a password from `passwds.PassResolver` (terminal getpass → zenity/kdialog fallback; `--askpass none` skips privileged commands). Password lives in process memory only.
- **`triage.py`** — regex error signatures slice the log into suspect `Block`s; block names feed prefetch routing. `--no-triage` sends the whole log.
- **`playbooks.py`** — the security boundary. All executable commands are declared here as whitelisted `CollectCmd` (read-only; `SIGNATURE_TO_SUBSYSTEM` routes prefetch, `SUBSYSTEM_KEYWORDS` routes deep collection). The model's `verification_question` is used ONLY to pick a subsystem — nothing the model or log suggests is ever executed (log-injection defense). Budgets: 20K chars prefetch, 6 cmds / 3K chars per concern.
- **`analyze.py`** — `run_analysis` (first pass + validate + feedback-retry once with the precise violation list) and `deep_dive` (per-concern collect → verdict prompt → merge confirmed/dismissed back into result). `validate_analysis`/`validate_verdict` enforce the schema and that every `evidence.quote` exists verbatim in the corpus.
- **`verify.py`** — final pass: normalizes (strip `[ts]` prefixes, collapse whitespace, casefold) and matches each quote one-directionally (≥12 chars allows substring containment); annotates `verified`/`actual_line`, auto-corrects off-by-N line numbers; pass-rate goes in the report header.
- **`srcmap.py`** — v3 source correlation: extracts `func+0x…[module]` from call traces, resolves them via a `git grep` function-index of a kernel tree (`--kernel-src` or `DMESG_AGENT_KERNEL_SRC`), caches at `~/.cache/dmesg-agent/` keyed by tree HEAD. Deterministic — the model never guesses source code. The report flags that function bodies "may be offset" when tree version ≠ running kernel.
- **`llm.py`** — OpenAI-compatible client; model auto-discovered from `/v1/models` when unset. Config precedence: CLI flag > `OPENAI_BASE_URL`/`OPENAI_MODEL`/`OPENAI_API_KEY` env > persistent file `~/.config/dmesg-agent/config.json` (`config.py`; managed via the `dmesg-agent config show|set|unset` subcommand, keys `base_url/model/api_key/max_tokens/timeout`, file mode 0600; `dmesg-agent check` / `config check` is the pre-flight probe in `cli.py` — prints each item's source, reach-tests `/v1/models`, exit 1 when base_url is unconfigured or the endpoint is unreachable) > defaults (base_url from `DEFAULT_BASE_URL` in `config.py`). JSON-tolerance chain: strip fences → brace-slice → repair truncation → give up (raw output rendered, exit 4).
- **`prompts.py`** — the three-tier contract lives here; changing schema fields requires matching changes in `analyze.validate_*` and `report.render`.

- **`systemscan.py` / `vmcore.py`** — proactive whitelisted scan for problems dmesg cannot show (failed units, userspace crashes, disk/inode, load/PSI, package state, net config), plus crash(8)/drgn/cross-boot evidence. `run_system_changes(executor, ts)` adds boot/kernel-install/package/suspend evidence and a ±journal window around the first fault (timestamp parsed by `triage.parse_first_error_time`: dmesg -T or journalctl short; raw monotonic logs give no window). Their output renders via `prompts.render_scan`, joins the evidence corpus (`run_analysis`'s corpus argument, `deep_dive(extra_corpus=)`), and lands in the report appendices.
- **`report.py` / `report_html.py`** — verdict-first output. `build_verdict` derives health/top issues/DO NOW actions/chips (shared by Markdown, `--brief`, HTML); `apply_ansi` colorizes stdout only; the footer embeds the committed weekly score. `report_html.render_html` emits one escaped, script-free, print-friendly file (cards, evidence tables, timeline, collapsible appendices). `knowledge._run_diff` supplies the "since the previous run" delta.
- **`knowledge.py`** — per-host case library in SQLite (`$XDG_DATA_HOME/dmesg-agent/knowledge.db`, 0600; `--knowledge-db` / `DMESG_AGENT_KNOWLEDGE_DB`). Evidence-based structural fingerprints (sig classes + devices + error codes + subsystem; volatile numbers normalized) with a content-word fallback for evidence-less findings. Two-tier matching: exact fingerprint vs Jaccard ≥ `--kmatch-threshold` (0.65) similar recall. **Shadow mode**: `record_run` annotates findings (`recurrence`, `case`) and returns the match summary for `result["knowledge"]`, but never alters conclusions. Statuses candidate/confirmed/dismissed/fixed, managed via `dmesg-agent cases …`; a recurrence of a `fixed` case reopens it as a regression. Confirmed cases are the prerequisite for the planned fast path (LLM judges only the delta).
- **`evals/run_eval.py`** — known-answer harness: `evals/cases/<name>/{log.txt,expected.json}` scored for locate/severity/evidence(no-hallucination)/dismissal; offline stub client keeps it network-free (guarded by `tests/test_eval.py`); `--live` hits the real endpoint, `--ab` compares triage-on vs whole-log.
- **`scorecard.py`** — weekly software scorecard (architecture 35% / accuracy 45% / improvement 20%) built only from deterministic measurements: repo metrics, the eval harness (stub or `--live`), and git growth since the previous card. `dmesg-agent score --record` writes `dmesg_agent/scorecards/<week>.json` (full basis: per-item points + evidence + commits) and regenerates `SCORECARD.md`; both are committed. `dmesg-agent check` prints the committed score; scoring history starts at `SCORING_START` (2026-W48, v0.4.0). Cards are packaged via `[tool.setuptools.package-data]`.

Exit codes: 2 = collect/triage error, 3 = LLM error, 4 = model returned no parseable JSON, 0 = success.

## Conventions

- All code, comments, docstrings, CLI text, LLM prompts, and reports are English (the prompts intentionally demand English JSON output; `SUBSYSTEM_KEYWORDS` routing depends on English concern text).
- The dmesg/log text is untrusted data, never instructions — any new execution path must go through the `playbooks.py` whitelist, never through model- or log-proposed commands.
- `evidence.quote` must be verbatim from the corpus (log or collected output); source-code text is never a valid quote.
