# dmesg-agent

A [sashiko](https://sashiko.dev)-style AI diagnosis agent for kernel logs. Feed it a dmesg and the LLM **triages issues into three tiers** (confirmed / open questions / dismissed); for each open question it **automatically collects deeper data and re-verifies it** (prompting for a password when root is needed); every piece of evidence is **matched verbatim** against the raw data to prevent hallucination.

Pipeline (v0.6):

```
collect → triage prefilter → proactive system scan (when the log is quiet) + system-change
        correlation (reboots, kernel/package installs, suspend/resume around the first fault)
        + deterministic prefetch → deterministic facts (rule-extracted) + host case history
        → confirmed-case fast path (skip deep collection when a confirmed case matches)
        → LLM three-tier analysis
        → per inconclusive item: whitelisted playbook collection (sudo prompt) → LLM verdict;
          still inconclusive → follow-up round routed by the stated gap (up to --deep-rounds)
        → verbatim evidence check → verdict-first Markdown / brief / HTML report
        → run archive (full LLM I/O + context, replayable)
```

The report leads with a **verdict box** — system health, the top three issues, a "DO NOW"
action list, and evidence/recurrence chips — before any detail. `--brief` prints only that
plus a findings table; `--html` writes a self-contained, print/PDF-ready report with
severity-colored cards and a timeline. The footer carries the weekly software score.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[ssh]"     # add SSH remote diagnosis support
```

## Usage

### Common commands

```bash
# pre-flight and provider setup
dmesg-agent check
dmesg-agent config providers
dmesg-agent config use local --base-url http://127.0.0.1:8000
dmesg-agent config use deepseek                  # export DEEPSEEK_API_KEY first

# offline analysis (file mode: no live collection)
dmesg-agent --file dmesg.txt --kernel 6.12.11 --distro "Debian 13" -o report.md
dmesg-agent --file sosreport-*.tar.xz --issue jira.txt --host-id JIRA-1234 \
  -o report.md --html report.html
dmesg-agent --file nvidia-bug-report.log.gz --host-id JIRA-1234 -o report.md
dmesg-agent --file journal-export.json -o report.md

# live diagnosis (full pipeline)
sudo dmesg-agent
dmesg-agent --boot previous
dmesg-agent --ssh user@10.0.0.5 --key ~/.ssh/id_ed25519

# web UI (command plugin)
dmesg-agent web --port 8790 --open

# evaluation / maintenance
dmesg-agent eval
dmesg-agent eval --live --provider local
dmesg-agent score --no-tests
dmesg-agent plugins list
dmesg-agent cases list
dmesg-agent learn --mbox lore.mbox --verbose   # ingest community issues (see docs/LEARN.md)
dmesg-agent learn --tracker-query 'nvme timeout' --bugzilla https://bugzilla.kernel.org --launchpad
```

Every command supports `--help`; the complete option and subcommand reference follows the examples.

### More examples

```bash
# 1) Analyze an offline log (no executor: no prefetch, no deep verification)
dmesg-agent --file dmesg.txt --kernel 6.12.11+ --distro "Debian 13" -o report.md
sudo dmesg -T --color=never | dmesg-agent --file -

# 1b) Offline diagnostic packages (auto-detected by name + content)
dmesg-agent --file sosreport-ubuntu-*.tar.xz -o report.md
dmesg-agent --file nvidia-bug-report.log.gz --host-id "$(cat /etc/machine-id)" -o report.md
dmesg-agent --file journal-export.json        # journalctl -o json / -o export

# 1c) Attach the reporter's problem description (Jira body etc.) as context
dmesg-agent --file sosreport-*.tar.xz --issue jira-description.txt -o report.md

# 2) Local machine (full pipeline: prefetch + deep verification; reading dmesg needs root)
sudo .venv/bin/dmesg-agent
dmesg-agent --boot previous

# 3) Remote over SSH (also full pipeline; deep verification uses sudo on the remote)
dmesg-agent --ssh user@10.0.0.5 --key ~/.ssh/id_ed25519
dmesg-agent --ssh user@10.0.0.5 --ssh-password   # password login: prompted (hidden),
                                                 # or set DMESG_AGENT_SSH_PASSWORD
```

Offline packages are unpacked in memory (nothing is extracted to disk) and reduced to a main kernel log (fed to triage) plus extra sources that join the prompt and evidence corpus. sosreport also surfaces the command outputs a live run would collect — `smartctl`, `lsblk`, `ps`, `free`, `df`, `mount`, `systemctl --failed`, `lspci`, `dmidecode`, `ethtool`, `ip addr`, `sysctl`… — so an offline diagnosis still gets prefetch/scan/deep-equivalent data, just read from the tarball instead of run on the host; it also yields kernel version, distro and hostname from `uname`/`os-release`/`hostname`. `journalctl -o json`/`-o export` dumps are rebuilt into plain text with the hostname recovered for the case library. `--issue PATH` injects the reporter's description as context only (never evidence, never instructions).

When deep verification hits a collection command that needs root: it asks for the password via hidden terminal input; with no terminal but a desktop session available it falls back to a `zenity`/`kdialog` password dialog; `--askpass none` disables this (those commands are skipped). The password is kept in process memory only.

Common pipeline switches: `--no-deep`, `--no-prefetch`, `--max-verify N`, `--deep-rounds N`, `--no-triage`, `--json`, `--askpass`, `--max-tokens`; full reference below.

### Complete option reference

Data source (mutually exclusive; neither = collect from the local machine):

| Option | Meaning |
|---|---|
| `--ssh USER@HOST` | collect and diagnose a remote machine over SSH |
| `--file PATH` | analyze an offline log: plain dmesg/kern.log (`.gz`, `-` = stdin), `journalctl -o json`/`-o export`, `nvidia-bug-report.log[.gz]`, or a sosreport tar (`.tar`/`.tar.gz`/`.tar.xz`); no executor → no live scan/prefetch/deep |
| `--issue PATH` | reporter's problem description (Jira body etc.), injected as untrusted context (never evidence, never instructions); works with any source |

Collection & authentication:

| Option | Default | Meaning |
|---|---|---|
| `--boot now\|previous` | `now` | which boot's kernel log to collect |
| `--port N` | 22 | SSH port |
| `--user NAME` | — | SSH user when `--ssh` has no `user@` prefix |
| `--key PATH` | — | SSH private key path |
| `--ssh-password` | off | password-based SSH login: prompt hidden (or env `DMESG_AGENT_SSH_PASSWORD`); keys/agent skipped |
| `--askpass auto\|terminal\|gui\|none` | `auto` | how to obtain the sudo password (`none` skips privileged collection) |

Offline-log metadata:

| Option | Meaning |
|---|---|
| `--kernel VER` / `--distro NAME` | what the offline log came from (shown in the report) |

Pipeline switches:

| Option | Meaning |
|---|---|
| `--no-triage` | skip signature prefilter; send the whole log to the model |
| `--no-prefetch` | skip deterministic pre-analysis collection |
| `--scan` | always run the proactive system scan (default: only when triage finds nothing) |
| `--no-scan` | never run the proactive scan |
| `--no-deep` | skip deep verification of open questions |
| `--max-verify N` | cap on deep-verified concerns (default 5) |
| `--deep-rounds N` | max collection rounds per open question (default 2; a second round is routed by the model's stated gap) |
| `--no-knowledge` | do not record this run into the per-host case library (history injection and fast path are skipped too) |
| `--knowledge-db PATH` | case-library SQLite path (or env `DMESG_AGENT_KNOWLEDGE_DB`) |
| `--known-issues-db PATH` | community known-issue store for diagnosis-time recall (or env `DMESG_AGENT_KNOWN_ISSUES_DB`) |
| `--no-known-issues` | skip community known-issue recall in the analysis prompt |
| `--host-id ID` | host identity for the case library (default: machine-id on live/SSH; hostname parsed from journalctl lines for `--file`; the file name is a warned last resort) |
| `--kmatch-threshold F` | similar-case recall threshold (default 0.65) |

Advanced forensics (require an executor; each degrades to a "skipped" note if its tool is missing):

| Option | Meaning |
|---|---|
| `--vmcore PATH` | analyze a kernel crash dump with crash(8) |
| `--vmlinux PATH` | debuginfo for `--vmcore` (or env `DMESG_AGENT_VMLINUX`) |
| `--live-probe` | live kernel forensics via drgn (`/proc/kcore`, root) |
| `--cross-boot N` | previous N boots' error-level kernel logs (recurrence) |
| `--kernel-src PATH` | kernel git tree for call-trace source correlation (or env `DMESG_AGENT_KERNEL_SRC`) |
| `--no-srcmap` | disable source correlation |

LLM backend & output:

| Option | Meaning |
|---|---|
| `--provider NAME` | provider preset: `local`, `vllm`, `ollama`, `deepseek`, `openai`/`gpt`, `anthropic`/`claude`, `gemini`, `openrouter`, `custom` |
| `--base-url URL` / `--model NAME` / `--api-key KEY` | endpoint/model/key overrides on top of the preset |
| `--max-tokens N` | model output ceiling (default 32768; a truncation warning is printed if hit) |
| `-o, --output PATH` | write the Markdown report to a file (default: stdout) |
| `--brief` | verdict box + findings table + next actions only (triage-sized) |
| `--html PATH` | also write a self-contained HTML report (print/PDF-ready) |
| `--color auto\|always\|never` | ANSI colors on stdout (auto: TTY only, respects `NO_COLOR`) |
| `--json` | emit the structured result instead of the report |
| `-v` | stage-by-stage progress (stderr), including live model streaming |
| `--version` | print version |

### Complete subcommand reference

`config` — persistent settings (`~/.config/dmesg-agent/config.json`, mode 0600):

```bash
dmesg-agent config show
dmesg-agent config providers
dmesg-agent config use <provider> [--base-url URL] [--model NAME] [--api-key KEY]
dmesg-agent config set <key> <value>
dmesg-agent config unset <key>
dmesg-agent config check
```

Keys: `provider`, `base_url`, `model`, `api_key`, `api_style`, `chat_path`,
`models_path`, `max_tokens`, `timeout`, `temperature`, `extra_body`.

`check` — pre-flight readiness (exit 1 if not ready):

```bash
dmesg-agent check [--provider NAME] [--base-url URL] [--model NAME] [--api-key KEY]
```

`eval` — known-answer harness:

```bash
dmesg-agent eval [--live] [--provider NAME] [--base-url URL] [--model NAME]
                 [--api-key KEY] [--json] [--min-locate F] [--ab]
```

`cases` — per-host case library (`STATUS` = candidate/confirmed/dismissed/fixed):

```bash
dmesg-agent cases [--db PATH] list [--host H] [--status STATUS] [--limit N]
dmesg-agent cases [--db PATH] show <ID>
dmesg-agent cases [--db PATH] confirm|dismiss|fixed <ID>
```

`score` — weekly software scorecard:

```bash
dmesg-agent score [--record] [--live] [--note TEXT] [--no-tests]
                  [--base-url URL] [--model NAME] [--api-key KEY] [--json]
```

`plugins` — plugin inventory:

```bash
dmesg-agent plugins list
```

`learn` — ingest community issues into the known-issue store (command plugin;
see `docs/LEARN.md`):

```bash
dmesg-agent learn --mbox lore.mbox [--source lore] [--since 2024-01-01]
                  [--limit N] [--loop] [--interval SEC] [--db PATH] [--verbose]
dmesg-agent learn --lore-search 'nvme timeout' [--full-threads]
                  [--max-download-mb 128] [--limit N] [--verbose]
                  [--extract --max-extract 25] [--provider NAME] [--base-url URL]
dmesg-agent learn --tracker-query 'nvme timeout'
                  [--bugzilla BASE]... [--launchpad] [--gitlab PROJECT_URL]...
                  [--tracker-limit 25] [--gitlab-token TOKEN]
dmesg-agent learn --auto [--auto-max-mb 512] [--auto-max-queries N]
                  [--limit N] [--extract --max-extract 25] [--loop]
```

`--lore-search` pulls a search-result mbox directly (POST form) — **no
message-id needed**; broad queries can be large, so the download is capped by
`--max-download-mb`. `--extract` asks the configured LLM to fill
symptom / root_cause / fix / confidence / log_snippets; snippets must be
verbatim and fix pointers (commit / URL / bug number) must appear in the
source, otherwise they are dropped. The stored fix is a lookup pointer, never
comment or patch text.

Disable at startup: `DMESG_AGENT_DISABLE_PLUGINS=<module>,...` (module names,
e.g. `collect_facts,web,learn`).

`web` — local web UI (command plugin; see `docs/WEB.md`):

```bash
dmesg-agent web [--host 127.0.0.1] [--port 8790] [--token TOKEN]
                [--job-root PATH] [--open | --no-open]
```

Non-loopback `--host` auto-generates an access token. Every subcommand
supports `--help`.

Environment variables: `DMESG_AGENT_PROVIDER`, `DMESG_AGENT_BASE_URL`, `DMESG_AGENT_MODEL`, `DMESG_AGENT_API_KEY`, `DMESG_AGENT_EXTRA_BODY` (JSON object merged into the request body), `DMESG_AGENT_DISABLE_PLUGINS` (comma-separated plugin module names), `OPENAI_BASE_URL`, `OPENAI_MODEL`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` (fallback), `ANTHROPIC_BASE_URL` (Anthropic provider only), `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `OPENROUTER_API_KEY`, `DMESG_AGENT_SSH_PASSWORD`, `DMESG_AGENT_KERNEL_SRC`, `DMESG_AGENT_VMLINUX`, `DMESG_AGENT_KNOWLEDGE_DB`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` (case library/archive; falls back to `XDG_STATE_HOME`, cache, then a per-UID temp dir when unwritable), `XDG_STATE_HOME`, `NO_COLOR`. Config precedence everywhere: CLI flag > env var > config file > provider preset > default.

Always on, no flag: model output streams live to stderr; confirmed findings are fingerprinted into the per-host case library and re-appear as "🔁 Recurrence" annotations; the host's prior cases and last run summary are injected into the prompt as non-evidence context; every run is archived under `$XDG_DATA_HOME/dmesg-agent/runs/` (gzip JSON, mode 0600, newest 200 kept) with the full LLM request/response exchanges, triage blocks, collected context and final result — the replay/audit trail that makes a diagnosis debuggable.

If the preferred data directory is not writable (a classic cause: an earlier `sudo dmesg-agent` left `~/.local/share/dmesg-agent` owned by root), the case library and archive fall back to `$XDG_STATE_HOME`, `$XDG_CACHE_HOME`, then a per-UID temp directory, with a warning and the exact `chown` fix. A run that fails at the LLM step still writes an archive containing the collected data and the error, so the failure itself is replayable.

### Case library (shadow mode)

Every confirmed finding is reduced to a **structural fingerprint** built from its verbatim evidence quotes — matched log-signature classes, device tokens (`sda`, `ata6`, `nvme0n1`), error codes (`SErr`/`Emask`/`errno`) and subsystem routing — with volatile values (timestamps, PIDs, sectors, hex addresses) normalized away. Findings without evidence fall back to the original content-word fingerprint. State lives in SQLite at `~/.local/share/dmesg-agent/knowledge.db` (0600), per host.

```bash
dmesg-agent cases list                  # id, status, occurrences, last seen, title
dmesg-agent cases show 3                # fingerprint core + recent occurrences
dmesg-agent cases confirm 3             # eligible for the future fast path
dmesg-agent cases fixed 3               # a recurrence reopens it (regression flag)
```

Matching is two-tier: an **exact** fingerprint match (same fault on the same host) versus a **similar** case recalled by token-set Jaccard ≥ `--kmatch-threshold` (0.65). Recording stays in shadow mode — it never silently changes a conclusion.

**Fast path**: before the first LLM pass the raw suspicious log is fingerprinted and compared against the host's **confirmed** cases (evidence-kind only, containment ≥ 0.7 with ≥5 shared tokens). On a hit the stored case is injected into the prompt with an instruction to judge only the delta, and deep collection is skipped (one analysis pass still runs so every evidence quote remains verifiable against the current log). The report shows a `fast path · case #N` chip.

**Prior context**: before analysis, `host_history()` reads the host's recent cases and last run summary and injects them as explicitly non-evidence context, so a machine that keeps failing is judged with its own history in view.

### Weekly scorecard

`dmesg-agent check` prints the committed software score. It is computed from deterministic measurements, not model self-assessment, across three weighted dimensions:

- **Architecture (35%)** — module layout, largest-module size, test density, docs/invariants, CI, dependency hygiene, annotation consistency.
- **Accuracy (45%)** — eval-suite category coverage and case count plus the measured detect/evidence/dismissal rates from `evals/run_eval.py`. An offline stub run earns only harness-integrity points; real-model accuracy requires `--live`.
- **Improvement (20%)** — commits, lines, and test/eval-case growth since the previous card, plus a passing pytest run. The commit list is recorded as the "why it improved" basis.

Weekly ritual (maintainer):

```bash
dmesg-agent score --live --record --note "what improved and why"
git add SCORECARD.md dmesg_agent/scorecards/ && git commit -m "scorecard: 2026-W49"
```

The JSON basis (`dmesg_agent/scorecards/<week>.json`) records every metric, per-item points and evidence strings, the eval results, and the commit list; `SCORECARD.md` is regenerated from it. Scoring history starts at **2026-W48 (v0.4.0)** — users installing later inherit that history through `check`, so the score starts from when the software shipped, not from their install date.

### Source correlation (v3)

Given a kernel source tree (git), call traces in the log are resolved to function source **deterministically**:

```bash
export DMESG_AGENT_KERNEL_SRC=/path/to/linux-src   # or --kernel-src
dmesg-agent --file dmesg.txt --kernel-src /works/Linux-debugs/linux-src
```

Flow: extract `func+0x…[module]` symbols → function-definition index (built on first use, cached under `~/.cache/dmesg-agent/`, invalidated when the tree HEAD changes) → function bodies (≤120 lines) plus the file's recent commits → injected into the model context and attached to the report. When the source tree version differs from the running kernel, the report notes that "function bodies may be offset".

**Known-fix candidates**: for each correlated file the module also lists recent commits whose subject mentions a fix, with the first release tag that contains each commit (`git describe --contains`) and a version comparison against the running kernel — "already upstream as of vX" versus "NOT in the running kernel; candidate for upgrade/backport (check the distro changelog)". This is deliberately labeled a *candidate*: the report never claims a commit is the root-cause fix without human confirmation, and distro backports can change the picture.

### Result presentation

- **Verdict-first**: the Markdown report opens with a boxed `HEALTH:` line, the top three issues, a `DO NOW` action list (de-duplicated next steps from the most severe findings) and evidence/recurrence chips, before any detail.
- `--brief` prints only the verdict box, a findings table and the open questions — suitable for chat/paste.
- `--html PATH` writes one self-contained file (inline CSS, no scripts, everything escaped): severity-colored cards, verbatim evidence tables, a timeline of suspect segments, collapsible appendices, print/PDF friendly.
- `--color auto|always|never` colorizes stdout (auto = TTY only; honors `NO_COLOR`).
- When the case library knows the host's previous run, the report and verdict show **"Since the previous run: +N new / -M resolved / K ongoing"**.
- A **deterministic-facts appendix** lists rule-extracted facts (OOM victims, hung tasks, per-device I/O/fs error counts, NVRM allocation failures, SMART attributes, failed units, full disks, load/memory) — extracted without the model and injected into the prompt as facts the model must not contradict.
- The footer records the tool version and the committed weekly software score.

### System-change correlation

Whenever an executor is available the agent records recent **system changes**: boots (`last -x`, `uptime -s`), the running kernel's install time, package install/upgrade history, and — when the log carries absolute timestamps — the non-kernel journal window (± around the first suspicious segment). A sudden fault that follows a kernel/package change or a suspend/resume becomes a checkable causal link instead of a guess. All commands are read-only and declared in code; nothing model- or log-provided is executed. The data joins the prompt/evidence corpus and lands in the report appendix.

## Beyond the kernel log

dmesg alone misses problems that never print a line — failed systemd units,
userspace crashes, full disks, resource pressure, broken packages, bad network
config. When a local/SSH executor is available the agent proactively runs a
**whitelisted system scan** (`systemscan.py`) whenever triage finds nothing
suspicious; force it with `--scan`, suppress it with `--no-scan`.

```bash
dmesg-agent --scan                       # always scan, even when the log has signals
dmesg-agent --vmcore /var/crash/vmcore.2 --vmlinux /work/vmlinux   # post-mortem via crash(8)
dmesg-agent --live-probe                 # live kernel forensics via drgn (D-state tasks, /proc/kcore)
dmesg-agent --cross-boot 2               # error logs of the previous 2 boots (recurrence check)
```

Every confirmed finding is additionally fingerprinted into the **case library** (see above): the same fault (exact structural fingerprint, or Jaccard ≥ 0.5 content overlap for evidence-less findings) is counted across runs per host and reported as "🔁 Recurrence: seen N times" plus a "🗂 Case #id" annotation — no LLM tokens spent on the comparison. All four feed their output into the same prompt + evidence corpus (quoted data
is verbatim-verified like log lines), attach as a report appendix, and degrade
to a one-line "skipped: <reason>" entry when crash/drgn/root/vmlinux are
missing. `--vmlinux` also reads `DMESG_AGENT_VMLINUX`. The crash batch is a
fixed read-only script (`log/sys/bt/ps/mod/net/mount/dev`) — never interactive
commands, never model-chosen ones. New subsystems (service / userspace /
disk-space / package / net-config / performance) route through the same
prefetch/deep playbooks, and triage learned their signatures
(`Failed to start`, `core dumped`, `No space left`, …).

## Evaluation harness

`evals/` measures pipeline quality the way sashiko/syzkaller are measured:
known-answer cases scored automatically.

```bash
dmesg-agent eval                    # offline self-test (stub client; also runs under pytest)
dmesg-agent eval --live --provider deepseek   # real endpoint via a provider preset
dmesg-agent eval --live --min-locate 0.8      # fail below 80% detect
dmesg-agent eval --live --json                 # machine-readable metrics
python evals/run_eval.py ...        # the same harness directly (git checkout only)
```

The subcommand loads `evals/run_eval.py` from the checkout next to the
package — same binary, dev-only entry, like `sashiko benchmark`. In an
installed wheel without the checkout it reports the harness is absent.

A case = `evals/cases/<name>/{log.txt, expected.json}` (expected subsystem,
severity, keywords; optional `must_not_dismiss`, `expected_count`). Scoring
follows the sashiko benchmark's three-state protocol: every case is
**DETECTED** (confirmed finding, right tier/severity, all quotes verbatim),
**PARTIAL** (spotted but parked in inconclusive, or wrong severity, or a
fabricated quote) or **MISSED**; plus `noise_rate` = findings emitted per
expected bug (sashiko's findings/patch signal-to-noise, adapted). Metrics:
`detected_rate / partial_rate / missed_rate / detect_rate / evidence_rate /
dismissal_rate / noise_rate`. Add a case by dropping in a log whose root
cause you know plus its expected.json — the offline pytest guard
(`tests/test_eval.py`) keeps the harness honest.

The suite includes real captured logs (e.g. the `nvidia-nvrm-oom` and
`xhci-unknown-stream` cases come from a thinkstationpgx running
`7.0.0-1025-nvidia`) alongside the smaller known-answer fixtures.

## LLM backend

Any OpenAI-compatible API, plus a native Anthropic Messages client. Default
`http://192.168.8.43:19527`; override per run with `--provider`, `--base-url`,
`--model`, `--api-key`, or persist a preset.

```bash
dmesg-agent config providers                 # list presets, URLs, default models, key envs

# local vLLM / LM Studio / llama.cpp (OpenAI-compatible)
dmesg-agent config use local --base-url http://192.168.1.70:8080
dmesg-agent config use ollama               # http://127.0.0.1:11434
dmesg-agent config use vllm                 # http://127.0.0.1:8000

# hosted providers: the API key comes from the documented env var
export DEEPSEEK_API_KEY=...                 # config use deepseek (deepseek-chat)
export OPENAI_API_KEY=...                   # config use openai  / gpt
export ANTHROPIC_API_KEY=...                # config use anthropic / claude (native Messages API)
export GEMINI_API_KEY=...                   # config use gemini (OpenAI-compatible endpoint)
export OPENROUTER_API_KEY=...               # config use openrouter
dmesg-agent config use deepseek
dmesg-agent check                           # resolve provider/model, probe the endpoint
dmesg-agent check --provider local --base-url http://127.0.0.1:8000  # one-off probe

# provider-specific escape hatch: disable Qwen3 thinking on vLLM/Strata
dmesg-agent config set extra_body '{"chat_template_kwargs":{"enable_thinking":false}}'
# or one-off: DMESG_AGENT_EXTRA_BODY='{"reasoning_effort":"none"}' dmesg-agent ...
```

`config use` writes the provider, base URL, model and auth style into
`~/.config/dmesg-agent/config.json` (mode 0600). A model left unset is
auto-discovered from the server's models endpoint, preferring chat models over
embedding/audio ones. One-off overrides: `dmesg-agent --provider deepseek
--model deepseek-reasoner ...`. Generic automation env vars:
`DMESG_AGENT_PROVIDER`, `DMESG_AGENT_BASE_URL`, `DMESG_AGENT_MODEL`,
`DMESG_AGENT_API_KEY`.

```bash
dmesg-agent config show                      # saved settings + effective provider/style/key source
dmesg-agent config set temperature 0.2       # low-level setters (provider/base_url/model/api_key/...)
dmesg-agent config unset api_key
dmesg-agent check                            # ready or not, with the exact missing piece
```

The native Anthropic path uses `x-api-key` + `anthropic-version` and
`/v1/messages`; the OpenAI-compatible path uses `/chat/completions` with
`max_tokens` or `max_completion_tokens` per provider. On a 400 that rejects
`temperature` or the token field, the client retries once with the unsupported
field removed. Effective precedence: CLI flag > operation-specific env >
`DMESG_AGENT_*` > provider key env > config file > provider preset > built-in
default.

## Design (engineering ideas borrowed from sashiko)

- **Three-tier routing**: the model must split its judgments into `findings` (sufficient evidence) / `inconclusive_concerns` (with a `verification_question` stating what data is still missing) / `dismissed_concerns` (must give a verbatim counter-quote; no dismissal without evidence)
- **prefetch**: before the first analysis, system state is collected **deterministically** based on the signatures triage matched (no sudo, capped at 20K characters), removing blind model guessing
- **deep verification**: for each open question, specialized data (SMART, NIC error counters, historical journal, hwmon, …) is collected via the subsystem's **declarative whitelist playbook** (`playbooks.py`), and the model renders a final confirmed/dismissed/inconclusive verdict from the new data; `--max-verify` caps the total, and an inconclusive verdict triggers a follow-up round routed by the model's stated gap (bounded by `--deep-rounds`, commands already run are excluded)
- **deterministic facts before the model**: rule-based extraction (`facts.py`) of OOM victims, hung tasks, per-device I/O/fs errors, NVRM allocation failures, SMART attributes, failed units, full disks, load/memory — injected as authoritative facts and rendered as an appendix; the model is told not to contradict them
- **fast path for confirmed cases**: raw-log structural fingerprint vs. the host's confirmed cases; a hit skips deep collection and asks the model to judge only the delta, while still verifying every quote against the current log
- **the model cannot run commands**: any "command suggestion" from the log or the model is never executed — only the playbook whitelist runs (log-injection defense)
- **feedback retry**: when the JSON is invalid or an evidence reference cannot be found, the precise violation list is fed back to the model for one retry (with a budget; no infinite loop)
- **anti-hallucination verify**: every evidence quote is compared verbatim (after normalization) against the corpus (original log + collected output); line-number offsets are auto-corrected and the pass rate is written into the report header
- when the model returns no valid JSON: strip fences, slice braces, repair truncation — if all fail, present the raw output (exit code 4)

## Plugin architecture

The core is a dispatcher; features are plugins under `dmesg_agent/plugins/`
(seven hook kinds: source, collect, context, deep, post, render, command).
Removing a plugin file — or disabling one — removes that enhancement without
breaking the core report; evidence verification and the command whitelist stay
in the core. The `command` hook is how `dmesg-agent web` and `dmesg-agent learn`
are provided.

```bash
dmesg-agent plugins list                                   # what is loaded, where
DMESG_AGENT_DISABLE_PLUGINS=collect_facts dmesg-agent ...  # one-off disable (module names)
```

`docs/PLUGINS.md` has the hook contracts, the degradation matrix and the
step-by-step "add a plugin without touching the core" guide.

## Web UI (plugin)

```bash
dmesg-agent check
dmesg-agent web --port 8790 --open
```

Upload a log/package plus the reporter's description; the CLI runs as a
background job (offline pipeline), and the page shows stage/log progress,
the verdict/findings, evidence verification, and downloads for Markdown, HTML
and the run archive. Cancel is graceful (SIGINT). History survives a server
restart. No extra dependencies; binds to 127.0.0.1 by default, and a
non-loopback bind auto-generates an access token.

Options: `--open` opens a browser (default), `--no-open` for headless servers,
`--host 0.0.0.0` to listen remotely (token auto-generated), `--token` to set
one, `--job-root PATH` to relocate job storage, `--port N` (0 = auto). See
`docs/WEB.md` for the HTTP API and security notes.

It is a `command` plugin: `DMESG_AGENT_DISABLE_PLUGINS=web` (or deleting
`dmesg_agent/plugins/web/`) removes it without touching the CLI.

## Known-issue store (plugin)

`dmesg-agent learn` ingests community issues (lore mbox, plus public Bugzilla /
Launchpad / GitLab REST sources) into a small **three-level index** —
subsystem (L1) → fault class (L2) → structural fingerprint (L3) — built with
the *same* `triage`/`playbooks`/`knowledge` rules that classify a live dmesg.
Only the index + a one-line summary + an external URL are stored (~0.6 KB/
record); duplicate sources merge by fingerprint.

```bash
# bulk: one search, no message-id needed (POST form under the hood)
dmesg-agent learn --lore-search 'nvme timeout' --limit 1000 --verbose
dmesg-agent learn --lore-search 'NV_ERR_NO_MEMORY' --full-threads --max-download-mb 64

# LLM extraction (stage 2): fill root_cause / fix / log_snippets
dmesg-agent learn --lore-search 'nvmet-tcp TLS handshake timeout' \
  --extract --max-extract 25 --verbose

# local mbox / thread mbox
dmesg-agent learn --mbox lore.mbox.gz --verbose
dmesg-agent learn --mbox lore.mbox.gz --since 2024-01-01 --limit 1000
dmesg-agent learn --mbox lore.mbox.gz --loop --interval 3600   # continuous update

# stage 3: public bug-tracker REST adapters (kernel.org + Fedora share the
# Bugzilla API; Launchpad and GitLab use their own)
dmesg-agent learn --tracker-query 'nvme timeout' \
  --bugzilla https://bugzilla.kernel.org \
  --bugzilla https://bugzilla.redhat.com \
  --launchpad \
  --gitlab https://gitlab.gnome.org/GNOME/mutter \
  --tracker-limit 25

# automatic catalog: targeted lore + Bugzilla queries for the common fault
# classes (storage/memory/gpu/network/usb/firmware/hardware/locking)
dmesg-agent learn --auto --auto-max-mb 512
dmesg-agent learn --auto --extract --max-extract 200   # fill root cause/fix
dmesg-agent learn --auto --loop --interval 86400       # keep it current
```

`.mbox.gz` is supported; HTML pages are rejected with a clear error. Ingest
drops release announcements, stable-review cover letters (000/816), Yocto/OE
version bumps, GIT PULL/ANNOUNCE/CVE digests, and pure discussion with only a
generic signature. Patch-series versions (v1/v2/v3 + `Re:`) and cross-source
duplicates merge into one record with multiple URLs. See `docs/LEARN.md`.

**Diagnosis-time recall** (stage 4): the `known_issues` context plugin
classifies the selected log blocks with the same rules, ranks matches (exact
fingerprint > same fault class > same subsystem > token similarity) and
injects up to four records into the analysis prompt, explicitly marked as
external reports — never as evidence. Select a store with
`--known-issues-db` / `DMESG_AGENT_KNOWN_ISSUES_DB`; disable with
`--no-known-issues`. The report's **Appendix: community known-issue recall**
lists every injected match (match reason, source segment, upstream link) and
the model's `known_issue_usage` verdict (applied / considered / rejected);
zero matches — or a missing store — are stated explicitly, so you can tell
whether the community store influenced a diagnosis.

`learn --auto` walks the built-in catalog (`dmesg_agent/ingest_catalog.py`)
instead of requiring per-topic commands: one targeted lore query per common
fault class/subsystem plus kernel.org Bugzilla queries, under a global
download budget (`--auto-max-mb`). Lore queries are split into per-year
windows (`--auto-since-year`, default 2018, newest first), so broad topics
are covered without exceeding a single-download cap. Bugzilla issues keep the
bug id + URL as their fix pointer; only the reporter's first comment is read
(transiently, never stored). Repeated or `--loop` runs dedupe by source
id/fingerprint and keep extracting pending records, so coverage and compact
fix pointers accumulate.

The same catalog runs on a schedule in GitHub Actions
(`.github/workflows/known-issues.yml`); the rebuilt SQLite store is uploaded
as a workflow artifact for local use with `--known-issues-db`. CI has no LLM
credentials, so its artifact carries the issue/fingerprint index; run
`learn --auto --extract` locally to fill root causes and compact fix pointers.

## Development

```bash
.venv/bin/python -m pytest tests/ -q
```

CI runs on every push/PR (pytest on Python 3.10/3.12/3.13, offline `dmesg-agent eval`, CLI smoke, sdist/wheel build). Releases: bump `dmesg_agent/__version__` (the single version source — `pyproject.toml` reads it dynamically), tag the commit `vX.Y.Z` and push the tag — the Release workflow guards tag==version, runs tests+eval, and publishes a GitHub Release with the sdist/wheel (PyPI Trusted Publishing is pre-wired but commented until pypi.org is configured).

## Research notes (local projects and external tools)

**Local (evaluated, not auto-integrated)**:
- `/works/Develop/AI/KernelDebugger` (funchook-style kernel inline-hook framework): prototype-grade, rewrites kernel code segments, crash risk, narrow kernel-version window. Only suitable as an "assumption verifier" inside an **isolated reproduction VM** (LLM generates a hook template → load → value-bearing log flows back to this tool); not for the production playbook.
- `/works/Develop/AI/kprobe_inspect` (instruction-level kprobe batch-registration scaffolding): no LICENSE/module_init, several error-path bugs; positioned as a manual kernel-developer debugging tool, does not fit the "whitelisted command collection" model — not integrated.

**External (already borrowed from)**: syzkaller `pkg/report` (triage signature expansion), sashiko `designs/` (prefetch / guardrails / three-tier routing / feedback retry).
**External (future candidates)**: drgn (live kernel data-structure forensics, requires install), bpftrace/perf-tools (dynamic probes, requires install), crash + mcp-crash (vmcore branch), intel/linux-kernel-oops (What/How/Where protocol), live-kbench (syzbot regression eval set), semcode/LKML lore search (known-fix queries, requires network), hotkdump debuginfod (automatic vmlinux fetch — requires building vmlinux with `make` first to hook up `scripts/faddr2line`).

## Known limitations / future directions

- local mode cannot read dmesg without root (use `sudo dmesg | dmesg-agent --file -`)
- `--file` offline mode has no executor: no scan/prefetch/deep verification — only the proactive scan, vmcore, drgn probe and cross-boot require a live or SSH target
- vmcore analysis needs the crash utility + a matching vmlinux on hand; the agent never fetches debuginfo itself
- the proactive scan is a fixed whitelist snapshot, not continuous monitoring; multi-turn follow-up Q&A is not implemented
- the case library records confirmed findings only (inconclusive/dismissed signals are not stored yet); matching is per host, and the confirmed-case fast path is not enabled — the library runs in shadow mode
- the weekly score is a maintainer-recorded artifact; without `--live` the accuracy dimension reflects only the offline harness (the missing live accuracy is shown explicitly in the basis)
- small local models occasionally quote a line number off by 1; verify already auto-corrects and flags it
