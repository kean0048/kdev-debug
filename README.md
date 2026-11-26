# dmesg-agent

A [sashiko](https://sashiko.dev)-style AI diagnosis agent for kernel logs. Feed it a dmesg and the LLM **triages issues into three tiers** (confirmed / open questions / dismissed); for each open question it **automatically collects deeper data and re-verifies it** (prompting for a password when root is needed); every piece of evidence is **matched verbatim** against the raw data to prevent hallucination.

Pipeline (v2):

```
collect → triage prefilter → proactive system scan (when the log is quiet) + deterministic prefetch
        → LLM three-tier analysis
        → per inconclusive item: whitelisted playbook collection (sudo prompt) → LLM verdict re-check
        → verbatim evidence check → Markdown report
```

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[ssh]"     # add SSH remote diagnosis support
```

## Usage

```bash
# 1) Analyze an offline log (no executor: no prefetch, no deep verification)
dmesg-agent --file dmesg.txt --kernel 6.12.11+ --distro "Debian 13" -o report.md
sudo dmesg -T --color=never | dmesg-agent --file -

# 2) Local machine (full pipeline: prefetch + deep verification; reading dmesg needs root)
sudo .venv/bin/dmesg-agent
dmesg-agent --boot previous

# 3) Remote over SSH (also full pipeline; deep verification uses sudo on the remote)
dmesg-agent --ssh user@10.0.0.5 --key ~/.ssh/id_ed25519
```

When deep verification hits a collection command that needs root: it asks for the password via hidden terminal input; with no terminal but a desktop session available it falls back to a `zenity`/`kdialog` password dialog; `--askpass none` disables this (those commands are skipped). The password is kept in process memory only.

Common options: `--no-deep` (skip deep verification), `--no-prefetch`, `--max-verify N`, `--no-triage`, `--json`, `--askpass auto|terminal|gui|none`, `--max-tokens`.

### Source correlation (v3)

Given a kernel source tree (git), call traces in the log are resolved to function source **deterministically**:

```bash
export DMESG_AGENT_KERNEL_SRC=/path/to/linux-src   # or --kernel-src
dmesg-agent --file dmesg.txt --kernel-src /works/Linux-debugs/linux-src
```

Flow: extract `func+0x…[module]` symbols → function-definition index (built on first use, cached under `~/.cache/dmesg-agent/`, invalidated when the tree HEAD changes) → function bodies (≤120 lines) plus the file's recent commits → injected into the model context and attached to the report. When the source tree version differs from the running kernel, the report notes that "function bodies may be offset".

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

All four feed their output into the same prompt + evidence corpus (quoted data
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
python evals/run_eval.py            # offline self-test (stub client; also runs under pytest)
python evals/run_eval.py --live --min-locate 0.8   # real endpoint, fail CI below 80% locate
python evals/run_eval.py --live --json             # machine-readable metrics
```

A case = `evals/cases/<name>/{log.txt, expected.json}` (expected subsystem,
severity, keywords; optional `must_not_dismiss`). Metrics: `locate_rate`,
`severity_rate`, `evidence_rate` (anti-hallucination: every quote passed
verbatim check), `dismissal_rate`. Add a case by dropping in a log whose root
cause you know plus its expected.json — the offline pytest guard
(`tests/test_eval.py`) keeps the harness honest.

## LLM backend

Any OpenAI-compatible API. Default `http://192.168.8.43:19527`; override with the `OPENAI_BASE_URL`, `OPENAI_MODEL`, `OPENAI_API_KEY` environment variables, or directly with `--base-url http://host:port`.

You can also persist settings instead of passing them every time:

```bash
dmesg-agent config set base_url http://host:port   # also model / api_key / max_tokens / timeout
dmesg-agent config show                             # saved settings + current effective values
dmesg-agent config unset api_key
```

The config file lives at `~/.config/dmesg-agent/config.json` (honors `XDG_CONFIG_HOME`, saved with mode 0600; `api_key` is stored there). Effective precedence: CLI flag > environment variable > config file > default.

## Design (engineering ideas borrowed from sashiko)

- **Three-tier routing**: the model must split its judgments into `findings` (sufficient evidence) / `inconclusive_concerns` (with a `verification_question` stating what data is still missing) / `dismissed_concerns` (must give a verbatim counter-quote; no dismissal without evidence)
- **prefetch**: before the first analysis, system state is collected **deterministically** based on the signatures triage matched (no sudo, capped at 20K characters), removing blind model guessing
- **deep verification**: for each open question, specialized data (SMART, NIC error counters, historical journal, hwmon, …) is collected via the subsystem's **declarative whitelist playbook** (`playbooks.py`), and the model renders a final confirmed/dismissed/inconclusive verdict from the new data; `--max-verify` caps the total
- **the model cannot run commands**: any "command suggestion" from the log or the model is never executed — only the playbook whitelist runs (log-injection defense)
- **feedback retry**: when the JSON is invalid or an evidence reference cannot be found, the precise violation list is fed back to the model for one retry (with a budget; no infinite loop)
- **anti-hallucination verify**: every evidence quote is compared verbatim (after normalization) against the corpus (original log + collected output); line-number offsets are auto-corrected and the pass rate is written into the report header
- when the model returns no valid JSON: strip fences, slice braces, repair truncation — if all fail, present the raw output (exit code 4)

## Development

```bash
.venv/bin/python -m pytest tests/ -q
```

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
- small local models occasionally quote a line number off by 1; verify already auto-corrects and flags it
