# Plugin architecture

The pipeline is a **dispatcher**; features are **plugins**. A plugin can be
removed (delete its file) or disabled (`DMESG_AGENT_DISABLE_PLUGINS`) and the
core still produces a report with one fewer enhancement. This document is the
contract for adding or removing one.

## Core (stable; the tool stops being this tool without it)

- `cli.py` — argument parsing and the plugin dispatcher
- `triage.py` — suspect-segment prefilter (`--no-triage` turns it off)
- `analyze.py` — the three-tier JSON contract and feedback retry
- `verify.py` — **mandatory** verbatim evidence verification
- `report.py` — verdict-first Markdown (the default renderer)
- `llm.py` / `config.py` / `providers.py` — model transport and configuration
- `collectors/base.py` + `collectors/filelog.py` — live local/SSH collection and
  plain-text file input
- `executors.py` / `playbooks.py` security boundary primitives
- `plugins/__init__.py` — registry, `RunContext`, discovery

## Hooks

Every plugin function carries `@register(kind, ...)` from
`dmesg_agent.plugins`. All hooks are optional.

| kind | signature | contract |
|---|---|---|
| `source` | `fn(ctx) -> bool` | claim the input and set `ctx.bundle` (and optional `ctx.offline_sources`); `False` = not mine |
| `collect` | `fn(ctx) -> None` | gather evidence before the LLM; merge into `ctx.scan_text`/`ctx.scan_lines`/`ctx.prefetch_text`/`ctx.facts*` |
| `context` | `fn(ctx) -> None` | inject prompt context (`ctx.issue_text`, `ctx.history_text`, `ctx.known_issues_text`, `ctx.known_cases`) |
| `deep` | `fn(ctx) -> None` | per-concern collection + verdict after the first pass; set `ctx.result`/`ctx.corpus`/`ctx.deep_used` |
| `post` | `fn(ctx) -> None` | result post-processing (`ctx.result["knowledge"]`, `ctx.archive_path`) |
| `render` | `fn(ctx) -> str \| None` | alternate output; named `brief` / `html` |
| `command` | `fn(argv) -> int` | register a CLI subcommand (e.g. `dmesg-agent web`); argv is everything after the command name |

Collect and context hooks run in ascending `order`. Source/depth/render use the
first matching plugin; a command plugin is selected by `argv[0]`, with built-in
subcommands (`config`, `check`, `eval`, `cases`, `score`, `plugins`) taking
priority. Runtime isolation: a plugin raising `CollectError` aborts the run with
exit 2 (a real data/input error); **any other exception is caught per plugin**,
printed as “plugin <name> failed (…); continuing”, and the stage is skipped. A
broken plugin degrades the report, never the core. Command plugins own their
process; errors there are theirs (the CLI gives a clear “unknown command” when a
command plugin is disabled/missing).

## The shared context

`RunContext` (defined in `dmesg_agent/plugins/__init__.py`) is the only state the
core and plugins share: `args`, `argv`, `executor`, `bundle`, `lines`, `blocks`,
assembled prompt texts, `client`, `result`, `corpus`, `summary`, `host`,
`run_uuid`, etc. Plugins must not import `cli.py` (circular import) — import the
core module they need.

## Adding a plugin

1. Create `dmesg_agent/plugins/<kind>_<name>.py`.
2. Register one function:

```python
from ..prompts import render_scan
from . import register
from ._util import add_scan_evidence

@register("collect", order=25, description="what it adds and when it runs")
def my_collector(ctx) -> None:
    if ctx.executor is None or not ctx.args.my_flag:
        return
    add_scan_evidence(ctx, run_my_thing(ctx.executor), render_scan)
```

3. Add a test under `tests/` and run `pytest tests/ -q`.
4. `dmesg-agent plugins list` must show it; the CLI needs **no change**.

A command plugin looks the same but owns a subcommand:

```python
@register("command", order=10, description="my subcommand")
def mycmd(argv: list[str]) -> int:
    args = my_parser().parse_args(argv)   # your own argparse
    ...
    return 0
```

`dmesg-agent mycmd ...` dispatches to it; built-in subcommands win on name
clashes. `plugins/web/` is the reference implementation.

Helpers live in `plugins/_util.py` (underscore-prefixed modules are not
discovered). List plugins with `dmesg-agent plugins list`.

## Removing / disabling

- Delete the module file, or
- `DMESG_AGENT_DISABLE_PLUGINS=collect_facts,render_brief` (module names, i.e.
  without the `dmesg_agent.plugins.` prefix).

The core degrades explicitly and visibly:

| missing plugin | behavior |
|---|---|
| `source_offline_packages` | a tar input fails with “no source plugin claimed it”; plain/log files still work |
| `collect_offline_sources` | package extra files are ignored (warning if present) |
| `collect_*` | `--scan`/`--vmcore`/`--live-probe`/`--cross-boot`/`--kernel-src` print “plugin not installed; ignoring” |
| `context_issue` | `--issue` warns and is ignored |
| `context_history` | no prior-case context, no fast path (deep runs normally) |
| `context_known_issues` | no community known-issue recall; diagnosis is unchanged otherwise |
| `deep` | open questions stay open; a note is logged |
| `post_knowledge` | no case library update |
| `post_archive` | no run archive |
| `render_brief` / `render_html` | `--brief` falls back to the full Markdown report; `--html` warns and is skipped |
| `web` (command) | `dmesg-agent web` reports “unknown command … plugin disabled or missing”; the CLI is unchanged |

`tests/test_plugins.py::test_core_runs_with_empty_registry` proves the core
still emits a report when the registry is empty.

## Invariants plugins may not break

1. **Security boundary**: executable commands stay in `playbooks.py`; a plugin
   may add declarative `CollectCmd`s there, but never run model/log-provided
   commands.
2. **Evidence verification**: `verify.py` runs in the core and cannot be
   bypassed by a plugin.
3. **Data trust**: offline/issue/history text is context, never instructions or
   evidence unless it is the log/collection corpus.
4. **No core imports**: plugins import core modules, never `cli.py`.

## Current inventory

| kind | plugins |
|---|---|
| source | `offline_packages` (sosreport / journal json+export / nvidia-bug-report) |
| collect | `system_scan`, `vmcore`, `live_probe`, `cross_boot`, `prefetch`, `system_changes`, `offline_sources`, `srcmap`, `facts` |
| context | `issue`, `history` |
| deep | `deep` (playbooks, multi-round) |
| post | `knowledge`, `archive` |
| render | `brief`, `html` |
| command | `web` (local HTTP UI; see `docs/WEB.md`) |
