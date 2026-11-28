"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
from pathlib import Path

from . import __version__
from . import plugins as plugin_framework
from .analyze import run_analysis
from .archive import RecordingClient, new_run_uuid
from .collectors.base import RawBundle, collect_via
from .collectors.filelog import collect_file
from .config import (
    FILE_KEYS,
    config_path,
    load_config,
    read_file_config,
    set_file_config,
    unset_file_config,
    use_provider,
)
from .errors import CollectError
from .executors import Executor, LocalExecutor, SSHExecutor
from .knowledge import DEFAULT_FUZZY, cases_main
from .llm import Client, LLMError, pick_model
from .passwds import PassResolver
from .plugins import RunContext
from .providers import get_provider, provider_choices, provider_table
from .report import apply_ansi, render
from .scorecard import format_for_check, latest_score, score_main
from .triage import Block, find_blocks, render_blocks
from .verify import VerifySummary, verify_result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmesg-agent",
        description="sashiko-style dmesg AI diagnosis agent: three-tier issue triage, "
                    "deep data collection with verification, verbatim-checkable evidence",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--ssh", metavar="USER@HOST", help="collect from a remote machine over SSH")
    src.add_argument("--file", metavar="PATH", help="analyze an offline log: dmesg/kern.log "
                        "(.gz, '-' for stdin), journalctl -o json/export, nvidia-bug-report.log[.gz], "
                        "or a sosreport tarball (.tar/.tar.gz/.tar.xz)")
    p.add_argument("--issue", metavar="PATH", help="a text file with the reporter's problem "
                                                   "description (Jira body, etc.); context only — "
                                                   "never treated as evidence or instructions")
    p.add_argument("--boot", choices=["now", "previous"], default="now", help="which boot's log to collect")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", help="SSH user name (when --ssh has no user@ prefix)")
    p.add_argument("--key", help="path to an SSH private key")
    p.add_argument("--ssh-password", action="store_true",
                   help="authenticate SSH login with a password (prompted, hidden; "
                        "or set DMESG_AGENT_SSH_PASSWORD). Without it, keys/agent are used.")
    p.add_argument("--kernel", default="unknown", help="kernel version the offline log came from")
    p.add_argument("--distro", default="unknown", help="distro the offline log came from")
    p.add_argument("--no-triage", action="store_true", help="skip prefiltering; send the whole log to the model")
    p.add_argument("--no-prefetch", action="store_true", help="skip the initial prefetch collection")
    p.add_argument("--no-deep", action="store_true", help="skip deep verification of open questions")
    p.add_argument("--max-verify", type=int, default=5, help="max open questions to deep-verify (default 5)")
    p.add_argument("--deep-rounds", type=int, default=2, metavar="N",
                   help="max deep-collection rounds per open question (default 2)")
    p.add_argument("--askpass", choices=["auto", "terminal", "gui", "none"], default="auto",
                   help="how to obtain the sudo password (default auto: terminal first, GUI dialog fallback)")
    p.add_argument("-o", "--output", help="write the report to a file (default: stdout)")
    p.add_argument("--brief", action="store_true",
                   help="verdict, findings table and next actions only (triage-sized)")
    p.add_argument("--html", metavar="PATH",
                   help="also write a self-contained HTML report (print/PDF-ready)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="ANSI colors on stdout (default auto: TTY only, respects NO_COLOR)")
    p.add_argument("--json", action="store_true", help="emit structured JSON instead of a Markdown report")
    p.add_argument("--kernel-src", metavar="PATH",
                   help="kernel source tree (git) for call-trace source correlation; "
                        "defaults to the DMESG_AGENT_KERNEL_SRC env var")
    p.add_argument("--no-srcmap", action="store_true", help="disable source correlation")
    p.add_argument("--scan", action="store_true",
                   help="proactive system scan even when the log looks clean (failed units, "
                        "userspace errors, disk/inode, load, package state, network config)")
    p.add_argument("--no-scan", action="store_true",
                   help="never run the proactive system scan (default: scan only when triage finds nothing)")
    p.add_argument("--vmcore", metavar="PATH", help="kernel crash dump (vmcore) to analyze with the crash utility")
    p.add_argument("--vmlinux", help="vmlinux debuginfo for --vmcore (or set DMESG_AGENT_VMLINUX)")
    p.add_argument("--live-probe", action="store_true",
                   help="live kernel data-structure forensics via drgn (/proc/kcore, needs root)")
    p.add_argument("--cross-boot", type=int, default=0, metavar="N",
                   help="correlate error-level kernel logs of the previous N boots (recurrence check)")
    p.add_argument("--no-knowledge", action="store_true",
                   help="do not record this run into the per-host case library")
    p.add_argument("--knowledge-db", metavar="PATH",
                   help="case-library SQLite path (default: $XDG_DATA_HOME/dmesg-agent/knowledge.db, "
                        "or DMESG_AGENT_KNOWLEDGE_DB)")
    p.add_argument("--host-id", metavar="ID",
                   help="host identity for the case library (default: the analyzed machine's "
                        "machine-id; file mode falls back to the log path)")
    p.add_argument("--kmatch-threshold", type=float, default=DEFAULT_FUZZY, metavar="F",
                   help=f"similarity threshold for similar-case recall (default {DEFAULT_FUZZY})")
    p.add_argument("--max-tokens", type=int, help="model output ceiling (default 32768)")
    p.add_argument("--provider", choices=provider_choices(),
                   help="LLM provider preset: local/vllm/ollama, deepseek, openai/gpt, "
                        "anthropic/claude, gemini, openrouter, custom")
    p.add_argument("--model", help="model name (default: auto-discover)")
    p.add_argument("--base-url", help="endpoint base URL (overrides the provider preset)")
    p.add_argument("--api-key", help="API key (or use the provider's env var)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


_INT_KEYS = {"max_tokens", "timeout"}
_FLOAT_KEYS = {"temperature"}


def _build_config_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmesg-agent config",
        description="manage the persistent LLM config file "
                    "(lower precedence than CLI flags and environment variables)",
    )
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("show", help="show saved settings and the effective values")
    sub.add_parser("providers", help="list the built-in provider presets")
    use = sub.add_parser("use", help="quick-setup a provider preset (writes provider, "
                                     "base_url, model and API style)")
    use.add_argument("provider", choices=provider_choices())
    use.add_argument("--base-url", help="override the preset's base URL (required for local)")
    use.add_argument("--model", help="override the preset's default model")
    use.add_argument("--api-key", help="store an API key in the config file (0600); "
                                       "environment variables are recommended")
    sp = sub.add_parser("set", help=f"write a setting ({', '.join(FILE_KEYS)})")
    sp.add_argument("key", choices=list(FILE_KEYS))
    sp.add_argument("value")
    sub.add_parser("unset", help="remove a setting").add_argument("key", choices=list(FILE_KEYS))
    sub.add_parser("check", help="pre-flight readiness check: probe the endpoint and list "
                                 "anything that still needs configuring")
    return p


def _config_main(argv: list[str]) -> int:
    args = _build_config_parser().parse_args(argv)
    if args.action == "check":
        return _check_main()
    if args.action == "providers":
        rows = provider_table()
        print(f"{'PROVIDER':<12} {'BASE URL':<52} {'DEFAULT MODEL':<22} KEY ENV")
        for r in rows:
            print(f"{r['name']:<12} {r['base_url']:<52} {r['default_model']:<22} {r['key_envs']}")
            if r["note"]:
                print(f"{'':<12} {r['note']}")
        print("\nquick setup: dmesg-agent config use <provider> [--base-url URL] "
              "[--model NAME]\nthen verify:  dmesg-agent check")
        return 0
    if args.action == "use":
        preset = get_provider(args.provider)
        old = read_file_config().get("provider")
        try:
            data = use_provider(args.provider, base_url=args.base_url,
                                model=args.model, api_key=args.api_key)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"provider: {preset.name} — {preset.label}")
        print(f"base_url: {data.get('base_url') or preset.base_url or '(not set)'}")
        print(f"model:    {data.get('model') or '(auto-discover)'}")
        print(f"style:    {preset.api_style}  chat_path={preset.chat_path}  "
              f"models_path={preset.models_path}")
        if old and old != preset.name and data.get("api_key") and not args.api_key:
            print("warning: an existing api_key was kept; it may belong to the previous "
                  "provider — unset it with `dmesg-agent config unset api_key`",
                  file=sys.stderr)
        if preset.key_envs and not args.api_key:
            print(f"api key:  set {preset.key_envs[0]} in the environment "
                  f"(recommended) or re-run with --api-key")
        print(f"config file: {config_path()}")
        print("next: dmesg-agent check")
        return 0
    if args.action == "show":
        cfg = load_config()
        saved = read_file_config()
        print(f"config file: {config_path()}")
        if not saved:
            print("  (no settings saved yet; environment variables or defaults are in use)")
        masked = dict(saved)
        if masked.get("api_key"):
            masked["api_key"] = masked["api_key"][:4] + "…" if len(masked["api_key"]) > 4 else "…"
        for k in FILE_KEYS:
            print(f"  {k}: {masked.get(k, '(not set)')}")
        print("effective values:")
        print(f"  provider: {cfg.provider} ({cfg.provider_label})")
        print(f"  base_url: {cfg.base_url or '(not set)'} ({cfg.base_url_source})")
        print(f"  model: {cfg.model or '(auto-discover)'}")
        print(f"  api_key: {'(set via ' + cfg.key_source + ')' if cfg.api_key else '(not set)'}")
        print(f"  api_style: {cfg.api_style}  chat_path={cfg.chat_path}  "
              f"models_path={cfg.models_path}")
        print(f"  max_tokens: {cfg.max_tokens}  timeout: {cfg.timeout}s  "
              f"temperature: {cfg.temperature}")
        return 0
    if args.action == "set":
        value: object = args.value
        if args.key == "provider":
            try:
                data = use_provider(str(value))
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(f"provider = {data.get('provider')} → {config_path()}")
            print("next: dmesg-agent check")
            return 0
        if args.key in _INT_KEYS or args.key in _FLOAT_KEYS:
            try:
                value = (int(args.value) if args.key in _INT_KEYS
                         else float(args.value))
            except ValueError:
                print(f"error: {args.key} requires a number, got {args.value!r}",
                      file=sys.stderr)
                return 2
        elif args.key == "extra_body":
            try:
                value = json.loads(args.value)
            except json.JSONDecodeError as e:
                print(f"error: extra_body must be a JSON object: {e}", file=sys.stderr)
                return 2
            if not isinstance(value, dict):
                print("error: extra_body must be a JSON object", file=sys.stderr)
                return 2
        set_file_config(args.key, value)
        shown = "****" if args.key == "api_key" else value
        print(f"wrote {args.key} = {shown} → {config_path()}")
        return 0
    unset_file_config(args.key)
    print(f"removed {args.key} → {config_path()}")
    return 0


def _check_main(argv: list[str] | None = None, client: Client | None = None) -> int:
    """`dmesg-agent check`: pre-flight readiness probe — print every config item
    with its source, reach-test the endpoint, and list what still needs setting.
    Exit 0 = ready, 1 = not ready.

    ``argv is None`` checks the saved config (used by `config check`); otherwise
    `check --provider/--base-url/--model/--api-key` applies one-off overrides."""
    opts = None
    if argv is not None:
        cp = argparse.ArgumentParser(
            prog="dmesg-agent check",
            description="pre-flight LLM readiness probe (optionally with one-off overrides)")
        cp.add_argument("--provider", choices=provider_choices())
        cp.add_argument("--base-url")
        cp.add_argument("--model")
        cp.add_argument("--api-key")
        opts = cp.parse_args(argv)
    cfg = load_config(
        provider=getattr(opts, "provider", None),
        base_url=getattr(opts, "base_url", None),
        model=getattr(opts, "model", None),
        api_key=getattr(opts, "api_key", None),
    )
    fc = read_file_config()
    problems: list[str] = []

    print("dmesg-agent pre-flight check")
    print(f"config file: {config_path()}")

    print(f"[ok]         provider: {cfg.provider} ({cfg.provider_label}); "
          f"style={cfg.api_style}")
    if cfg.base_url_source not in ("built-in default", "not set") and cfg.base_url:
        print(f"[ok]         base_url: {cfg.base_url} ({cfg.base_url_source})")
    else:
        print(f"[needs set]  base_url: {cfg.base_url or '(empty)'} ({cfg.base_url_source})")
        problems.append("base_url not configured — run `dmesg-agent config use <provider>` "
                        "or set base_url")

    client = client or Client(cfg)
    models: list[str] = []
    try:
        models = client.list_models()
        print(f"[ok]         endpoint: {cfg.models_path} reachable — {len(models)} model(s)")
        if models:
            shown = ", ".join(models[:5]) + (" …" if len(models) > 5 else "")
            print(f"             models: {shown}")
    except LLMError as e:
        print(f"[fail]       endpoint: unreachable — {e}")
        problems.append(f"endpoint unreachable at {cfg.base_url} — check base_url and the network")

    if cfg.model:
        if models and cfg.model not in models:
            print(f"[warn]       model: '{cfg.model}' not found in the server's model list")
        else:
            print(f"[ok]         model: {cfg.model}")
    elif models:
        picked = pick_model(models)
        print(f"[ok]         model: (auto-discover) → '{picked}'")
    else:
        print("[warn]       model: (auto-discover) — cannot confirm until the endpoint is reachable")

    preset = get_provider(cfg.provider)
    if cfg.api_key:
        print(f"[ok]         api_key: set ({cfg.key_source})")
    elif preset.requires_key:
        env_hint = preset.key_envs[0] if preset.key_envs else "the provider's API key env var"
        print(f"[needs set]  api_key: not set for provider {preset.name!r}")
        problems.append(f"set the API key for {preset.name}: export {env_hint}=... "
                        f"or `dmesg-agent config use {preset.name} --api-key <key>`")
    else:
        print("[info]       api_key: not set (fine for unauthenticated local endpoints; "
              "otherwise: dmesg-agent config set api_key <key>)")
    print(f"[ok]         limits: max_tokens={cfg.max_tokens}  timeout={cfg.timeout}s")

    card = latest_score()
    if card:
        print(f"[ok]         {format_for_check(card)}")
    else:
        print("[info]       software score: no weekly scorecard in this build "
              "(record one with `dmesg-agent score --record`)")

    if problems:
        print("\nNOT ready — still needs configuring:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nready: all checks passed")
    return 0


class _Log:
    def __init__(self, verbose: bool):
        self.verbose = verbose

    def __call__(self, stage: str, msg: str) -> None:
        if self.verbose:
            print(f"{stage} {msg}", file=sys.stderr)


class _Streamer:
    """Live model output to stderr (sashiko-style): reasoning is summarized as
    progress ticks, the answer itself is printed as it arrives."""

    def __init__(self, label: str):
        self.label = label
        self.reason_chars = 0
        self.content_started = False
        print(f"  ▶ {label}", file=sys.stderr, flush=True)

    def cb(self, part: tuple[str, str]) -> None:
        kind, txt = part
        if kind == "reasoning":
            before = self.reason_chars // 4000
            self.reason_chars += len(txt)
            if self.reason_chars // 4000 != before:
                print(f"    … thinking ({self.reason_chars} chars)", file=sys.stderr, flush=True)
        else:
            if not self.content_started:
                self.content_started = True
                print("    answer: ", end="", file=sys.stderr, flush=True)
            print(txt, end="", file=sys.stderr, flush=True)

    def finish(self) -> None:
        if self.content_started:
            print(file=sys.stderr, flush=True)


def _make_stream_factory():
    current: list[_Streamer | None] = [None]

    def make(label: str):
        if current[0] is not None:
            current[0].finish()
        current[0] = _Streamer(label)
        return current[0].cb

    return make


def _resolve_host(args, bundle: RawBundle) -> str:
    """Stable case-library identity for this run.

    Priority: explicit --host-id > /etc/machine-id (live/SSH) > hostname parsed
    from journalctl lines (--file) > SSH target > file name (last resort, warned
    about because different machines exporting the same file name would collide).
    """
    if args.host_id:
        return str(args.host_id).strip()[:128]
    ctx = bundle.extra_context or {}
    for key in ("machine_id", "hostname"):
        value = ctx.get(key)
        if value:
            return str(value).strip()[:128]
    if args.ssh:
        return str(args.ssh).strip()[:128]
    if args.file:
        name = Path(args.file).name
        print(f"warning: no stable host identity found in {args.file}; using the file "
              f"name {name!r} for the case library — pass --host-id to keep cases "
              f"from different machines apart", file=sys.stderr)
        return name.strip()[:128]
    return str(bundle.source).strip()[:128]


def _make_executor(args, resolver: PassResolver) -> Executor | None:
    if args.file:
        return None
    if args.ssh:
        if "@" in args.ssh:
            user, host = args.ssh.split("@", 1)
        else:
            user, host = args.user, args.ssh
        if not user:
            raise CollectError("SSH target must be user@host, or pass --user")
        ssh_password = None
        if args.ssh_password:
            import getpass
            ssh_password = os.environ.get("DMESG_AGENT_SSH_PASSWORD")
            if not ssh_password:
                ssh_password = getpass.getpass(f"SSH password for {user}@{host}: ")
        return SSHExecutor(host, user, port=args.port, key_filename=args.key,
                           resolver=resolver, password=ssh_password)
    return LocalExecutor(resolver)


def _eval_main(argv: list[str]) -> int:
    """`dmesg-agent eval ...` → the benchmark harness in evals/run_eval.py
    (sashiko ships `sashiko benchmark` the same way: same binary, dev-only
    subcommand)."""
    runner = Path(__file__).resolve().parent.parent / "evals" / "run_eval.py"
    if not runner.is_file():
        print("error: eval harness not found next to the package "
              "(present in a git checkout; missing in an installed wheel)",
              file=sys.stderr)
        return 2
    import importlib.util
    spec = importlib.util.spec_from_file_location("dmesg_agent_eval", runner)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main(argv)

def _plugins_main(argv: list[str]) -> int:
    """`dmesg-agent plugins list`: show what is loaded (and what failed)."""
    registry = plugin_framework.load_plugins()
    if argv and argv[0] not in ("list", "ls"):
        print("usage: dmesg-agent plugins list", file=sys.stderr)
        return 2
    metas = registry.all_meta()
    current = None
    for meta in metas:
        if meta.kind != current:
            current = meta.kind
            print(f"{meta.kind}:")
        print(f"  {meta.name:<26} order={meta.order:<4} {meta.module}")
        if meta.description:
            print(f"    {meta.description}")
    if not metas:
        print("no plugins loaded")
    disabled = registry.disabled()
    if disabled:
        print(f"\ndisabled via DMESG_AGENT_DISABLE_PLUGINS: {', '.join(sorted(disabled))}")
    if registry.errors:
        print("\nload errors:")
        for err in registry.errors:
            print(f"  - {err}")
    return 0


def _render_markdown(ctx: RunContext) -> str:
    return render(ctx.result, ctx.bundle, ctx.summary, ctx.blocks,
                  raw_text=ctx.answer, prefetch_used=bool(ctx.prefetch_text),
                  deep_used=ctx.deep_used, source_text=ctx.source_text,
                  srcmap_version=ctx.srcmap_version, scan_used=bool(ctx.scan_text),
                  scan_text=ctx.scan_text, changes_text=ctx.changes_text)


def _plugin_name(fn) -> str:
    meta = getattr(fn, "_plugin_meta", None)
    return getattr(meta, "name", getattr(fn, "__name__", "?"))


def _warn_plugin(fn, kind: str, e: Exception) -> None:
    """A plugin bug is a warning, never a core crash."""
    print(f"warning: {kind} plugin {_plugin_name(fn)} failed "
          f"({type(e).__name__}: {e}); continuing", file=sys.stderr)


def _run_cli(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    if argv and argv[0] == "config":
        return _config_main(argv[1:])
    if argv and argv[0] == "check":
        return _check_main(argv[1:])
    if argv and argv[0] == "eval":
        return _eval_main(argv[1:])
    if argv and argv[0] == "cases":
        return cases_main(argv[1:])
    if argv and argv[0] == "score":
        return score_main(argv[1:])
    if argv and argv[0] == "plugins":
        return _plugins_main(argv[1:])

    args = build_parser().parse_args(argv)
    registry = plugin_framework.load_plugins()
    log = _Log(args.verbose)
    resolver = PassResolver(args.askpass)
    ctx = RunContext(args=args, argv=argv, resolver=resolver, log=log)

    # [1/5] data source: optional source plugins, then the core live/plain-file source
    try:
        if args.file:
            for source in registry.get("source"):
                try:
                    if source(ctx):
                        break
                except CollectError:
                    raise
                except Exception as e:
                    _warn_plugin(source, "source", e)
            if ctx.bundle is None:
                if args.file != "-" and tarfile.is_tarfile(args.file):
                    raise CollectError(
                        f"{args.file} is a tarball but no source plugin claimed it; "
                        f"the offline-package plugin (plugins/source_offline_packages.py) "
                        f"is not installed — extract a kernel log or restore that plugin")
                log("[1/5]", f"reading file {args.file}")
                ctx.bundle = collect_file(args.file, kernel=args.kernel,
                                          distro=args.distro)
        else:
            if args.ssh:
                log("[1/5]", f"SSH connect {args.ssh}")
            log("[1/5]", f"collecting (boot={args.boot})")
            ctx.executor = _make_executor(args, resolver)
            ctx.bundle = collect_via(ctx.executor, boot=args.boot)
    except CollectError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    bundle = ctx.bundle
    ctx.lines = bundle.dmesg_text.splitlines()

    # [2/5] triage prefilter (core)
    if args.no_triage:
        ctx.blocks = [Block(start=1, end=len(ctx.lines), names=["whole-log"])]
        ctx.blocks_text = bundle.dmesg_text
    else:
        ctx.blocks = find_blocks(ctx.lines)
        ctx.blocks_text = render_blocks(ctx.lines, ctx.blocks)
    if not ctx.blocks_text.strip():
        print("error: log is empty or no suspicious segments were selected "
              "(pass --no-triage to analyze the full log)", file=sys.stderr)
        return 2
    log("[2/5]", f"prefilter: {len(ctx.blocks)} segments / {len(ctx.lines)} lines")

    # [3/5] collect + context plugins
    ctx.host = _resolve_host(args, bundle)
    try:
        for collect in registry.get("collect"):
            try:
                collect(ctx)
            except CollectError:
                raise
            except Exception as e:
                _warn_plugin(collect, "collect", e)
        if ctx.offline_sources and registry.named("collect", "offline_sources") is None:
            print("warning: the offline package attached extra files but the "
                  "offline-sources plugin is not installed; ignoring them",
                  file=sys.stderr)
        for flag, value, kind, name in (
            ("--issue", args.issue, "context", "issue"),
            ("--scan", args.scan, "collect", "system_scan"),
            ("--vmcore", args.vmcore, "collect", "vmcore"),
            ("--live-probe", args.live_probe, "collect", "live_probe"),
            ("--cross-boot", args.cross_boot, "collect", "cross_boot"),
            ("--kernel-src", args.kernel_src, "collect", "srcmap"),
        ):
            if value and registry.named(kind, name) is None:
                print(f"warning: {flag} was given but the {name} plugin is not "
                      f"installed; ignoring it", file=sys.stderr)
        for context in registry.get("context"):
            try:
                context(ctx)
            except CollectError:
                raise
            except Exception as e:
                _warn_plugin(context, "context", e)
    except CollectError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    cfg = load_config(base_url=args.base_url, model=args.model, api_key=args.api_key,
                      provider=args.provider)
    if args.max_tokens:
        cfg.max_tokens = args.max_tokens
    ctx.cfg = cfg
    ctx.run_uuid = new_run_uuid()
    ctx.client = RecordingClient(Client(cfg))
    ctx.make_stream = _make_stream_factory()

    # [4/5] three-tier analysis; [5/5] optional deep verification plugin
    try:
        log("[4/5]", f"LLM three-tier analysis ({cfg.base_url})")
        ctx.corpus = ctx.lines + ctx.scan_lines
        ctx.result, ctx.answer = run_analysis(
            ctx.client, bundle, ctx.blocks_text, ctx.prefetch_text, ctx.corpus,
            source_text=ctx.source_text, scan_text=ctx.scan_text,
            make_stream=ctx.make_stream, history_text=ctx.history_text,
            facts_text=ctx.facts_text, issue_text=ctx.issue_text)
        if ctx.known_cases and ctx.result is not None \
                and ctx.result.get("inconclusive_concerns"):
            ids = ", ".join(f"#{kc['case_id']}" for kc in ctx.known_cases)
            log("[5/5]", f"fast path: skipping deep verification (confirmed {ids})")
        deep_hooks = registry.get("deep")
        if deep_hooks:
            try:
                deep_hooks[0](ctx)
            except LLMError:
                raise
            except Exception as e:
                _warn_plugin(deep_hooks[0], "deep", e)
        elif ctx.result is not None and not args.no_deep and ctx.executor is not None \
                and ctx.result.get("inconclusive_concerns") and not ctx.known_cases:
            log("[5/5]", "deep-verification plugin not installed; "
                         "leaving open questions unresolved")
    except LLMError as e:
        ctx.llm_error = str(e)
        print(f"error: {e}", file=sys.stderr)
    finally:
        if ctx.executor is not None:
            ctx.executor.close()

    # evidence verification is core and mandatory; then optional post plugins
    if isinstance(ctx.result, dict):
        if ctx.facts:
            ctx.result["facts"] = ctx.facts
        ctx.summary = verify_result(ctx.result, ctx.corpus)
    else:
        ctx.summary = VerifySummary()
    for post in registry.get("post"):
        try:
            post(ctx)
        except Exception as e:
            _warn_plugin(post, "post", e)

    if ctx.llm_error is not None:
        return 3
    if getattr(ctx.client, "last_finish_reason", None) == "length":
        print("warning: model output hit the max_tokens ceiling and was truncated "
              "(results may be incomplete)", file=sys.stderr)

    use_color = args.color == "always" or (
        args.color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    if args.json:
        print(json.dumps(ctx.result, ensure_ascii=False, indent=2)
              if ctx.result is not None else
              json.dumps({"error": "model returned no JSON", "raw": ctx.answer},
                         ensure_ascii=False, indent=2))
    elif args.brief:
        brief = registry.named("render", "brief")
        if brief is None:
            print("warning: brief renderer plugin not installed; printing the full report",
                  file=sys.stderr)
            text = _render_markdown(ctx)
        else:
            try:
                text = brief(ctx)
            except Exception as e:
                _warn_plugin(brief, "render", e)
                print("warning: brief renderer failed; printing the full report",
                      file=sys.stderr)
                text = _render_markdown(ctx)
        print(apply_ansi(text) if use_color else text)
    elif args.output:
        report = _render_markdown(ctx)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"report written to {args.output}", file=sys.stderr)
    elif not args.html:
        report = _render_markdown(ctx)
        print(apply_ansi(report) if use_color else report)

    if args.html:
        html_hook = registry.named("render", "html")
        if html_hook is None:
            print("warning: HTML renderer plugin not installed; --html ignored",
                  file=sys.stderr)
        else:
            try:
                path = html_hook(ctx)
            except Exception as e:
                _warn_plugin(html_hook, "render", e)
                print("warning: HTML renderer failed; --html skipped", file=sys.stderr)
            else:
                print(f"HTML report written to {path}", file=sys.stderr)
    return 0 if ctx.result is not None else 4


def main(argv: list[str] | None = None) -> int:
    """Entry point: turn Ctrl-C into a clean exit (130, no traceback)."""
    try:
        return _run_cli(argv)
    except KeyboardInterrupt:
        print("\ninterrupted — no report written", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
