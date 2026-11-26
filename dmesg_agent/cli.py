"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyze import deep_dive, run_analysis
from .collectors.base import RawBundle, collect_via
from .collectors.filelog import collect_file
from .config import (
    FILE_KEYS,
    config_path,
    load_config,
    read_file_config,
    set_file_config,
    unset_file_config,
)
from .errors import CollectError
from .executors import Executor, LocalExecutor, SSHExecutor
from .llm import Client, LLMError
from .passwds import PassResolver
from .srcmap import SrcMap, extract_symbols
from .playbooks import run_prefetch
from .prompts import render_prefetch
from .report import render
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
    src.add_argument("--file", metavar="PATH", help="analyze an offline dmesg/kernel log file "
                                                    "(.gz supported, '-' for stdin)")
    p.add_argument("--boot", choices=["now", "previous"], default="now", help="which boot's log to collect")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", help="SSH user name (when --ssh has no user@ prefix)")
    p.add_argument("--key", help="path to an SSH private key")
    p.add_argument("--kernel", default="unknown", help="kernel version the offline log came from")
    p.add_argument("--distro", default="unknown", help="distro the offline log came from")
    p.add_argument("--no-triage", action="store_true", help="skip prefiltering; send the whole log to the model")
    p.add_argument("--no-prefetch", action="store_true", help="skip the initial prefetch collection")
    p.add_argument("--no-deep", action="store_true", help="skip deep verification of open questions")
    p.add_argument("--max-verify", type=int, default=5, help="max open questions to deep-verify (default 5)")
    p.add_argument("--askpass", choices=["auto", "terminal", "gui", "none"], default="auto",
                   help="how to obtain the sudo password (default auto: terminal first, GUI dialog fallback)")
    p.add_argument("-o", "--output", help="write the report to a file (default: stdout)")
    p.add_argument("--json", action="store_true", help="emit structured JSON instead of a Markdown report")
    p.add_argument("--kernel-src", metavar="PATH",
                   help="kernel source tree (git) for call-trace source correlation; "
                        "defaults to the DMESG_AGENT_KERNEL_SRC env var")
    p.add_argument("--no-srcmap", action="store_true", help="disable source correlation")
    p.add_argument("--max-tokens", type=int, help="model output ceiling (default 32768)")
    p.add_argument("--model", help="model name (default: auto-discover)")
    p.add_argument("--base-url", help="OpenAI-compatible API base URL")
    p.add_argument("--api-key", help="API key (or set the OPENAI_API_KEY env var)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


_INT_KEYS = {"max_tokens", "timeout"}


def _build_config_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmesg-agent config",
        description="manage the persistent LLM config file "
                    "(lower precedence than CLI flags and environment variables)",
    )
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("show", help="show saved settings and the effective values")
    sp = sub.add_parser("set", help=f"write a setting ({', '.join(FILE_KEYS)})")
    sp.add_argument("key", choices=list(FILE_KEYS))
    sp.add_argument("value")
    sub.add_parser("unset", help="remove a setting").add_argument("key", choices=list(FILE_KEYS))
    return p


def _config_main(argv: list[str]) -> int:
    args = _build_config_parser().parse_args(argv)
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
        print(f"  base_url: {cfg.base_url}")
        print(f"  model: {cfg.model or '(auto-discover)'}")
        print(f"  api_key: {'(set)' if cfg.api_key else '(not set)'}")
        print(f"  max_tokens: {cfg.max_tokens}  timeout: {cfg.timeout}s")
        return 0
    if args.action == "set":
        value: object = args.value
        if args.key in _INT_KEYS:
            try:
                value = int(args.value)
            except ValueError:
                print(f"error: {args.key} requires an integer, got {args.value!r}", file=sys.stderr)
                return 2
        set_file_config(args.key, value)
        shown = "****" if args.key == "api_key" else value
        print(f"wrote {args.key} = {shown} → {config_path()}")
        return 0
    unset_file_config(args.key)
    print(f"removed {args.key} → {config_path()}")
    return 0


class _Log:
    def __init__(self, verbose: bool):
        self.verbose = verbose

    def __call__(self, stage: str, msg: str) -> None:
        if self.verbose:
            print(f"{stage} {msg}", file=sys.stderr)


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
        return SSHExecutor(host, user, port=args.port, key_filename=args.key, resolver=resolver)
    return LocalExecutor(resolver)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "config":
        return _config_main(argv[1:])
    args = build_parser().parse_args(argv)
    log = _Log(args.verbose)
    resolver = PassResolver(args.askpass)

    executor: Executor | None = None
    try:
        executor = _make_executor(args, resolver)
        if args.file:
            log("[1/5]", f"reading file {args.file}")
            bundle = collect_file(args.file, kernel=args.kernel, distro=args.distro)
        else:
            if args.ssh:
                log("[1/5]", f"SSH connect {args.ssh}")
            log("[1/5]", f"collecting (boot={args.boot})")
            bundle = collect_via(executor, boot=args.boot)
    except CollectError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    lines = bundle.dmesg_text.splitlines()
    if args.no_triage:
        blocks = [Block(start=1, end=len(lines), names=["whole-log"])]
        blocks_text = bundle.dmesg_text
    else:
        blocks = find_blocks(lines)
        blocks_text = render_blocks(lines, blocks)
    if not blocks_text.strip():
        print("error: log is empty or no suspicious segments were selected "
              "(pass --no-triage to analyze the full log)", file=sys.stderr)
        return 2
    log("[2/5]", f"prefilter: {len(blocks)} segments / {len(lines)} lines")

    prefetch_text = ""
    if executor is not None and not args.no_prefetch:
        sig_names = {n for b in blocks for n in b.names}
        evs = run_prefetch(executor, sig_names)
        prefetch_text = render_prefetch(evs)
        log("[3/5]", f"prefetch: {sum(1 for e in evs if e.status == 'ok')} items")
    else:
        log("[3/5]", "skipping prefetch" + (" (no executor with --file)" if args.file else ""))

    source_text = ""
    srcmap_version = ""
    src_path = args.kernel_src or os.environ.get("DMESG_AGENT_KERNEL_SRC")
    if src_path and not args.no_srcmap:
        sm = SrcMap(src_path)
        if not sm.available:
            print(f"warning: kernel source tree unavailable ({src_path}); skipping source correlation",
                  file=sys.stderr)
        else:
            syms = extract_symbols(lines)
            if not syms:
                log("[3.5]", "no Call Trace symbols in the log; skipping source correlation")
            if syms:
                srcmap_version = sm.version
                log("[3.5]", f"source correlation: {len(syms)} trace functions @ {src_path}")
                try:
                    sm.build_index(progress=lambda m: print(f"  {m}", file=sys.stderr))
                    source_text, matched = sm.render(syms)
                    log("[3.5]", f"correlated {len(matched)}/{len(syms)} functions")
                except Exception as e:
                    print(f"warning: source correlation failed ({e}); continuing without sources",
                          file=sys.stderr)

    cfg = load_config(base_url=args.base_url, model=args.model, api_key=args.api_key)
    if args.max_tokens:
        cfg.max_tokens = args.max_tokens
    client = Client(cfg)
    deep_used = False
    corpus = lines
    try:
        log("[4/5]", f"LLM three-tier analysis ({cfg.base_url})")
        result, answer = run_analysis(client, bundle, blocks_text, prefetch_text, lines,
                                      source_text=source_text)
        if result is not None and not args.no_deep and executor is not None \
                and result.get("inconclusive_concerns"):
            n = len(result["inconclusive_concerns"])
            log("[5/5]", f"deep-verifying {min(n, args.max_verify)}/{n} open questions "
                         "(a password prompt may appear for root-level collection)")
            result, corpus = deep_dive(client, executor, result, lines, bundle, max_concerns=args.max_verify)
            deep_used = True
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    finally:
        if executor is not None:
            executor.close()

    if isinstance(result, dict):
        summary = verify_result(result, corpus)
    else:
        summary = VerifySummary()
    if getattr(client, "last_finish_reason", None) == "length":
        print("warning: model output hit the max_tokens ceiling and was truncated "
              "(results may be incomplete)", file=sys.stderr)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2) if result is not None else
              json.dumps({"error": "model returned no JSON", "raw": answer}, ensure_ascii=False, indent=2))
    else:
        report = render(result, bundle, summary, blocks, raw_text=answer,
                        prefetch_used=bool(prefetch_text), deep_used=deep_used,
                        source_text=source_text, srcmap_version=srcmap_version)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report + "\n")
            print(f"report written to {args.output}", file=sys.stderr)
        else:
            print(report)
    return 0 if result is not None else 4


if __name__ == "__main__":
    sys.exit(main())
