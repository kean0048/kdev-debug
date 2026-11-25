"""命令行入口 v2。"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyze import deep_dive, run_analysis
from .collectors.base import RawBundle, collect_via
from .collectors.filelog import collect_file
from .config import load_config
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
        description="类 sashiko 的 dmesg AI 诊断 agent:三段式定位问题,深度采集核验,证据可逐字验证",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--ssh", metavar="USER@HOST", help="通过 SSH 采集远程机器")
    src.add_argument("--file", metavar="PATH", help="分析离线 dmesg/内核日志文件(支持 .gz,'-' 为标准输入)")
    p.add_argument("--boot", choices=["now", "previous"], default="now", help="采集哪次启动的日志")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", help="SSH 用户名(当 --ssh 未写 user@ 时)")
    p.add_argument("--key", help="SSH 私钥路径")
    p.add_argument("--kernel", default="unknown", help="离线日志对应的内核版本")
    p.add_argument("--distro", default="unknown", help="离线日志对应的发行版")
    p.add_argument("--no-triage", action="store_true", help="跳过预过滤,整份日志直接送模型分析")
    p.add_argument("--no-prefetch", action="store_true", help="跳过初始预采集")
    p.add_argument("--no-deep", action="store_true", help="跳过待验证问题的深度采集核验")
    p.add_argument("--max-verify", type=int, default=5, help="最多深度核验几条待验证问题(默认 5)")
    p.add_argument("--askpass", choices=["auto", "terminal", "gui", "none"], default="auto",
                   help="sudo 密码获取方式(默认 auto:终端优先,回退桌面弹窗)")
    p.add_argument("-o", "--output", help="将报告写入文件(默认打印到标准输出)")
    p.add_argument("--json", action="store_true", help="输出结构化 JSON 结果而非 Markdown 报告")
    p.add_argument("--kernel-src", metavar="PATH",
                   help="内核源码树(git)用于 call trace 源码关联;默认环境变量 DMESG_AGENT_KERNEL_SRC")
    p.add_argument("--no-srcmap", action="store_true", help="禁用源码关联")
    p.add_argument("--max-tokens", type=int, help="模型输出上限(默认 32768)")
    p.add_argument("--model", help="模型名(默认自动发现)")
    p.add_argument("--base-url", help="OpenAI 兼容 API 地址")
    p.add_argument("--api-key", help="API key(也可用环境变量 OPENAI_API_KEY)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


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
            raise CollectError("SSH 目标需形如 user@host 或配合 --user")
        return SSHExecutor(host, user, port=args.port, key_filename=args.key, resolver=resolver)
    return LocalExecutor(resolver)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = _Log(args.verbose)
    resolver = PassResolver(args.askpass)

    executor: Executor | None = None
    try:
        executor = _make_executor(args, resolver)
        if args.file:
            log("[1/5]", f"读取文件 {args.file}")
            bundle = collect_file(args.file, kernel=args.kernel, distro=args.distro)
        else:
            if args.ssh:
                log("[1/5]", f"SSH 连接 {args.ssh}")
            log("[1/5]", f"采集 (boot={args.boot})")
            bundle = collect_via(executor, boot=args.boot)
    except CollectError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 2

    lines = bundle.dmesg_text.splitlines()
    if args.no_triage:
        blocks = [Block(start=1, end=len(lines), names=["whole-log"])]
        blocks_text = bundle.dmesg_text
    else:
        blocks = find_blocks(lines)
        blocks_text = render_blocks(lines, blocks)
    if not blocks_text.strip():
        print("错误: 日志为空或未筛出任何可疑片段(可加 --no-triage 分析全文)", file=sys.stderr)
        return 2
    log("[2/5]", f"预过滤 {len(blocks)} 个片段 / {len(lines)} 行")

    prefetch_text = ""
    if executor is not None and not args.no_prefetch:
        sig_names = {n for b in blocks for n in b.names}
        evs = run_prefetch(executor, sig_names)
        prefetch_text = render_prefetch(evs)
        log("[3/5]", f"预采集 {sum(1 for e in evs if e.status == 'ok')} 项")
    else:
        log("[3/5]", "跳过预采集" + ("(--file 无执行器)" if args.file else ""))

    source_text = ""
    srcmap_version = ""
    src_path = args.kernel_src or os.environ.get("DMESG_AGENT_KERNEL_SRC")
    if src_path and not args.no_srcmap:
        sm = SrcMap(src_path)
        if not sm.available:
            print(f"警告: 内核源码树不可用({src_path}),跳过源码关联", file=sys.stderr)
        else:
            syms = extract_symbols(lines)
            if not syms:
                log("[3.5]", "日志中无 Call Trace 符号,跳过源码关联")
            if syms:
                srcmap_version = sm.version
                log("[3.5]", f"源码关联:trace 中 {len(syms)} 个函数 @ {src_path}")
                try:
                    sm.build_index(progress=lambda m: print(f"  {m}", file=sys.stderr))
                    source_text, matched = sm.render(syms)
                    log("[3.5]", f"成功关联 {len(matched)}/{len(syms)} 个函数")
                except Exception as e:
                    print(f"警告: 源码关联失败({e}),继续无源码分析", file=sys.stderr)

    cfg = load_config(base_url=args.base_url, model=args.model, api_key=args.api_key)
    if args.max_tokens:
        cfg.max_tokens = args.max_tokens
    client = Client(cfg)
    deep_used = False
    corpus = lines
    try:
        log("[4/5]", f"LLM 三段分析 ({cfg.base_url})")
        result, answer = run_analysis(client, bundle, blocks_text, prefetch_text, lines,
                                      source_text=source_text)
        if result is not None and not args.no_deep and executor is not None \
                and result.get("inconclusive_concerns"):
            n = len(result["inconclusive_concerns"])
            log("[5/5]", f"深度核验 {min(n, args.max_verify)}/{n} 项待验证问题(需要 root 时会弹出密码框)")
            result, corpus = deep_dive(client, executor, result, lines, bundle, max_concerns=args.max_verify)
            deep_used = True
    except LLMError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 3
    finally:
        if executor is not None:
            executor.close()

    if isinstance(result, dict):
        summary = verify_result(result, corpus)
    else:
        summary = VerifySummary()
    if getattr(client, "last_finish_reason", None) == "length":
        print("警告: 模型输出达到 max_tokens 上限被截断(结果可能不完整)", file=sys.stderr)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2) if result is not None else
              json.dumps({"error": "模型未返回 JSON", "raw": answer}, ensure_ascii=False, indent=2))
    else:
        report = render(result, bundle, summary, blocks, raw_text=answer,
                        prefetch_used=bool(prefetch_text), deep_used=deep_used,
                        source_text=source_text, srcmap_version=srcmap_version)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report + "\n")
            print(f"报告已写入 {args.output}", file=sys.stderr)
        else:
            print(report)
    return 0 if result is not None else 4


if __name__ == "__main__":
    sys.exit(main())
