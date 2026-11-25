"""call trace → 内核源码的确定性关联(借鉴 sashiko:代码即证据)。

模型不猜源码:本模块用 git 树索引把日志里的 `func+0x1a2/0x4d0 [module]` 解析为
源码函数体与文件近期提交历史,作为可校验的上下文喂给模型。

首次使用会构建函数定义索引(全树 git grep,约 1-3 分钟),缓存到 ~/.cache/dmesg-agent/,
随内核树 HEAD 失效。
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# 调用栈样式:func+0x1a2/0x4d0 可选 [module]
_TRACE_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]+)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+(?:\s*\[([a-zA-Z0-9_\-\.]+)\])?")

# 定义行候选(交给 git grep -E):行首即类型/函数名(名可以数字结尾)
_DEF_GREP_PATTERN = r"^[A-Za-z_][A-Za-z0-9_ *]*\("

CACHE_ROOT = Path(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))) / "dmesg-agent"


class SrcMapError(Exception):
    pass


@dataclass
class SrcInfo:
    func: str
    module: str
    file: str
    line: int
    body: str = ""
    history: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)  # 同名多定义时的其他位置


def extract_symbols(log_lines: list[str], cap: int = 12) -> list[tuple[str, str]]:
    """从日志行提取 (函数, 模块),按出现顺序去重。"""
    seen: dict[str, str] = {}
    for line in log_lines:
        for m in _TRACE_RE.finditer(line):
            name, module = m.group(1), m.group(2) or ""
            if name not in seen:
                seen[name] = module
                if len(seen) >= cap:
                    return list(seen.items())
    return list(seen.items())


def _git(tree: str, *args: str, timeout: int = 120) -> str:
    proc = subprocess.run(["git", "-C", tree, *args], capture_output=True, text=True,
                          errors="replace", timeout=timeout)
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _name_on_line(line: str) -> str | None:
    """取行中第一个 `(` 之前紧邻的标识符。"""
    idx = line.find("(")
    if idx <= 0:
        return None
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", line[:idx])
    return m.group(1) if m else None


class SrcMap:
    """内核源码树关联器。tree 为 None 时整体降级为不可用。"""

    def __init__(self, tree: str | None, cache_dir: Path | None = None):
        self.tree = Path(tree) if tree else None
        self._index: dict[str, list[tuple[str, int]]] | None = None
        self._cache_dir = cache_dir or CACHE_ROOT

    @property
    def available(self) -> bool:
        if not self.tree:
            return False
        return (self.tree / ".git").exists() or (self.tree / "Makefile").exists()

    @property
    def version(self) -> str:
        if not self.available:
            return "?"
        v = _git(str(self.tree), "describe", "--tags", timeout=30).strip()
        if v:
            return v
        # 从 Makefile 读版本
        try:
            parts = {}
            for line in (self.tree / "Makefile").open():
                m = re.match(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*)", line)
                if m:
                    parts[m.group(1)] = m.group(2).strip()
            return "-".join(parts.get(k, "") for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL")) + parts.get("EXTRAVERSION", "")
        except OSError:
            return "?"

    def _cache_path(self) -> Path:
        head = _git(str(self.tree), "rev-parse", "HEAD", timeout=30).strip() or self.version
        key = hashlib.sha1(f"{self.tree}@{head}".encode()).hexdigest()[:16]
        return self._cache_dir / f"srcmap-{key}.tsv"

    def build_index(self, progress=None, timeout: int = 420) -> None:
        if not self.available:
            raise SrcMapError(f"内核源码树不可用: {self.tree}")
        cache = self._cache_path()
        if cache.exists():
            self._index = self._load_index(cache)
            return
        if progress:
            progress("首次使用:构建内核函数索引(全树扫描,约 1-3 分钟,只此一次)...")
        out = _git(str(self.tree), "grep", "-I", "-n", "-E", _DEF_GREP_PATTERN, "--", "*.c",
                   timeout=timeout)
        if not out:
            raise SrcMapError("git grep 索引构建失败(内核树过大或 git 不可用)")
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for raw in out.splitlines():
                path, _, rest = raw.partition(":")
                lineno, _, line = rest.partition(":")
                if line.rstrip().endswith(";"):
                    continue  # 声明而非定义
                name = _name_on_line(line)
                if name:
                    f.write(f"{name}\t{path}\t{lineno}\n")
        tmp.replace(cache)
        self._index = self._load_index(cache)

    @staticmethod
    def _load_index(cache: Path) -> dict[str, list[tuple[str, int]]]:
        index: dict[str, list[tuple[str, int]]] = {}
        for raw in cache.read_text(encoding="utf-8").splitlines():
            parts = raw.split("\t")
            if len(parts) != 3:
                continue
            name, path, lineno = parts
            index.setdefault(name, []).append((path, int(lineno) if lineno.isdigit() else 0))
        return index

    def lookup(self, func: str, module: str = "") -> SrcInfo | None:
        if self._index is None:
            self.build_index()
        entries = self._index.get(func)
        if not entries:
            return None
        def _score(e: tuple[str, int]) -> int:
            path = e[0]
            if module and f"/{module}/" in f"/{path}":
                return 0
            return 1
        entries = sorted(entries, key=_score)
        file, line = entries[0]
        info = SrcInfo(func=func, module=module, file=file, line=line,
                       candidates=[f"{p}:{n}" for p, n in entries[1:4]])
        info.body = self._extract_body(file, line)
        hist = _git(str(self.tree), "log", "--oneline", "-5", "--", file, timeout=60)
        info.history = [h for h in hist.splitlines() if h][:5]
        return info

    def _extract_body(self, rel_path: str, start_line: int, cap: int = 120) -> str:
        try:
            lines = (self.tree / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        i = start_line - 1
        out: list[str] = []
        depth = 0
        started = False
        for _ in range(cap):
            if i >= len(lines):
                break
            out.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                started = True
            if started and depth <= 0:
                break
            i += 1
        return "\n".join(out)

    def render(self, symbols: list[tuple[str, str]], max_funcs: int = 5,
               body_funcs: int = 3, budget: int = 18_000) -> tuple[str, list[SrcInfo]]:
        """渲染 source_context 文本;返回 (文本, 成功关联的 SrcInfo 列表)。"""
        text_parts: list[str] = [
            f"【内核源码关联】源码树 {self.tree}(版本 {self.version}),以下函数体为源码树原文:",
        ]
        infos: list[SrcInfo] = []
        used = len(text_parts[0])
        for n, (func, module) in enumerate(symbols):
            if len(infos) >= max_funcs:
                break
            try:
                info = self.lookup(func, module)
            except SrcMapError:
                break
            if info is None:
                continue
            body = f"```\n{info.body}\n```" if len(infos) < body_funcs else "(函数体略,见源码位置)"
            hist = "\n".join(f"  - {h}" for h in info.history) or "  - (无记录)"
            chunk = (f"### {func}"
                     + (f" (模块 {module})" if module else "")
                     + f"\n位置:{info.file}:{info.line}"
                     + (f"\n同名定义还有:{', '.join(info.candidates)}" if info.candidates else "")
                     + f"\n{body}\n该文件最近提交:\n{hist}"
                     + (f"\n(截断)" if len(body) > 4000 else ""))
            if used + len(chunk) > budget:
                break
            text_parts.append(chunk)
            infos.append(info)
            used += len(chunk)
        if len(infos) == 0:
            return "", []
        return "\n\n".join(text_parts), infos
