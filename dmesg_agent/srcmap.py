"""Deterministic call-trace → kernel-source correlation (sashiko idea: code is evidence).

The model does not guess source code: this module resolves `func+0x1a2/0x4d0 [module]`
from the log into the function body and the file's recent commit history using a git-tree
index, and feeds that as verifiable context to the model.

The first run builds a function-definition index (a whole-tree git grep, roughly 1-3
minutes), cached under ~/.cache/dmesg-agent/ and invalidated when the tree HEAD changes.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# call-trace pattern: func+0x1a2/0x4d0 with an optional [module]
_TRACE_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]+)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+(?:\s*\[([a-zA-Z0-9_\-\.]+)\])?")

# definition-line candidates (fed to git grep -E): a type/function name at line start (names may end in digits)
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
    candidates: list[str] = field(default_factory=list)  # other definitions of the same name
    fixes: list[dict] = field(default_factory=list)  # fix commits touching this file


_KVER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_RC_RE = re.compile(r"-rc(\d+)")


def parse_kernel_version(text: str) -> tuple[int, int, int, int | None] | None:
    m = _KVER_RE.search(text or "")
    if not m:
        return None
    rc_m = _RC_RE.search(text)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0),
            int(rc_m.group(1)) if rc_m else None)


def kernel_includes_tag(running: str, tag: str) -> bool | None:
    """Is upstream release `tag` <= the running kernel version? (heuristic)

    Distro kernels backport fixes, so False means "not in the upstream release
    line the running version is based on" — the report tells the user to check
    the distro changelog rather than treating it as proof.
    """
    rv, tv = parse_kernel_version(running), parse_kernel_version(tag)
    if rv is None or tv is None:
        return None

    def key(v: tuple[int, int, int, int | None]) -> tuple[int, int, int, int]:
        major, minor, patch, rc = v
        return (major, minor, patch, 0 if rc is None else -rc)

    return key(rv) >= key(tv)


def extract_symbols(log_lines: list[str], cap: int = 12) -> list[tuple[str, str]]:
    """Extract (function, module) pairs from log lines, deduplicated in order of appearance."""
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
    """Take the identifier immediately before the first `(` on the line."""
    idx = line.find("(")
    if idx <= 0:
        return None
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", line[:idx])
    return m.group(1) if m else None


class SrcMap:
    """Kernel source-tree correlator. Degrades to unavailable when tree is None."""

    def __init__(self, tree: str | None, cache_dir: Path | None = None):
        self.tree = Path(tree) if tree else None
        self._index: dict[str, list[tuple[str, int]]] | None = None
        self._cache_dir = cache_dir or CACHE_ROOT
        self._fix_cache: dict[str, list[dict]] = {}

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
        # read the version from the Makefile
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
            raise SrcMapError(f"kernel source tree unavailable: {self.tree}")
        cache = self._cache_path()
        if cache.exists():
            self._index = self._load_index(cache)
            return
        if progress:
            progress("first run: building the kernel function index (whole-tree scan, ~1-3 minutes, one-time)...")
        out = _git(str(self.tree), "grep", "-I", "-n", "-E", _DEF_GREP_PATTERN, "--", "*.c",
                   timeout=timeout)
        if not out:
            raise SrcMapError("git grep index build failed (kernel tree too large or git unavailable)")
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for raw in out.splitlines():
                path, _, rest = raw.partition(":")
                lineno, _, line = rest.partition(":")
                if line.rstrip().endswith(";"):
                    continue  # declaration, not definition
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
        info.fixes = self._fix_candidates(file)
        return info

    def _fix_candidates(self, rel_path: str, cap: int = 3) -> list[dict]:
        """Commits touching this file whose subject mentions a fix, with the
        first release tag that contains them (git describe --contains)."""
        if rel_path in self._fix_cache:
            return self._fix_cache[rel_path]
        out = _git(str(self.tree), "log", "--format=%h%x09%s", "-40", "--", rel_path,
                   timeout=60)
        fixes: list[dict] = []
        for raw in out.splitlines():
            sha, _, subject = raw.partition("\t")
            if not sha or not re.search(r"\b(fix|fixes|fixed|fixing|regression)\b",
                                        subject, re.I):
                continue
            tag = _git(str(self.tree), "describe", "--contains", sha, "--tags",
                       "--abbrev=0", timeout=30).strip()
            fixes.append({"commit": sha, "subject": subject.strip()[:160],
                          "first_tag": tag})
            if len(fixes) >= cap:
                break
        self._fix_cache[rel_path] = fixes
        return fixes

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
               body_funcs: int = 3, budget: int = 18_000,
               running_kernel: str = "") -> tuple[str, list[SrcInfo]]:
        """Render the source_context text; returns (text, list of successfully correlated SrcInfo)."""
        text_parts: list[str] = [
            f"[Kernel source correlation] source tree {self.tree} (version {self.version}); the function bodies below are verbatim from the tree:",
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
            body = f"```\n{info.body}\n```" if len(infos) < body_funcs else "(body omitted; see the source location)"
            hist = "\n".join(f"  - {h}" for h in info.history) or "  - (no records)"
            fix_lines = ""
            if info.fixes:
                parts = ["Fix candidates (commits touching this file whose subject mentions a fix; "
                         "confirm the commit is the actual root-cause fix before backporting):"]
                for fx in info.fixes:
                    tag = fx.get("first_tag") or ""
                    if tag:
                        inc = kernel_includes_tag(running_kernel, tag) if running_kernel else None
                        if inc is True:
                            status = (f"first released in {tag}; the running kernel "
                                      f"{running_kernel or '?'} is at or after it upstream "
                                      f"(distro backports may still differ)")
                        elif inc is False:
                            status = (f"first released in {tag}; NOT in the running kernel "
                                      f"{running_kernel} upstream — candidate for upgrade/backport "
                                      f"(check the distro changelog for backports)")
                        else:
                            status = f"first released in {tag} (running kernel version unknown)"
                    else:
                        status = "no release tag contains this commit yet"
                    parts.append(f"  - {fx['commit']} {fx['subject']} — {status}")
                fix_lines = "\n".join(parts)
            chunk = (f"### {func}"
                     + (f" (module {module})" if module else "")
                     + f"\nLocation: {info.file}:{info.line}"
                     + (f"\nOther same-name definitions: {', '.join(info.candidates)}" if info.candidates else "")
                     + f"\n{body}\nRecent commits touching this file:\n{hist}"
                     + (f"\n{fix_lines}" if fix_lines else "")
                     + ("\n(truncated)" if len(body) > 4000 else ""))
            if used + len(chunk) > budget:
                break
            text_parts.append(chunk)
            infos.append(info)
            used += len(chunk)
        if len(infos) == 0:
            return "", []
        return "\n\n".join(text_parts), infos
