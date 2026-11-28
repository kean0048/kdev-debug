"""Plugin framework: the core pipeline is a dispatcher; features are plugins.

Six hook kinds, all optional:

    source   fn(ctx) -> bool        claim the input and set ctx.bundle
    collect  fn(ctx) -> None        gather evidence BEFORE the LLM (executor or offline)
    context  fn(ctx) -> None        inject prompt context (issue report, history, ...)
    deep     fn(ctx) -> None        per-concern collection AFTER the first pass
    post     fn(ctx) -> None        result post-processing (case library, archive)
    render   fn(ctx) -> str | None  alternate output (brief text, HTML file)
    command  fn(argv) -> int        register a CLI subcommand (e.g. `web`)

A plugin is a module under this package whose functions carry @register(...).
Dropping a module (or disabling it with DMESG_AGENT_DISABLE_PLUGINS) removes the
feature; the core keeps working with one fewer enhancement.

Invariants that plugins may NOT break:
  - execution stays inside playbooks.py's whitelist (no model/log-provided commands);
  - evidence verification (verify.py) is enforced by the core, never by a plugin.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

KINDS = ("source", "collect", "context", "deep", "post", "render", "command")


@dataclass
class PluginMeta:
    kind: str
    name: str
    order: int = 100
    description: str = ""
    module: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "order": self.order,
                "description": self.description, "module": self.module}


@dataclass
class RunContext:
    """Mutable state shared between the core pipeline and plugins."""
    args: Any
    argv: list[str] = field(default_factory=list)
    resolver: Any = None
    log: Callable[[str, str], None] = lambda stage, msg: None

    executor: Any = None
    bundle: Any = None
    offline_sources: list[tuple[str, str]] = field(default_factory=list)

    lines: list[str] = field(default_factory=list)
    blocks: list = field(default_factory=list)
    blocks_text: str = ""

    prefetch_text: str = ""
    scan_text: str = ""
    scan_lines: list[str] = field(default_factory=list)
    changes_text: str = ""
    source_text: str = ""
    srcmap_version: str = ""

    issue_text: str = ""
    history_text: str = ""
    known_issues_text: str = ""
    known_issues: list[dict] = field(default_factory=list)
    known_issues_meta: dict = field(default_factory=dict)
    facts: list[dict] = field(default_factory=list)
    facts_text: str = ""

    host: str = ""
    run_uuid: str = ""
    cfg: Any = None
    client: Any = None
    make_stream: Any = None
    known_cases: list[dict] = field(default_factory=list)
    known_case: dict | None = None

    result: dict | None = None
    answer: str = ""
    corpus: list[str] = field(default_factory=list)
    summary: Any = None
    verify: dict = field(default_factory=dict)
    deep_used: bool = False
    llm_error: str | None = None
    archive_path: Any = None
    html_written: bool = False


class Registry:
    def __init__(self) -> None:
        self._plugins: dict[str, list[Callable]] = {k: [] for k in KINDS}
        self._discovered = False
        self.errors: list[str] = []

    # ------------------------------------------------------------- registration

    def register(self, kind: str, name: str | None = None, order: int = 100,
                 description: str = ""):
        if kind not in KINDS:
            raise ValueError(f"unknown plugin kind {kind!r} (valid: {', '.join(KINDS)})")

        def decorator(fn: Callable) -> Callable:
            meta = PluginMeta(kind=kind, name=name or fn.__name__, order=order,
                              description=description or (fn.__doc__ or "").strip().split(
                                  "\n")[0], module=fn.__module__)
            fn._plugin_meta = meta  # type: ignore[attr-defined]
            self._plugins[kind].append(fn)
            self._plugins[kind].sort(key=lambda f: f._plugin_meta.order)  # type: ignore[attr-defined]
            return fn
        return decorator

    # ---------------------------------------------------------------- discovery

    def discover(self, disabled: set[str] | None = None) -> None:
        """Import every module in this package; broken plugins are warnings."""
        if self._discovered:
            return
        self._discovered = True
        disabled = disabled if disabled is not None else _disabled_from_env()
        here = __path__  # type: ignore[name-defined]
        for info in pkgutil.iter_modules(here):
            name = info.name
            if name.startswith("_") or name in disabled:
                continue
            full = f"{__name__}.{name}"
            try:
                cached = sys.modules.get(full)
                if cached is not None:
                    # registry.reset() clears registrations; reload re-runs the
                    # decorators instead of returning the cached module
                    importlib.reload(cached)
                else:
                    importlib.import_module(full)
            except Exception as e:  # a broken plugin must not break the core
                msg = f"{name}: {type(e).__name__}: {e}"
                self.errors.append(msg)
                print(f"warning: plugin {msg}; continuing without it", file=sys.stderr)

    def reset(self) -> None:
        for kind in KINDS:
            self._plugins[kind] = []
        self._discovered = False
        self.errors = []

    # ----------------------------------------------------------------- accessors

    def get(self, kind: str) -> list[Callable]:
        return list(self._plugins.get(kind, []))

    def named(self, kind: str, name: str) -> Callable | None:
        for fn in self._plugins.get(kind, []):
            if fn._plugin_meta.name == name:  # type: ignore[attr-defined]
                return fn
        return None

    def all_meta(self) -> list[PluginMeta]:
        metas = [fn._plugin_meta for kind in KINDS for fn in self._plugins[kind]]
        return sorted(metas, key=lambda m: (KINDS.index(m.kind), m.order, m.name))

    def disabled(self) -> set[str]:
        return _disabled_from_env()


def _disabled_from_env() -> set[str]:
    raw = os.environ.get("DMESG_AGENT_DISABLE_PLUGINS", "")
    return {part.strip() for part in raw.split(",") if part.strip()}


registry = Registry()
register = registry.register


def load_plugins() -> Registry:
    registry.discover()
    return registry


__all__ = ["KINDS", "PluginMeta", "RunContext", "Registry", "registry", "register",
           "load_plugins"]
