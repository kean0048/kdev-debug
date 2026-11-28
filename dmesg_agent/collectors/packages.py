"""Offline package importers: turn common diagnostic dumps into the pipeline's
"main kernel log + extra sources" shape without any live system access.

Supported inputs, auto-detected by name + content:
  - sosreport tarballs  (.tar / .tar.gz / .tar.xz / .tar.bz2)
  - journalctl JSON dumps (-o json / -o json-pretty / -o json-seq)
  - journalctl export dumps (-o export, the native key=value blocks)
  - nvidia-bug-report.log[.gz]  (NVIDIA's combined report)
  - plain dmesg / kern.log / journalctl -o short text (existing behavior)

Everything is read into memory (no files are extracted to disk); the returned
bundle's ``dmesg_text`` feeds triage, while ``extra_sources`` join the prompt
and evidence corpus exactly like a live system-scan would.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import CollectError
from .base import RawBundle, parse_os_release
from .filelog import derive_hostname, _read

# --------------------------------------------------------------------------- API

EXTRA_CHAR_BUDGET = 40_000   # total cap for extra sources (characters)


@dataclass
class OfflinePackage:
    bundle: RawBundle
    extra_sources: list[tuple[str, str]] = field(default_factory=list)
    note: str = ""


def load_offline_input(path: str, kernel: str = "unknown",
                       distro: str = "unknown") -> OfflinePackage:
    """Detect and import one offline input path. Raises CollectError on failure."""
    if _looks_like_tar(path):
        return _load_sosreport(path, kernel, distro)
    text = _read(path).strip()
    if not text:
        raise CollectError(f"log file {path} is empty")
    if _is_journal_json(text):
        return _load_journal_json(text, path, kernel, distro)
    if _is_journal_export(text):
        return _load_journal_export(text, path, kernel, distro)
    if _is_nvidia_bug_report(text):
        return _load_nvidia_bug_report(text, path, kernel, distro)
    return OfflinePackage(bundle=_plain_bundle(text, path, kernel, distro))


# ------------------------------------------------------------------- detection

def _looks_like_tar(path: str) -> bool:
    if path == "-":
        return False
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def is_offline_package(path: str) -> bool:
    """Cheap detection used by the source plugin: tar / journal json|export /
    nvidia-bug-report. Plain dmesg/kern.log returns False (core file source)."""
    if not path or path == "-":
        return False
    if _looks_like_tar(path):
        return True
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
        opener = gzip.open if magic == b"\x1f\x8b" else open
        with opener(path, "rt", errors="replace") as f:
            head = f.read(8192)
    except OSError:
        return False
    if head.lstrip().startswith("{") and any(
            key in head for key in ('"__CURSOR"', '"MESSAGE"', '"__REALTIME_TIMESTAMP"')):
        return True
    if "__CURSOR=" in head and "MESSAGE=" in head:
        return True
    return _is_nvidia_bug_report(head)


_JOURNAL_JSON_KEYS = {"__CURSOR", "MESSAGE", "_HOSTNAME", "__REALTIME_TIMESTAMP"}


def _is_journal_json(text: str) -> bool:
    first = text.splitlines()[0].strip() if text.splitlines() else ""
    if not first.startswith("{"):
        return False
    try:
        obj = json.loads(first)
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and bool(_JOURNAL_JSON_KEYS & set(obj))


_EXPORT_RE = re.compile(r"^(__CURSOR|__REALTIME_TIMESTAMP|_HOSTNAME|MESSAGE)=")


def _is_journal_export(text: str) -> bool:
    hits = 0
    for line in text.splitlines()[:200]:
        if _EXPORT_RE.match(line):
            hits += 1
    return hits >= 2 and "__CURSOR" in text[:4000]


_NV_RE = re.compile(r"NVIDIA bug report|nvidia-bug-report\.sh", re.I)


def _is_nvidia_bug_report(text: str) -> bool:
    return bool(_NV_RE.search(text[:8000]))


# ------------------------------------------------------------- plain / helpers

def _plain_bundle(text: str, path: str, kernel: str, distro: str) -> RawBundle:
    extra: dict[str, str] = {"note": "offline log file; no live system context available"}
    hostname = derive_hostname(text)
    if hostname:
        extra["hostname"] = hostname
    return RawBundle(dmesg_text=text, kernel_version=kernel, distro=distro,
                     extra_context=extra, source=f"file:{path}")


def _ts(us: int | str) -> str:
    """journal __REALTIME_TIMESTAMP (microseconds) → "Nov 28 00:12:34"."""
    try:
        return _dt.datetime.fromtimestamp(int(us) / 1_000_000).strftime("%b %d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return ""


def _transport_label(rec: dict) -> str:
    if rec.get("_TRANSPORT") == "kernel":
        return "kernel"
    return rec.get("_COMM") or rec.get("SYSLOG_IDENTIFIER") or "journal"


def _source_note(path: str, what: str) -> str:
    return {"note": f"offline {what}; no live system context available"}


# ------------------------------------------------------------ journalctl JSON

def _load_journal_json(text: str, path: str, kernel: str,
                       distro: str) -> OfflinePackage:
    lines: list[str] = []
    hosts: dict[str, int] = {}
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        msg = str(rec.get("MESSAGE", "")).rstrip("\n")
        if not msg:
            continue
        host = str(rec.get("_HOSTNAME", ""))
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        ts = _ts(rec.get("__REALTIME_TIMESTAMP", rec.get("_SOURCE_REALTIME_TIMESTAMP", "")))
        label = _transport_label(rec)
        prefix = f"{ts} {host} {label}: " if ts else f"{host} {label}: " if host else f"{label}: "
        lines.append(prefix + msg.replace("\n", " "))
    if not lines:
        raise CollectError(f"{path}: no journal records parsed from the JSON export")
    return OfflinePackage(bundle=_bundle_from_lines(lines, hosts, path, kernel, distro,
                                                    what="journalctl json"))


def _load_journal_export(text: str, path: str, kernel: str,
                         distro: str) -> OfflinePackage:
    """journalctl -o export: key=value blocks separated by blank lines."""
    lines: list[str] = []
    hosts: dict[str, int] = {}
    for block in text.split("\n\n"):
        rec: dict[str, str] = {}
        key = None
        for raw in block.splitlines():
            m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", raw)
            if m:
                key, value = m.group(1), m.group(2)
                rec[key] = value
            elif key and key in rec:
                rec[key] += "\n" + raw  # MESSAGE continuation line
        msg = rec.get("MESSAGE", "").rstrip("\n")
        if not msg:
            continue
        host = rec.get("_HOSTNAME", "")
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        ts = _ts(rec.get("__REALTIME_TIMESTAMP", rec.get("_SOURCE_REALTIME_TIMESTAMP", "")))
        label = "kernel" if rec.get("_TRANSPORT") == "kernel" else (
            rec.get("_COMM") or rec.get("SYSLOG_IDENTIFIER") or "journal")
        prefix = f"{ts} {host} {label}: " if ts else f"{host} {label}: " if host else f"{label}: "
        lines.append(prefix + msg.replace("\n", " "))
    if not lines:
        raise CollectError(f"{path}: no journal records parsed from the export")
    return OfflinePackage(bundle=_bundle_from_lines(lines, hosts, path, kernel, distro,
                                                    what="journalctl export"))


def _bundle_from_lines(lines: list[str], hosts: dict[str, int], path: str,
                       kernel: str, distro: str, what: str) -> RawBundle:
    text = "\n".join(lines)
    extra = _source_note(path, what)
    hostname = max(hosts, key=hosts.get) if hosts else derive_hostname(text)
    if hostname:
        extra["hostname"] = hostname
    return RawBundle(dmesg_text=text, kernel_version=kernel, distro=distro,
                     extra_context=extra, source=f"file:{path}")


# ------------------------------------------------------ nvidia-bug-report

_NV_DMESG_RE = re.compile(
    r"^\[\s*\d+\.\d+\]|^NVRM:|^\[\s*[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]")


def _load_nvidia_bug_report(text: str, path: str, kernel: str,
                            distro: str) -> OfflinePackage:
    dmesg_lines = [l for l in text.splitlines() if _NV_DMESG_RE.match(l)]
    extra: dict[str, str] = _source_note(path, "nvidia-bug-report")
    if len(dmesg_lines) >= 5:
        main = "\n".join(dmesg_lines)
    else:
        main = text  # no distinct kernel section found; analyze the whole report
        extra["note"] += "; whole report treated as the main log"
    hostname = derive_hostname(main) or derive_hostname(text)
    if hostname:
        extra["hostname"] = hostname
    bundle = RawBundle(dmesg_text=main, kernel_version=kernel, distro=distro,
                       extra_context=extra, source=f"file:{path}")
    sources: list[tuple[str, str]] = []
    if main != text:
        sources.append(("nvidia-bug-report (full)", _trim(text, EXTRA_CHAR_BUDGET)))
    return OfflinePackage(bundle=bundle, extra_sources=sources,
                          note="nvidia-bug-report: kernel lines fed to triage, "
                               "full report attached as extra context")


# ------------------------------------------------------------------- sosreport

_SOS_DMESG = re.compile(r"/dmesg(\b|[-_])", re.I)
_SOS_JOURNAL = re.compile(r"/journalctl", re.I)
_SOS_MESSAGES = re.compile(r"(^|/)messages(\b|[-_.])", re.I)
_SOS_KERNLOG = re.compile(r"kern\.log", re.I)
_SOS_OSRELEASE = re.compile(r"(^|/)os-release$")
_SOS_UNAME = re.compile(r"/uname_-[ar]$")
_SOS_HOSTNAME = re.compile(r"(^|/)(hostname|hostname_-f)$")

# Command outputs inside a sosreport that mirror the live prefetch/scan/deep
# playbooks. Ordered by diagnostic value: hardware/storage state first.
_SOS_EXTRA: list[tuple[str, re.Pattern]] = [
    ("smartctl", re.compile(r"sos_commands/(block|storage)/smartctl", re.I)),
    ("lsblk", re.compile(r"sos_commands/(block|storage|hardware)/lsblk", re.I)),
    ("systemctl --failed", re.compile(r"sos_commands/systemd/systemctl.*(failed|list-units)", re.I)),
    ("df", re.compile(r"sos_commands/filesys/df", re.I)),
    ("mount", re.compile(r"sos_commands/filesys/mount", re.I)),
    ("ps", re.compile(r"sos_commands/process/ps(?=_|$)", re.I)),
    ("free", re.compile(r"sos_commands/memory/free", re.I)),
    ("vmstat", re.compile(r"sos_commands/memory/vmstat", re.I)),
    ("lspci", re.compile(r"sos_commands/(hardware|pci)/lspci", re.I)),
    ("dmidecode", re.compile(r"sos_commands/(hardware|devicemapper)/dmidecode", re.I)),
    ("lsusb", re.compile(r"sos_commands/(hardware|usb)/lsusb", re.I)),
    ("ethtool", re.compile(r"sos_commands/networking/ethtool", re.I)),
    ("ip addr", re.compile(r"sos_commands/networking/ip_.*addr", re.I)),
    ("sysctl", re.compile(r"sos_commands/kernel/sysctl", re.I)),
]

_PER_SOURCE_CAP = 8_000   # per extra source (command output / log) character cap


def _load_sosreport(path: str, kernel: str, distro: str) -> OfflinePackage:
    try:
        tar = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as e:
        raise CollectError(f"cannot open {path} as an archive: {e}") from e

    with tar:
        picked: dict[str, str] = {}
        commands: dict[str, str] = {}
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name
            f = tar.extractfile(member)
            if f is None:
                continue
            data = f.read().decode("utf-8", errors="replace")
            # keep the first (most specific) match per category
            if "dmesg" not in picked and _SOS_DMESG.search(name):
                picked["dmesg"] = data
            elif "journal" not in picked and _SOS_JOURNAL.search(name):
                picked["journal"] = data
            elif "kernlog" not in picked and _SOS_KERNLOG.search(name):
                picked["kernlog"] = data
            elif "messages" not in picked and _SOS_MESSAGES.search(name):
                picked["messages"] = data
            if "osrelease" not in picked and _SOS_OSRELEASE.search(name):
                picked["osrelease"] = data
            if "uname" not in picked and _SOS_UNAME.search(name):
                picked["uname"] = data
            if "hostname" not in picked and _SOS_HOSTNAME.search(name):
                picked["hostname"] = data
            for label, rx in _SOS_EXTRA:
                if label not in commands and rx.search(name):
                    commands[label] = data
                    break

    if not any(k in picked for k in ("dmesg", "journal", "kernlog", "messages")):
        raise CollectError(f"{path}: no dmesg/journal/messages/kern.log found in the archive")

    # choose the main kernel log, in precedence order
    main_key = next(k for k in ("dmesg", "journal", "kernlog", "messages")
                    if k in picked and picked[k].strip())
    main = picked[main_key].strip()
    if not main:
        raise CollectError(f"{path}: the kernel log found ({main_key}) is empty")

    resolved_kernel = kernel
    resolved_distro = distro
    if resolved_kernel == "unknown" and "uname" in picked:
        parts = picked["uname"].split()
        resolved_kernel = parts[2] if len(parts) > 2 else parts[-1]
    if resolved_distro == "unknown" and "osrelease" in picked:
        resolved_distro = parse_os_release(picked["osrelease"])

    extra = _source_note(path, "sosreport")
    hostname = derive_hostname(main)
    if not hostname and "hostname" in picked:
        hostname = picked["hostname"].strip().splitlines()[0].strip()
    if hostname:
        extra["hostname"] = hostname

    bundle = RawBundle(dmesg_text=main, kernel_version=resolved_kernel,
                       distro=resolved_distro, extra_context=extra, source=f"file:{path}")

    sources: list[tuple[str, str]] = []
    used = 0
    # 1) command outputs mirroring the live prefetch/deep playbooks, in value order
    for label, _rx in _SOS_EXTRA:
        if label in commands and commands[label].strip():
            piece = _trim(commands[label], _PER_SOURCE_CAP)
            sources.append((f"sosreport {label}", piece))
            used += len(piece)
    # 2) remaining log files that are not the main kernel log
    for key, label in (("journal", "journalctl"), ("kernlog", "kern.log"),
                       ("messages", "messages"), ("dmesg", "dmesg")):
        if key in picked and key != main_key and picked[key].strip():
            piece = _trim(picked[key], _PER_SOURCE_CAP)
            if used + len(piece) > EXTRA_CHAR_BUDGET:
                continue
            sources.append((f"sosreport {label}", piece))
            used += len(piece)
    return OfflinePackage(bundle=bundle, extra_sources=sources,
                          note=f"sosreport: {main_key} as the main kernel log, "
                               f"{len(sources)} collected file(s) attached")


def _trim(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit("\n", 1)[0] + "\n... (truncated) ..."


def render_offline_sources(sources: list[tuple[str, str]]) -> str:
    parts: list[str] = []
    for label, text in sources:
        parts.append(f"### [offline: {label}]\n{text}")
    return "\n\n".join(parts)
