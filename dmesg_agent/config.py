"""LLM connection settings: CLI flag > environment > config file > defaults.

The config file lives at ~/.config/dmesg-agent/config.json (honors
XDG_CONFIG_HOME), is written by `dmesg-agent config set`, and is saved with
mode 0600 (api_key is stored there too).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASE_URL = "http://192.168.8.43:19527"

FILE_KEYS = ("base_url", "model", "api_key", "max_tokens", "timeout")


@dataclass
class LLMConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str | None = None  # None = auto-discover from /v1/models
    api_key: str = ""
    timeout: int = 600
    temperature: float = 0.1
    max_tokens: int = 32768


def config_path() -> Path:
    root = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(root) / "dmesg-agent" / "config.json"


def read_file_config() -> dict:
    try:
        with open(config_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in FILE_KEYS}


def _save_file_config(data: dict) -> dict:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return data


def set_file_config(key: str, value) -> dict:
    if key not in FILE_KEYS:
        raise ValueError(f"unknown config key: {key} (valid: {', '.join(FILE_KEYS)})")
    data = read_file_config()
    data[key] = value
    return _save_file_config(data)


def unset_file_config(key: str) -> dict:
    data = read_file_config()
    data.pop(key, None)
    return _save_file_config(data)


def _int_of(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_config(
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> LLMConfig:
    fc = read_file_config()
    cfg = LLMConfig(
        base_url=(
            base_url
            or os.environ.get("OPENAI_BASE_URL")
            or fc.get("base_url")
            or DEFAULT_BASE_URL
        ).rstrip("/"),
        model=model or os.environ.get("OPENAI_MODEL") or fc.get("model") or None,
        api_key=(
            api_key
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or fc.get("api_key")
            or ""
        ),
    )
    mt = _int_of(fc.get("max_tokens"))
    if mt:
        cfg.max_tokens = mt
    to = _int_of(fc.get("timeout"))
    if to:
        cfg.timeout = to
    return cfg
