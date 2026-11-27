"""LLM connection settings with provider presets.

Precedence: CLI flag > operation-specific environment variable > generic
DMESG_AGENT_* variable > provider env (API key) > config file > provider
preset > built-in default.

The config file lives at ~/.config/dmesg-agent/config.json (honors
XDG_CONFIG_HOME), is written by `dmesg-agent config use|set`, and is saved with
mode 0600 (api_key is stored there too).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .providers import Provider, get_provider

DEFAULT_BASE_URL = "http://192.168.8.43:19527"

FILE_KEYS = (
    "provider", "base_url", "model", "api_key", "api_style",
    "chat_path", "models_path", "max_tokens", "timeout", "temperature",
    "extra_body",
)


@dataclass
class LLMConfig:
    provider: str = "custom"
    provider_label: str = "Custom / any OpenAI-compatible endpoint"
    base_url: str = DEFAULT_BASE_URL
    model: str | None = None  # None = auto-discover from the models endpoint
    api_key: str = ""
    api_style: str = "openai"  # openai | anthropic
    chat_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    max_tokens_field: str = "max_tokens"
    timeout: int = 600
    temperature: float = 0.1
    max_tokens: int = 32768
    base_url_source: str = "built-in default"
    key_source: str = "none"
    extra_body: dict = field(default_factory=dict)  # provider-specific body fields


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


def use_provider(name: str, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None) -> dict:
    """Persist a provider preset (and its defaults) into the config file.

    Switching providers replaces base_url/model with the preset's values,
    clears stale style/path overrides, and keeps an existing api_key unless a
    new one is supplied (the CLI warns when the key may belong to the previous
    provider).
    """
    preset = get_provider(name)
    data = read_file_config()
    data["provider"] = preset.name

    if base_url:
        resolved = base_url.strip()
    elif preset.base_url:
        resolved = preset.base_url
    elif preset.requires_base_url:
        resolved = str(data.get("base_url") or "").strip()
        if not resolved:
            raise ValueError(f"provider {preset.name!r} requires --base-url "
                             f"(example: dmesg-agent config use {preset.name} "
                             f"--base-url http://127.0.0.1:8000)")
    else:
        resolved = str(data.get("base_url") or "").strip()  # custom keeps current
    if resolved:
        data["base_url"] = resolved.rstrip("/")
    else:
        data.pop("base_url", None)

    if model:
        data["model"] = model
    elif preset.default_model:
        data["model"] = preset.default_model
    elif preset.name != "custom":
        data.pop("model", None)  # let the provider auto-discover
    # custom keeps the current model when none is supplied

    if api_key:
        data["api_key"] = api_key

    for key, value, default in (
        ("api_style", preset.api_style, "openai"),
        ("chat_path", preset.chat_path, "/v1/chat/completions"),
        ("models_path", preset.models_path, "/v1/models"),
    ):
        if value != default:
            data[key] = value
        else:
            data.pop(key, None)
    return _save_file_config(data)


def _int_of(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_of(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dict_of(value) -> dict | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _select_provider(explicit: str | None, file_cfg: dict) -> tuple[Provider, bool, str]:
    name = explicit or file_cfg.get("provider") or "custom"
    try:
        return get_provider(name), bool(explicit), name
    except ValueError as e:
        print(f"warning: {e}; falling back to the custom provider", file=sys.stderr)
        return get_provider("custom"), bool(explicit), "custom"


def load_config(
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    provider: str | None = None,
) -> LLMConfig:
    fc = read_file_config()
    explicit_name = provider or os.environ.get("DMESG_AGENT_PROVIDER")
    preset, explicit, _name = _select_provider(explicit_name, fc)

    generic_base = os.environ.get("DMESG_AGENT_BASE_URL")
    style_env_name = ("ANTHROPIC_BASE_URL" if preset.api_style == "anthropic"
                      else "OPENAI_BASE_URL")
    style_base = os.environ.get(style_env_name)

    if base_url:
        resolved_base, base_src = base_url, "--base-url"
    elif generic_base:
        resolved_base, base_src = generic_base, "DMESG_AGENT_BASE_URL env"
    elif style_base:
        resolved_base, base_src = style_base, f"{style_env_name} env"
    elif not explicit and fc.get("base_url"):
        resolved_base, base_src = str(fc["base_url"]), "config file"
    elif preset.base_url:
        resolved_base, base_src = preset.base_url, f"provider preset ({preset.name})"
    elif preset.name == "custom":
        resolved_base, base_src = DEFAULT_BASE_URL, "built-in default"
    else:
        resolved_base, base_src = "", "not set"

    if model:
        resolved_model = model
    elif os.environ.get("DMESG_AGENT_MODEL"):
        resolved_model = os.environ["DMESG_AGENT_MODEL"]
    elif not explicit and fc.get("model"):
        resolved_model = str(fc["model"])
    else:
        resolved_model = preset.default_model

    resolved_key, key_src = "", "none"
    if api_key:
        resolved_key, key_src = api_key, "--api-key"
    elif os.environ.get("DMESG_AGENT_API_KEY"):
        resolved_key, key_src = os.environ["DMESG_AGENT_API_KEY"], "DMESG_AGENT_API_KEY env"
    else:
        for env_name in preset.key_envs:
            if os.environ.get(env_name):
                resolved_key, key_src = os.environ[env_name], f"{env_name} env"
                break
        if not resolved_key and fc.get("api_key") and (
                not explicit or fc.get("provider") == preset.name or preset.name == "custom"):
            resolved_key, key_src = str(fc["api_key"]), "config file"
        if not resolved_key and preset.name == "custom" and os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            resolved_key, key_src = os.environ["ANTHROPIC_AUTH_TOKEN"], "ANTHROPIC_AUTH_TOKEN env"

    if explicit:
        api_style = preset.api_style
        chat_path = preset.chat_path
        models_path = preset.models_path
    else:
        style = str(fc.get("api_style") or preset.api_style)
        api_style = style if style in ("openai", "anthropic") else preset.api_style
        chat_path = str(fc.get("chat_path") or preset.chat_path)
        models_path = str(fc.get("models_path") or preset.models_path)

    cfg = LLMConfig(
        provider=preset.name,
        provider_label=preset.label,
        base_url=resolved_base.rstrip("/"),
        model=resolved_model,
        api_key=resolved_key,
        api_style=api_style,
        chat_path=chat_path,
        models_path=models_path,
        max_tokens_field=preset.max_tokens_field,
        base_url_source=base_src,
        key_source=key_src,
    )
    mt = _int_of(fc.get("max_tokens"))
    if mt:
        cfg.max_tokens = mt
    to = _int_of(fc.get("timeout"))
    if to:
        cfg.timeout = to
    temp = _float_of(fc.get("temperature"))
    if temp is not None:
        cfg.temperature = temp
    cfg.extra_body = (_dict_of(os.environ.get("DMESG_AGENT_EXTRA_BODY"))
                      or _dict_of(fc.get("extra_body")) or {})
    return cfg
