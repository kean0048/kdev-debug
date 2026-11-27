"""LLM provider presets: one command to point at a mainstream backend.

Borrowed from sashiko's split between a generic OpenAI-compatible chat
transport and a native Anthropic Messages client. A preset only supplies
defaults (base URL, model, auth style, paths, key env names); every value can
still be overridden by CLI flag, environment variable or the config file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    base_url: str | None = None
    api_style: str = "openai"          # "openai" | "anthropic"
    key_envs: tuple[str, ...] = ()
    default_model: str | None = None
    chat_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    max_tokens_field: str = "max_tokens"
    requires_base_url: bool = False
    requires_key: bool = False
    note: str = ""


PROVIDERS: dict[str, Provider] = {
    "custom": Provider(
        name="custom",
        label="Custom / any OpenAI-compatible endpoint",
        key_envs=("OPENAI_API_KEY",),
        note="default; pass base_url/model or use --base-url/--model",
    ),
    "local": Provider(
        name="local",
        label="Local OpenAI-compatible server",
        requires_base_url=True,
        note="vLLM / LM Studio / llama.cpp; often no API key",
    ),
    "vllm": Provider(
        name="vllm",
        label="vLLM (local)",
        base_url="http://127.0.0.1:8000",
        note="vLLM's default port; model auto-discovered",
    ),
    "ollama": Provider(
        name="ollama",
        label="Ollama (local)",
        base_url="http://127.0.0.1:11434",
        note="Ollama's OpenAI-compatible endpoint",
    ),
    "deepseek": Provider(
        name="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com",
        default_model="deepseek-chat",
        key_envs=("DEEPSEEK_API_KEY",),
        requires_key=True,
        note="use deepseek-reasoner for the reasoning model",
    ),
    "openai": Provider(
        name="openai",
        label="OpenAI / GPT",
        base_url="https://api.openai.com",
        key_envs=("OPENAI_API_KEY",),
        max_tokens_field="max_completion_tokens",
        requires_key=True,
        note="model auto-discovered (chat models preferred)",
    ),
    "anthropic": Provider(
        name="anthropic",
        label="Anthropic / Claude",
        base_url="https://api.anthropic.com",
        api_style="anthropic",
        default_model="claude-sonnet-5-5",
        key_envs=("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        chat_path="/v1/messages",
        requires_key=True,
        note="native Messages API (x-api-key + anthropic-version)",
    ),
    "gemini": Provider(
        name="gemini",
        label="Google Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        key_envs=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        chat_path="/chat/completions",
        models_path="/models",
        requires_key=True,
        note="Google's OpenAI-compatible endpoint",
    ),
    "openrouter": Provider(
        name="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        key_envs=("OPENROUTER_API_KEY",),
        chat_path="/chat/completions",
        models_path="/models",
        requires_key=True,
        note="one key for many vendors; model names are vendor/model",
    ),
}

ALIASES = {
    "gpt": "openai",
    "claude": "anthropic",
    "claude-code": "anthropic",
    "local-vllm": "vllm",
    "lmstudio": "local",
    "llama.cpp": "local",
}


def get_provider(name: str | None) -> Provider:
    """Resolve a provider name or alias; empty/None means custom."""
    key = (name or "custom").strip().lower()
    key = ALIASES.get(key, key)
    try:
        return PROVIDERS[key]
    except KeyError:
        valid = ", ".join(provider_choices())
        raise ValueError(f"unknown LLM provider {name!r} (choose from: {valid})") from None


def provider_choices() -> list[str]:
    return sorted(set(PROVIDERS) | set(ALIASES))


def provider_table() -> list[dict]:
    rows = []
    for p in PROVIDERS.values():
        rows.append({
            "name": p.name,
            "label": p.label,
            "base_url": p.base_url or ("built-in default" if p.name == "custom" else "(required)"),
            "default_model": p.default_model or "(auto-discover)",
            "key_envs": ", ".join(p.key_envs) or "(none)",
            "style": p.api_style,
            "note": p.note,
        })
    return rows
