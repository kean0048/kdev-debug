"""LLM 连接配置:CLI flag > 环境变量 > 默认值。"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_BASE_URL = "http://192.168.1.70:8080"


@dataclass
class LLMConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str | None = None  # None = 从 /v1/models 自动发现
    api_key: str = ""
    timeout: int = 600
    temperature: float = 0.1
    max_tokens: int = 32768


def load_config(
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> LLMConfig:
    return LLMConfig(
        base_url=(base_url or os.environ.get("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/"),
        model=model or os.environ.get("OPENAI_MODEL") or None,
        api_key=(
            api_key
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or ""
        ),
    )
