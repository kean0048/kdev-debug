import os

import pytest

from dmesg_agent.config import load_config, read_file_config, use_provider
from dmesg_agent.providers import get_provider, provider_choices

_ENV_VARS = (
    "OPENAI_BASE_URL", "OPENAI_MODEL", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY",
    "DMESG_AGENT_PROVIDER", "DMESG_AGENT_BASE_URL", "DMESG_AGENT_MODEL",
    "DMESG_AGENT_API_KEY",
)


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_aliases_resolve():
    assert get_provider("gpt").name == "openai"
    assert get_provider("claude").name == "anthropic"
    assert get_provider(None).name == "custom"
    assert "deepseek" in provider_choices() and "gpt" in provider_choices()
    with pytest.raises(ValueError):
        get_provider("nope")


def test_use_deepseek_writes_preset(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("deepseek")
    fc = read_file_config()
    assert fc["provider"] == "deepseek"
    assert fc["base_url"] == "https://api.deepseek.com"
    assert fc["model"] == "deepseek-chat"
    cfg = load_config()
    assert cfg.provider == "deepseek" and cfg.api_style == "openai"
    assert cfg.base_url_source.startswith("config file") or "preset" in cfg.base_url_source


def test_use_anthropic_sets_native_paths(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("claude")
    cfg = load_config()
    assert cfg.provider == "anthropic"
    assert cfg.api_style == "anthropic"
    assert cfg.chat_path == "/v1/messages"
    assert cfg.models_path == "/v1/models"
    assert cfg.model == "claude-sonnet-5-5"
    assert read_file_config()["api_style"] == "anthropic"


def test_switch_provider_clears_stale_paths(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("gemini")
    assert read_file_config()["chat_path"] == "/chat/completions"
    use_provider("deepseek")
    fc = read_file_config()
    assert "chat_path" not in fc and "models_path" not in fc
    assert load_config().chat_path == "/v1/chat/completions"


def test_local_requires_base_url(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="requires --base-url"):
        use_provider("local")
    use_provider("local", base_url="http://192.168.1.70:8080/")
    cfg = load_config()
    assert cfg.base_url == "http://192.168.1.70:8080"
    assert cfg.model is None


def test_explicit_provider_ignores_stale_file_base(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("deepseek")
    cfg = load_config(provider="openai")
    assert cfg.provider == "openai"
    assert cfg.base_url == "https://api.openai.com"
    assert cfg.model is None


def test_key_env_precedence(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-ds")
    cfg = load_config()
    assert cfg.api_key == "from-ds" and cfg.key_source == "DEEPSEEK_API_KEY env"
    monkeypatch.setenv("DMESG_AGENT_API_KEY", "generic")
    assert load_config().api_key == "generic"
    assert load_config(api_key="flag").api_key == "flag"


def test_anthropic_key_envs(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    use_provider("anthropic")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "auth-token")
    assert load_config().api_key == "auth-token"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "api-key")
    assert load_config().api_key == "api-key"


def test_custom_does_not_use_anthropic_api_key(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "session-token")
    assert load_config().api_key == ""


def test_env_provider_selection(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("DMESG_AGENT_PROVIDER", "local")
    monkeypatch.setenv("DMESG_AGENT_BASE_URL", "http://127.0.0.1:9000")
    cfg = load_config()
    assert cfg.provider == "local"
    assert cfg.base_url == "http://127.0.0.1:9000"


def test_extra_body_from_env_and_file(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("DMESG_AGENT_EXTRA_BODY",
                       '{"chat_template_kwargs":{"enable_thinking":false}}')
    assert load_config().extra_body == {
        "chat_template_kwargs": {"enable_thinking": False}}
    monkeypatch.delenv("DMESG_AGENT_EXTRA_BODY")
    from dmesg_agent.config import set_file_config
    set_file_config("extra_body", {"enable_thinking": False})
    assert load_config().extra_body == {"enable_thinking": False}


def test_invalid_extra_body_env_is_ignored(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("DMESG_AGENT_EXTRA_BODY", "not json")
    assert load_config().extra_body == {}


def test_file_config_roundtrip_still_works(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    from dmesg_agent.config import set_file_config
    set_file_config("base_url", "http://10.0.0.9:8080")
    set_file_config("api_key", "sk-secret")
    cfg = load_config()
    assert cfg.base_url == "http://10.0.0.9:8080"
    assert cfg.api_key == "sk-secret"
    assert cfg.api_key and cfg.key_source == "config file"
