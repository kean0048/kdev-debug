import json
import os

from dmesg_agent import config as cfg_mod


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for var in ("OPENAI_BASE_URL", "OPENAI_MODEL", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)


def test_file_config_roundtrip(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("base_url", "http://10.0.0.9:8080")
    cfg_mod.set_file_config("api_key", "sk-secret")
    assert cfg_mod.load_config().base_url == "http://10.0.0.9:8080"
    assert cfg_mod.load_config().api_key == "sk-secret"
    cfg_mod.unset_file_config("api_key")
    assert cfg_mod.load_config().api_key == ""


def test_precedence_flag_env_file_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("base_url", "http://from-file")
    assert cfg_mod.load_config().base_url == "http://from-file"
    monkeypatch.setenv("OPENAI_BASE_URL", "http://from-env/")
    assert cfg_mod.load_config().base_url == "http://from-env"
    assert cfg_mod.load_config(base_url="http://from-flag").base_url == "http://from-flag"
    cfg_mod.unset_file_config("base_url")
    monkeypatch.delenv("OPENAI_BASE_URL")
    assert cfg_mod.load_config().base_url == cfg_mod.DEFAULT_BASE_URL


def test_numeric_keys(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("max_tokens", 8192)
    cfg_mod.set_file_config("timeout", 120)
    cfg = cfg_mod.load_config()
    assert cfg.max_tokens == 8192 and cfg.timeout == 120
    # a bad value (unparseable string) falls back to the default instead of crashing
    path = cfg_mod.config_path()
    data = json.loads(path.read_text())
    data["max_tokens"] = "abc"
    path.write_text(json.dumps(data))
    assert cfg_mod.load_config().max_tokens == 32768


def test_unknown_key_rejected(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        cfg_mod.set_file_config("rm", "-rf")
        assert False, "should raise ValueError"
    except ValueError:
        pass


def test_missing_or_broken_file_tolerated(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert cfg_mod.read_file_config() == {}
    cfg_mod.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg_mod.config_path().write_text("not json {{")
    assert cfg_mod.read_file_config() == {}


def test_file_mode_0600(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("api_key", "sk-x")
    assert os.stat(cfg_mod.config_path()).st_mode & 0o777 == 0o600
