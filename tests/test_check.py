from dmesg_agent import cli
from dmesg_agent import config as cfg_mod
from dmesg_agent.llm import LLMError


class _FakeClient:
    """Stands in for llm.Client so the check never touches the network."""

    def __init__(self, models=None, fail=False):
        self.models = models or []
        self.fail = fail

    def list_models(self):
        if self.fail:
            raise LLMError("cannot reach the LLM service at http://x: connection refused")
        return self.models


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for var in ("OPENAI_BASE_URL", "OPENAI_MODEL", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)


def test_check_not_ready_when_base_url_is_only_the_default(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    assert cli._check_main(client=_FakeClient(["m1"])) == 1
    out = capsys.readouterr().out
    assert "base_url not configured" in out
    assert "NOT ready" in out


def test_check_ready(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("base_url", "http://127.0.0.1:9/v1")
    cfg_mod.set_file_config("api_key", "sk-x")
    assert cli._check_main(client=_FakeClient(["m1"])) == 0
    out = capsys.readouterr().out
    assert "ready: all checks passed" in out
    assert "(auto-discover) → 'm1'" in out


def test_check_endpoint_down(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    cfg_mod.set_file_config("base_url", "http://127.0.0.1:9")
    assert cli._check_main(client=_FakeClient(fail=True)) == 1
    out = capsys.readouterr().out
    assert "endpoint unreachable" in out
    assert "NOT ready" in out


def test_check_env_var_counts_as_configured(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9")
    assert cli._check_main(client=_FakeClient(["m1"])) == 0


def test_check_accepts_provider_and_base_url_overrides(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    rc = cli._check_main(["--provider", "local", "--base-url", "http://127.0.0.1:9"],
                         client=_FakeClient(["chat-model"]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "provider: local" in out
    assert "http://127.0.0.1:9 (--base-url)" in out
    assert "(auto-discover) → 'chat-model'" in out


def test_check_provider_requiring_key_is_not_ready(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    rc = cli._check_main(["--provider", "deepseek"], client=_FakeClient(["deepseek-chat"]))
    assert rc == 1
    out = capsys.readouterr().out
    assert "DEEPSEEK_API_KEY" in out
    assert "NOT ready" in out
