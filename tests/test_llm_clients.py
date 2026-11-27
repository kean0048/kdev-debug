import requests

import dmesg_agent.llm as llm
from dmesg_agent.config import LLMConfig
from dmesg_agent.llm import pick_model


class FakeResponse:
    def __init__(self, data=None, lines=None, status=200, text=""):
        self.data = data or {}
        self.lines = lines or []
        self.status_code = status
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"{self.status_code} error")
            err.response = self
            raise err

    def json(self):
        return self.data

    def iter_lines(self, decode_unicode=False):
        yield from self.lines

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.headers = {}
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json=None, timeout=None, stream=False):
        self.calls.append({"url": url, "json": json, "stream": stream, "timeout": timeout})
        return self.responses.pop(0)

    def get(self, url, timeout=None):
        self.calls.append({"url": url, "get": True})
        return self.responses.pop(0)


def _client(monkeypatch, cfg, responses):
    session = FakeSession(responses)
    monkeypatch.setattr(llm.requests, "Session", lambda: session)
    return llm.Client(cfg), session


def test_pick_model_prefers_chat_models():
    assert pick_model(["text-embedding-3-small", "tts-1", "gpt-5.4"]) == "gpt-5.4"
    assert pick_model(["embed-1"]) == "embed-1"
    assert pick_model([]) is None


def test_openai_compatible_custom_paths(monkeypatch):
    cfg = LLMConfig(provider="gemini", base_url="https://g/v1beta/openai",
                    chat_path="/chat/completions", models_path="/models",
                    model="gemini-x", api_key="k")
    resp = FakeResponse(data={"choices": [{"message": {"content": "hi"},
                                           "finish_reason": "stop"}]})
    client, session = _client(monkeypatch, cfg, [resp])
    assert client.chat([{"role": "user", "content": "x"}]) == "hi"
    call = session.calls[0]
    assert call["url"] == "https://g/v1beta/openai/chat/completions"
    assert call["json"]["model"] == "gemini-x"
    assert call["stream"] is False
    assert client.last_finish_reason == "stop"


def test_openai_style_streams_content_and_reasoning(monkeypatch):
    cfg = LLMConfig(provider="local", base_url="http://x", model="m")
    resp = FakeResponse(lines=[
        'data: {"choices":[{"delta":{"reasoning_content":"think"}}]}',
        'data: {"choices":[{"delta":{"content":"he"}}]}',
        'data: {"choices":[{"delta":{"content":"llo"},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ])
    client, _ = _client(monkeypatch, cfg, [resp])
    chunks = []
    assert client.chat([{"role": "user", "content": "x"}],
                       stream_cb=chunks.append) == "hello"
    assert ("reasoning", "think") in chunks
    assert ("content", "he") in chunks and ("content", "llo") in chunks
    assert client.last_finish_reason == "stop"


def test_anthropic_native_request_and_response(monkeypatch):
    cfg = LLMConfig(provider="anthropic", api_style="anthropic",
                    base_url="https://api.anthropic.com",
                    chat_path="/v1/messages", model="claude-x", api_key="secret")
    resp = FakeResponse(data={"content": [{"type": "text", "text": "hello"},
                                          {"type": "text", "text": " world"}],
                              "stop_reason": "max_tokens"})
    client, session = _client(monkeypatch, cfg, [resp])
    out = client.chat([{"role": "system", "content": "sys"},
                       {"role": "user", "content": "u"}])
    assert out == "hello world"
    call = session.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["json"]["system"] == "sys"
    assert call["json"]["messages"] == [{"role": "user", "content": "u"}]
    assert call["json"]["max_tokens"] == 32768
    assert session.headers["x-api-key"] == "secret"
    assert session.headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in session.headers
    assert client.last_finish_reason == "length"


def test_anthropic_streaming(monkeypatch):
    cfg = LLMConfig(provider="anthropic", api_style="anthropic",
                    base_url="https://a", chat_path="/v1/messages",
                    model="claude-x", api_key="k")
    resp = FakeResponse(lines=[
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"he"}}',
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"llo"}}',
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}',
    ])
    client, _ = _client(monkeypatch, cfg, [resp])
    chunks = []
    assert client.chat([{"role": "user", "content": "x"}],
                       stream_cb=chunks.append) == "hello"
    assert chunks == [("content", "he"), ("content", "llo")]
    assert client.last_finish_reason == "end_turn"


def test_model_discovery_uses_provider_models_path(monkeypatch):
    cfg = LLMConfig(provider="gemini", base_url="https://g/v1beta/openai",
                    models_path="/models")
    resp = FakeResponse(data={"data": [{"id": "embed-1"}, {"id": "gemini-chat"}]})
    client, session = _client(monkeypatch, cfg, [resp])
    assert client.resolve_model() == "gemini-chat"
    assert session.calls[0]["url"] == "https://g/v1beta/openai/models"


def test_url_join_avoids_double_v1():
    cfg = LLMConfig(base_url="http://x/v1", chat_path="/v1/chat/completions")
    client = llm.Client(cfg)
    assert client._url(cfg.chat_path) == "http://x/v1/chat/completions"


def test_max_completion_tokens_field(monkeypatch):
    cfg = LLMConfig(provider="openai", base_url="https://api.openai.com",
                    model="gpt-x", max_tokens_field="max_completion_tokens")
    resp = FakeResponse(data={"choices": [{"message": {"content": "ok"},
                                           "finish_reason": "stop"}]})
    client, session = _client(monkeypatch, cfg, [resp])
    client.chat([{"role": "user", "content": "x"}])
    body = session.calls[0]["json"]
    assert "max_completion_tokens" in body and "max_tokens" not in body


def test_extra_body_merged_into_payload(monkeypatch):
    cfg = LLMConfig(provider="local", base_url="http://x", model="m",
                    extra_body={"chat_template_kwargs": {"enable_thinking": False}})
    resp = FakeResponse(data={"choices": [{"message": {"content": "ok"},
                                           "finish_reason": "stop"}]})
    client, session = _client(monkeypatch, cfg, [resp])
    client.chat([{"role": "user", "content": "x"}])
    body = session.calls[0]["json"]
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["model"] == "m" and body["messages"]


def test_retry_without_unsupported_temperature(monkeypatch):
    cfg = LLMConfig(provider="openai", base_url="https://api.openai.com", model="gpt-x")
    bad = FakeResponse(status=400, text="Unsupported parameter: 'temperature' is not supported")
    good = FakeResponse(data={"choices": [{"message": {"content": "ok"},
                                           "finish_reason": "stop"}]})
    client, session = _client(monkeypatch, cfg, [bad, good])
    assert client.chat([{"role": "user", "content": "x"}]) == "ok"
    assert "temperature" not in session.calls[1]["json"]
