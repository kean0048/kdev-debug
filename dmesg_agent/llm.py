"""OpenAI-compatible /v1/chat/completions client + fault-tolerant JSON parsing."""

from __future__ import annotations

import json
import re
import time
from typing import Any

import requests

from .config import LLMConfig


class LLMError(Exception):
    pass


_NON_CHAT_HINTS = (
    "embed", "embedding", "tts", "whisper", "dall-e", "moderation",
    "rerank", "audio", "transcribe", "image", "davinci-002", "babbage-002",
)


def pick_model(models: list[str]) -> str | None:
    """Prefer a chat-capable model over embeddings/audio/etc. in auto-discovery."""
    if not models:
        return None
    chat = [m for m in models
            if not any(hint in m.lower() for hint in _NON_CHAT_HINTS)]
    return (chat or models)[0]


class Client:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        if cfg.api_key:
            if cfg.api_style == "anthropic":
                self._session.headers["x-api-key"] = cfg.api_key
                self._session.headers["anthropic-version"] = "2023-06-01"
            else:
                self._session.headers["Authorization"] = f"Bearer {cfg.api_key}"
        self.last_finish_reason: str | None = None
        self.last_model: str | None = None

    def _url(self, path: str) -> str:
        base = (self.cfg.base_url or "").rstrip("/")
        if not base:
            raise LLMError(f"no base_url configured for provider {self.cfg.provider!r} — "
                           f"run `dmesg-agent config use {self.cfg.provider} "
                           f"--base-url <url>` or set DMESG_AGENT_BASE_URL")
        if path.startswith("/v1/") and base.endswith("/v1"):
            path = path[3:]
        return base + path

    def _get(self, path: str) -> Any:
        url = self._url(path)
        try:
            resp = self._session.get(url, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise LLMError(f"cannot reach the LLM service at {self.cfg.base_url}: {e}") from e

    def list_models(self) -> list[str]:
        data = self._get(self.cfg.models_path)
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]

    def resolve_model(self) -> str:
        if self.cfg.model:
            return self.cfg.model
        models = self.list_models()
        picked = pick_model(models)
        if not picked:
            raise LLMError(f"no usable model available at {self.cfg.base_url}")
        return picked

    def _openai_payload(self, model: str, messages: list[dict], stream: bool) -> dict:
        payload = dict(self.cfg.extra_body)  # provider-specific extras first
        payload.update({
            "model": model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            self.cfg.max_tokens_field: self.cfg.max_tokens,
            "stream": stream,
        })
        return payload

    def _anthropic_payload(self, model: str, messages: list[dict], stream: bool) -> dict:
        system = "\n\n".join(str(m.get("content", "")) for m in messages
                             if m.get("role") == "system")
        conv = [{"role": m.get("role"), "content": str(m.get("content", ""))}
                for m in messages if m.get("role") in ("user", "assistant")]
        payload = dict(self.cfg.extra_body)
        payload.update({
            "model": model,
            "max_tokens": self.cfg.max_tokens,
            "messages": conv,
            "stream": stream,
        })
        if system:
            payload["system"] = system
        if self.cfg.temperature is not None:
            payload["temperature"] = self.cfg.temperature
        return payload

    def _chat_once(self, url: str, payload: dict, stream_cb=None,
                   stream: bool = False) -> str:
        if self.cfg.api_style == "anthropic":
            return self._chat_anthropic(url, payload, stream_cb)
        return self._chat_openai(url, payload, stream_cb)

    def _chat_openai(self, url: str, payload: dict, stream_cb=None) -> str:
        """OpenAI-compatible chat; streams SSE deltas (including reasoning_content)."""
        resp = self._session.post(url, json=payload, timeout=self.cfg.timeout,
                                  stream=stream_cb is not None)
        resp.raise_for_status()
        if stream_cb is None:
            choice = resp.json()["choices"][0]
            self.last_finish_reason = choice.get("finish_reason")
            return choice["message"].get("content") or ""
        parts: list[str] = []
        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data:"):
                    continue
                body = raw[5:].strip()
                if body == "[DONE]":
                    break
                try:
                    chunk = json.loads(body)
                except json.JSONDecodeError:
                    continue
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                if choices[0].get("finish_reason"):
                    self.last_finish_reason = choices[0]["finish_reason"]
                delta = choices[0].get("delta") or {}
                text = delta.get("content") or ""
                reasoning = delta.get("reasoning_content") or ""
                if reasoning:
                    stream_cb(("reasoning", reasoning))
                if text:
                    parts.append(text)
                    stream_cb(("content", text))
        finally:
            resp.close()
        return "".join(parts)

    def _anthropic_text(self, data: dict) -> str:
        stop = data.get("stop_reason")
        self.last_finish_reason = "length" if stop == "max_tokens" else stop
        return "".join(block.get("text", "") for block in data.get("content", [])
                       if block.get("type") == "text")

    def _chat_anthropic(self, url: str, payload: dict, stream_cb=None) -> str:
        """Native Anthropic Messages API (x-api-key + anthropic-version headers)."""
        resp = self._session.post(url, json=payload, timeout=self.cfg.timeout,
                                  stream=stream_cb is not None)
        resp.raise_for_status()
        if stream_cb is None:
            return self._anthropic_text(resp.json())
        parts: list[str] = []
        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data:"):
                    continue
                body = raw[5:].strip()
                if not body or body == "[DONE]":
                    continue
                try:
                    event = json.loads(body)
                except json.JSONDecodeError:
                    continue
                etype = event.get("type")
                if etype == "content_block_delta":
                    delta = event.get("delta") or {}
                    if delta.get("type") == "text_delta" and delta.get("text"):
                        parts.append(delta["text"])
                        stream_cb(("content", delta["text"]))
                    elif delta.get("type") == "thinking_delta" and delta.get("thinking"):
                        stream_cb(("reasoning", delta["thinking"]))
                elif etype == "message_delta":
                    stop = (event.get("delta") or {}).get("stop_reason")
                    if stop:
                        self.last_finish_reason = "length" if stop == "max_tokens" else stop
                elif etype == "error":
                    msg = (event.get("error") or {}).get("message", "anthropic stream error")
                    raise LLMError(msg)
        finally:
            resp.close()
        return "".join(parts)

    @staticmethod
    def _adapt_request(base: dict, e: Exception) -> bool:
        """Retry once without an unsupported field (temperature / max_tokens)."""
        resp = getattr(e, "response", None)
        if resp is None or resp.status_code != 400:
            return False
        text = (getattr(resp, "text", "") or "").lower()
        if "temperature" in text and "temperature" in base:
            base.pop("temperature", None)
            return True
        if "max_completion_tokens" in text and "max_completion_tokens" in base:
            base["max_tokens"] = base.pop("max_completion_tokens")
            return True
        if "max_tokens" in text and "max_tokens" in base:
            base["max_completion_tokens"] = base.pop("max_tokens")
            return True
        return False

    def chat(self, messages: list[dict], retries: int = 2, stream_cb=None) -> str:
        url = self._url(self.cfg.chat_path)
        model = self.cfg.model or self.resolve_model()
        self.last_model = model
        base = (self._anthropic_payload(model, messages, False)
                if self.cfg.api_style == "anthropic"
                else self._openai_payload(model, messages, False))
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                if stream_cb is not None:
                    try:
                        streamed = self._chat_once(url, {**base, "stream": True},
                                                   stream_cb, stream=True)
                        # servers that ignore stream=true and answer with plain
                        # JSON yield an empty stream: fall through to non-stream
                        if streamed:
                            return streamed
                    except (requests.RequestException, KeyError, IndexError) as e:
                        last_err = e
                return self._chat_once(url, {**base, "stream": False}, None, stream=False)
            except (requests.RequestException, KeyError, IndexError) as e:
                last_err = e
                if self._adapt_request(base, e):
                    continue
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
        raise LLMError(f"LLM call failed: {last_err}")


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_json_response(text: str) -> dict | None:
    """Tolerant parsing: direct parse → strip code fences → slice outermost braces. Returns None if all fail."""
    if not text:
        return None
    text = text.strip()
    for candidate in _json_candidates(text):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            repaired = _repair_truncated(candidate)
            if repaired is None:
                continue
            try:
                obj = json.loads(repaired)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                obj["_repaired_truncation"] = True
                return obj
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _repair_truncated(s: str) -> str | None:
    """When output was cut off by max_tokens, close open quotes/brackets and retry once."""
    stack: list[str] = []
    in_str = esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
    if in_str:
        s += '"'
    s = s.rstrip().rstrip(",")
    if s.endswith(":"):
        s += " null"
    s += "".join("}" if c == "{" else "]" for c in reversed(stack))
    try:
        json.loads(s)
    except json.JSONDecodeError:
        return None
    return s


def _json_candidates(text: str):
    yield text
    for m in _FENCE_RE.finditer(text):
        body = m.group(1).strip()
        if body:
            yield body
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        yield text[start : end + 1]
