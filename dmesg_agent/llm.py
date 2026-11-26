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


class Client:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._session = requests.Session()
        if cfg.api_key:
            self._session.headers["Authorization"] = f"Bearer {cfg.api_key}"
        self._session.headers["Content-Type"] = "application/json"
        self.last_finish_reason: str | None = None

    def _get(self, path: str) -> Any:
        url = f"{self.cfg.base_url}{path}"
        try:
            resp = self._session.get(url, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise LLMError(f"cannot reach the LLM service at {self.cfg.base_url}: {e}") from e

    def list_models(self) -> list[str]:
        data = self._get("/v1/models")
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]

    def resolve_model(self) -> str:
        if self.cfg.model:
            return self.cfg.model
        models = self.list_models()
        if not models:
            raise LLMError(f"no usable model available at {self.cfg.base_url}")
        return models[0]

    def _chat_once(self, url: str, payload: dict,
                   stream_cb=None) -> str:
        """One request; when stream_cb is given, consume SSE deltas, pass text
        chunks to it (reasoning chunks as ('reasoning', txt)) and return the
        assembled content."""
        resp = self._session.post(url, json=payload, timeout=self.cfg.timeout,
                                  stream=stream_cb is not None)
        resp.raise_for_status()
        if stream_cb is None:
            choice = resp.json()["choices"][0]
            self.last_finish_reason = choice.get("finish_reason")
            return choice["message"]["content"]
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

    def chat(self, messages: list[dict], retries: int = 2, stream_cb=None) -> str:
        url = f"{self.cfg.base_url}/v1/chat/completions"
        base = {
            "model": self.cfg.model or self.resolve_model(),
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                if stream_cb is not None:
                    try:
                        return self._chat_once(url, {**base, "stream": True}, stream_cb)
                    except (requests.RequestException, KeyError, IndexError) as e:
                        # server may not support streaming: fall through once
                        last_err = e
                return self._chat_once(url, {**base, "stream": False})
            except (requests.RequestException, KeyError, IndexError) as e:
                last_err = e
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
