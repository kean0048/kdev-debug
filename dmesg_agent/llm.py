"""OpenAI 兼容 /v1/chat/completions 客户端 + JSON 容错解析。"""

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
            raise LLMError(f"无法连接 LLM 服务 {self.cfg.base_url}: {e}") from e

    def list_models(self) -> list[str]:
        data = self._get("/v1/models")
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]

    def resolve_model(self) -> str:
        if self.cfg.model:
            return self.cfg.model
        models = self.list_models()
        if not models:
            raise LLMError(f"{self.cfg.base_url} 上没有可用模型")
        return models[0]

    def chat(self, messages: list[dict], retries: int = 2) -> str:
        url = f"{self.cfg.base_url}/v1/chat/completions"
        payload = {
            "model": self.cfg.model or self.resolve_model(),
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            "stream": False,
        }
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                resp = self._session.post(url, json=payload, timeout=self.cfg.timeout)
                resp.raise_for_status()
                data = resp.json()
                choice = data["choices"][0]
                self.last_finish_reason = choice.get("finish_reason")
                return choice["message"]["content"]
            except (requests.RequestException, KeyError, IndexError) as e:
                last_err = e
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
        raise LLMError(f"LLM 调用失败: {last_err}")


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_json_response(text: str) -> dict | None:
    """容错解析:直接 parse → 剥代码围栏 → 截取首尾大括号。全部失败返回 None。"""
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
    """输出被 max_tokens 截断时,补全引号与括号再试一次。"""
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
