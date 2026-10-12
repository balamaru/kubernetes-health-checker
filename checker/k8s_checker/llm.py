"""Klien LLM multi-provider (stdlib saja).

Provider yang didukung (env LLM_PROVIDER):
  openai             -> api.openai.com (Chat Completions)
  openai-compatible  -> endpoint apa pun yang kompatibel OpenAI: OpenRouter, Groq, DeepSeek,
                        Together, Mistral, vLLM, LM Studio, LiteLLM proxy, dsb. (wajib LLM_BASE_URL)
  ollama             -> Ollama lokal via endpoint OpenAI-compatible (default http://localhost:11434/v1)
  azure              -> Azure OpenAI (LLM_BASE_URL = https://<resource>.openai.azure.com, LLM_MODEL = nama deployment)
  anthropic          -> Anthropic Messages API (Claude)
  gemini             -> Google Gemini generateContent
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .config import Config

log = logging.getLogger(__name__)

PROVIDERS = {"openai", "openai-compatible", "ollama", "azure", "anthropic", "gemini"}

DEFAULT_BASE = {
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
}


class LLMError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.provider = cfg.llm_provider
        self.model = cfg.llm_model
        self.base = (cfg.llm_base_url or DEFAULT_BASE.get(self.provider, "")).rstrip("/")
        self.api_key = cfg.llm_api_key

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}"

    # public API
    def complete(self, system: str, user: str) -> LLMResponse:
        builder = {
            "openai": self._openai,
            "openai-compatible": self._openai,
            "ollama": self._openai,
            "azure": self._openai,
            "anthropic": self._anthropic,
            "gemini": self._gemini,
        }[self.provider]
        url, headers, body, parse = builder(system, user)
        data = self._post(url, headers, body)
        return parse(data)

    # providers
    def _openai(self, system: str, user: str):
        cfg = self.cfg
        headers = {"Content-Type": "application/json"}
        body: dict = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if self.provider == "azure":
            version = cfg.llm_api_version or "2024-10-21"
            url = f"{self.base}/openai/deployments/{urllib.parse.quote(self.model)}/chat/completions?api-version={version}"
            headers["api-key"] = self.api_key
            body.pop("model")
        else:
            url = f"{self.base}/chat/completions"
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
        # API resmi OpenAI/Azure memakai max_completion_tokens (wajib untuk model reasoning);
        # server kompatibel umumnya masih memakai max_tokens.
        if self.provider in ("openai", "azure"):
            body["max_completion_tokens"] = cfg.llm_max_tokens
            body["response_format"] = {"type": "json_object"}
        else:
            body["max_tokens"] = cfg.llm_max_tokens
        if cfg.llm_temperature is not None:
            body["temperature"] = cfg.llm_temperature

        def parse(data: dict) -> LLMResponse:
            try:
                text = data["choices"][0]["message"].get("content") or ""
            except (KeyError, IndexError, TypeError) as exc:
                raise LLMError(f"Respons tidak terduga: {str(data)[:300]}") from exc
            usage = data.get("usage") or {}
            return LLMResponse(text, usage.get("prompt_tokens"), usage.get("completion_tokens"))

        return url, headers, body, parse

    def _anthropic(self, system: str, user: str):
        cfg = self.cfg
        url = f"{self.base}/v1/messages"
        headers = {"Content-Type": "application/json", "x-api-key": self.api_key,
                   "anthropic-version": cfg.llm_api_version or "2023-06-01"}
        body: dict = {
            "model": self.model,
            "max_tokens": cfg.llm_max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if cfg.llm_temperature is not None:
            body["temperature"] = cfg.llm_temperature

        def parse(data: dict) -> LLMResponse:
            parts = [c.get("text", "") for c in data.get("content") or [] if c.get("type") == "text"]
            if not parts:
                raise LLMError(f"Respons tidak terduga: {str(data)[:300]}")
            usage = data.get("usage") or {}
            return LLMResponse("".join(parts), usage.get("input_tokens"), usage.get("output_tokens"))

        return url, headers, body, parse

    def _gemini(self, system: str, user: str):
        cfg = self.cfg
        model = self.model if self.model.startswith("models/") else f"models/{self.model}"
        url = f"{self.base}/{model}:generateContent"
        headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
        gen: dict = {"maxOutputTokens": cfg.llm_max_tokens, "responseMimeType": "application/json"}
        if cfg.llm_temperature is not None:
            gen["temperature"] = cfg.llm_temperature
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": gen,
        }

        def parse(data: dict) -> LLMResponse:
            try:
                parts = data["candidates"][0]["content"]["parts"]
                text = "".join(p.get("text", "") for p in parts)
            except (KeyError, IndexError, TypeError) as exc:
                reason = (data.get("promptFeedback") or {}).get("blockReason") or str(data)[:300]
                raise LLMError(f"Respons Gemini tidak berisi teks: {reason}") from exc
            usage = data.get("usageMetadata") or {}
            return LLMResponse(text, usage.get("promptTokenCount"), usage.get("candidatesTokenCount"))

        return url, headers, body, parse

    # HTTP
    def _post(self, url: str, headers: dict, body: dict, attempts: int = 3) -> dict:
        headers = {**headers, **self.cfg.llm_extra_headers, "User-Agent": "k8s-health-checker/1.1"}
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        last_err = ""
        for attempt in range(1, attempts + 1):
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.llm_timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
                last_err = f"HTTP {exc.code}: {detail}"
                if exc.code in (429, 500, 502, 503, 504, 529):
                    retry_after = exc.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after and retry_after.replace(".", "", 1).isdigit() else 2 ** attempt
                    log.warning("LLM %s sibuk (%s), retry dalam %.1fs", self.label, exc.code, wait)
                    time.sleep(min(wait, 30))
                    continue
                if exc.code == 404:
                    last_err += f" — model '{self.model}' tidak ditemukan / sudah dihentikan provider atau LLM_BASE_URL salah"
                elif exc.code in (401, 403):
                    last_err += " — periksa LLM_API_KEY"
                raise LLMError(last_err) from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = f"koneksi gagal: {getattr(exc, 'reason', exc)}"
                log.warning("LLM %s %s (percobaan %d)", self.label, last_err, attempt)
                time.sleep(min(2 ** attempt, 10))
            except json.JSONDecodeError as exc:
                raise LLMError(f"Respons bukan JSON: {exc}") from None
        raise LLMError(last_err or "gagal tanpa detail")


def extract_json(text: str) -> dict:
    """Ambil objek JSON pertama dari teks model (toleran terhadap ```json fences / teks tambahan)."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    try:
        val = json.loads(text)
        if isinstance(val, dict):
            return val
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        val = json.loads(text[start:i + 1])
                        if isinstance(val, dict):
                            return val
                    except json.JSONDecodeError:
                        break
                    break
        start = text.find("{", start + 1)
    raise LLMError("Model tidak mengembalikan JSON yang valid")
