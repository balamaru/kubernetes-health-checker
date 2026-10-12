# Penyamaran data sensitif sebelum dikirim ke LLM / Discord.
from __future__ import annotations

import re

_PATTERNS = [
    # header Authorization / bearer token
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 ***"),
    # key=value / key: value untuk kata kunci sensitif
    (re.compile(r"(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
                r"private[_-]?key|client[_-]?secret|credential|auth)[\w.-]*)(\"?\s*[:=]\s*\"?)([^\s\"',;&]{3,})"),
     r"\1\2***"),
    # kredensial di URL: scheme://user:pass@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@"), r"\1:***@"),
    # JWT
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***JWT***"),
    # AWS access key id
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "***AWSKEY***"),
    # API key umum (OpenAI/Anthropic/GitHub/Slack/Google)
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
                r"xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})"), "***KEY***"),
    # blok private key PEM
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***PRIVATE KEY***"),
]


def redact(text: str | None) -> str:
    if not text:
        return text or ""
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_lines(lines: list[str]) -> list[str]:
    return [redact(ln) for ln in lines]
