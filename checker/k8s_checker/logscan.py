"""Pemindaian log container yang TERLIHAT sehat (Running / Ready) untuk mendeteksi error aplikasi.

Kubernetes hanya memantau proses & probe. Aplikasi yang terus mencatat error (koneksi DB gagal,
exception per request, timeout ke dependensi) tetap berstatus Running/Ready selama prosesnya
hidup dan probe-nya lolos. Modul ini membaca log terbaru (read-only, `pods/log`) dan menghitung
baris error per container dalam jendela waktu tertentu.

Desain:
- Deteksi berbasis *level log* (ERROR/FATAL/panic/Traceback/"level":"error"/klog E0000), bukan
  sekadar kata "error", agar baris seperti "errors=0" atau "retrying after error=nil" tidak memicu.
- Baris error dinormalisasi menjadi *signature* (angka, IP, UUID, hex, timestamp dihapus) sehingga
  error yang sama dihitung sebagai satu jenis dan ditampilkan dengan jumlahnya.
- Semua baris disamarkan (redact) sebelum disimpan/dikirim.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .redact import redact

# Pola default — level log eksplisit dari berbagai format umum.
DEFAULT_ERROR_PATTERN = (
    # level kapital sebagai kata utuh: "ERROR", "[ERROR]", " FATAL ", "CRITICAL", "SEVERE" (Java JUL)
    r"(?<![\w.-])(?:ERROR|ERR|FATAL|CRITICAL|CRIT|PANIC|SEVERE|EMERG|EMERGENCY|ALERT)(?![\w.-])"
    # logfmt: level=error / lvl=fatal / severity=error
    r"|(?i:\b(?:level|lvl|severity|loglevel)\s*[=:]\s*\"?(?:error|err|fatal|critical|crit|panic|alert|emerg)\b)"
    # JSON: "level":"error" / "severity":"ERROR" / "log.level":"error"
    r"|(?i:\"(?:level|lvl|severity|log\.level|levelname|@l)\"\s*:\s*\"(?:error|err|fatal|critical|crit|panic|alert|emerg|emergency)\")"
    # klog (komponen Kubernetes, controller Go): E1013 10:00:00.123456 ...
    r"|^\s*[EF]\d{4}\s+\d{2}:\d{2}:\d{2}"
    # Python / Go / Node / Java
    r"|Traceback \(most recent call last\)"
    r"|^\s*panic:"
    r"|^\s*fatal error:"
    r"|Exception in thread"
    r"|(?i:unhandled(?:promise)?rejection|uncaughtexception)"
    r"|^(?:[\w$]+\.)*[\w$]*(?:Exception|Error):\s"
    # nginx / apache / php
    r"|(?i:\[(?:error|crit|alert|emerg)\])"
    r"|(?i:PHP (?:Fatal|Parse) error)"
)

_NORMALIZE = [
    # timestamp ISO / umum di awal baris
    (re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), ""),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"), ""),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def normalize(line: str, limit: int = 160) -> str:
    s = line
    for pat, repl in _NORMALIZE:
        s = pat.sub(repl, s)
    s = s.strip(" -|:[]")
    return s[:limit]


@dataclass
class ScanResult:
    total_lines: int = 0
    error_count: int = 0
    signatures: list[tuple[str, int]] = field(default_factory=list)  # (signature, jumlah)
    samples: list[str] = field(default_factory=list)                 # baris error terakhir (disamarkan)
    fatal: bool = False                                              # ada panic/fatal/traceback


_FATAL = re.compile(r"(?i)\b(fatal|panic|traceback|emerg|outofmemory)")


def compile_pattern(pattern: str | None, default: str | None = None) -> re.Pattern | None:
    src = pattern or default
    if not src:
        return None
    return re.compile(src, re.M)


def scan_lines(lines: list[str], error_re: re.Pattern, ignore_re: re.Pattern | None = None,
               sample_lines: int = 8, top: int = 3) -> ScanResult:
    res = ScanResult(total_lines=len(lines))
    counter: Counter[str] = Counter()
    first_example: dict[str, str] = {}
    errors: list[str] = []
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if not error_re.search(line):
            continue
        if ignore_re and ignore_re.search(line):
            continue
        res.error_count += 1
        clean = redact(line[:400])
        errors.append(clean)
        sig = normalize(clean)
        counter[sig] += 1
        first_example.setdefault(sig, clean)
        if _FATAL.search(line):
            res.fatal = True
    res.signatures = counter.most_common(top)
    res.samples = errors[-sample_lines:]
    return res


def workload_of(pod: dict) -> tuple[str, str]:
    """(kind, name) workload pemilik pod. ReplicaSet milik Deployment dipetakan ke Deployment."""
    meta = pod.get("metadata") or {}
    owners = meta.get("ownerReferences") or []
    owner = next((o for o in owners if o.get("controller")), owners[0] if owners else None)
    if not owner:
        return "Pod", meta.get("name", "?")
    kind, name = owner.get("kind", "Pod"), owner.get("name", "?")
    if kind == "ReplicaSet":
        h = (meta.get("labels") or {}).get("pod-template-hash")
        if h and name.endswith("-" + h):
            return "Deployment", name[: -len(h) - 1]
    return kind, name
