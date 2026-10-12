# Model data temuan (finding).
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

CATEGORIES = ("cluster", "node", "pod", "workload", "network", "storage", "event")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Resource:
    kind: str
    name: str
    namespace: str | None = None

    def ref(self) -> str:
        return f"{self.kind}/{self.namespace}/{self.name}" if self.namespace else f"{self.kind}/{self.name}"


@dataclass
class Finding:
    check: str            # kode pemeriksaan, mis. "pod.crashloop"
    category: str         # cluster | node | pod | workload | network | storage | event
    severity: str         # info | warning | critical
    title: str            # "ada masalah apa"
    explanation: str      # "penjelasan kenapa errornya"
    resource: Resource
    evidence: list[str] = field(default_factory=list)
    reason: str = ""
    # Temuan berbasis jendela waktu (event, job gagal, OOM) tidak dikirim sebagai "resolved" ketika keluar dari jendela waktu — cukup dihapus diam-diam.
    auto_expire: bool = False
    remediation: str | None = None   # ringkasan remediasi (teks) — kompatibilitas
    # Hasil analisis berbasis data nyata:
    # {source, provider, model, root_cause, impact, remediation: [..], commands: [..], confidence, needs_more_info, error}
    analysis: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        key = f"{self.check}|{self.resource.ref()}|{self.reason}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        d["resource"]["ref"] = self.resource.ref()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        res = d.get("resource") or {}
        return cls(
            check=d["check"],
            category=d["category"],
            severity=d["severity"],
            title=d["title"],
            explanation=d.get("explanation", ""),
            resource=Resource(kind=res.get("kind", ""), name=res.get("name", ""), namespace=res.get("namespace")),
            evidence=list(d.get("evidence") or []),
            reason=d.get("reason", ""),
            auto_expire=bool(d.get("auto_expire")),
            remediation=d.get("remediation"),
            analysis=d.get("analysis"),
            extra=dict(d.get("extra") or {}),
        )
