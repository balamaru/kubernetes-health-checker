# Konfigurasi checker — seluruh value dibaca dari environment variable.
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

ALL_CHECKS = ("cluster", "nodes", "pods", "workloads", "network", "storage", "events")
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Env {name} harus berupa angka, didapat: {raw!r}") from exc


def _float_opt(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Env {name} harus berupa angka desimal, didapat: {raw!r}") from exc


def _json_dict(name: str) -> dict:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    try:
        val = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Env {name} harus JSON object, mis. {{\"X-Title\": \"k8s\"}}") from exc
    if not isinstance(val, dict):
        raise ValueError(f"Env {name} harus JSON object")
    return {str(k): str(v) for k, v in val.items()}


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


@dataclass
class Config:
    # Identitas
    cluster_name: str = "kubernetes"

    # Koneksi Kubernetes
    auth_mode: str = "auto"  # auto | token | incluster
    api_server: str = ""
    token: str = ""
    token_file: str = ""
    ca_cert_b64: str = ""
    ca_cert_file: str = ""
    insecure_skip_tls_verify: bool = False
    request_timeout: int = 15

    # Jadwal
    check_interval_seconds: int = 60
    run_once: bool = False

    # Cakupan
    namespaces_include: list[str] = field(default_factory=list)
    namespaces_exclude: list[str] = field(default_factory=list)
    enabled_checks: list[str] = field(default_factory=lambda: list(ALL_CHECKS))
    min_severity: str = "warning"

    # Ambang batas
    pod_restart_threshold: int = 5
    pod_pending_minutes: int = 5
    pod_not_ready_minutes: int = 5
    event_window_minutes: int = 15
    event_min_count: int = 3
    job_failed_lookback_hours: int = 24
    pvc_pending_minutes: int = 5
    lb_pending_minutes: int = 10

    # Notifikasi
    notify_webhook_url: str = ""
    notify_webhook_token: str = ""
    notify_timeout: int = 30
    notify_resolved: bool = True
    reminder_interval_minutes: int = 60
    max_findings_per_report: int = 50

    # Diagnostik real dari cluster (log, event, spec) — dipakai LLM & ditampilkan di notifikasi
    diagnostics_enabled: bool = True
    include_logs: bool = True
    log_tail_lines: int = 60
    notify_log_lines: int = 8

    # Analisis & remediasi LLM
    remediation_enabled: bool = True   # aktif otomatis bila LLM_PROVIDER diisi
    llm_provider: str = ""             # openai | openai-compatible | ollama | azure | anthropic | gemini
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_version: str = ""
    llm_extra_headers: dict = field(default_factory=dict)
    llm_timeout: int = 60
    llm_max_tokens: int = 1500
    llm_temperature: float | None = None
    llm_max_findings_per_run: int = 10
    llm_concurrency: int = 3
    llm_min_severity: str = "warning"
    llm_language: str = "Bahasa Indonesia"
    llm_send_logs: bool = True

    # Lain-lain
    state_file: str = ""
    health_port: int = 8081
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls(
            cluster_name=_str("CLUSTER_NAME", "kubernetes"),
            auth_mode=_str("K8S_AUTH_MODE", "auto").lower(),
            api_server=_str("K8S_API_SERVER").rstrip("/"),
            token=_str("K8S_TOKEN"),
            token_file=_str("K8S_TOKEN_FILE"),
            ca_cert_b64=_str("K8S_CA_CERT"),
            ca_cert_file=_str("K8S_CA_CERT_FILE"),
            insecure_skip_tls_verify=_bool("K8S_INSECURE_SKIP_TLS_VERIFY", False),
            request_timeout=_int("K8S_REQUEST_TIMEOUT", 15),
            check_interval_seconds=_int("CHECK_INTERVAL_SECONDS", 60),
            run_once=_bool("RUN_ONCE", False),
            namespaces_include=_list("NAMESPACES_INCLUDE"),
            namespaces_exclude=_list("NAMESPACES_EXCLUDE"),
            enabled_checks=_list("ENABLED_CHECKS") or list(ALL_CHECKS),
            min_severity=_str("MIN_SEVERITY", "warning").lower(),
            pod_restart_threshold=_int("POD_RESTART_THRESHOLD", 5),
            pod_pending_minutes=_int("POD_PENDING_MINUTES", 5),
            pod_not_ready_minutes=_int("POD_NOT_READY_MINUTES", 5),
            event_window_minutes=_int("EVENT_WINDOW_MINUTES", 15),
            event_min_count=_int("EVENT_MIN_COUNT", 3),
            job_failed_lookback_hours=_int("JOB_FAILED_LOOKBACK_HOURS", 24),
            pvc_pending_minutes=_int("PVC_PENDING_MINUTES", 5),
            lb_pending_minutes=_int("LB_PENDING_MINUTES", 10),
            notify_webhook_url=_str("NOTIFY_WEBHOOK_URL"),
            notify_webhook_token=_str("NOTIFY_WEBHOOK_TOKEN"),
            notify_timeout=_int("NOTIFY_TIMEOUT", 30),
            notify_resolved=_bool("NOTIFY_RESOLVED", True),
            reminder_interval_minutes=_int("REMINDER_INTERVAL_MINUTES", 60),
            max_findings_per_report=_int("MAX_FINDINGS_PER_REPORT", 50),
            diagnostics_enabled=_bool("DIAGNOSTICS_ENABLED", True),
            include_logs=_bool("DIAGNOSTICS_INCLUDE_LOGS", True),
            log_tail_lines=_int("DIAGNOSTICS_LOG_TAIL_LINES", 60),
            notify_log_lines=_int("NOTIFY_LOG_LINES", 8),
            remediation_enabled=_bool("REMEDIATION_ENABLED", True),
            llm_provider=_str("LLM_PROVIDER").lower(),
            llm_api_key=_str("LLM_API_KEY"),
            llm_model=_str("LLM_MODEL"),
            llm_base_url=_str("LLM_BASE_URL").rstrip("/"),
            llm_api_version=_str("LLM_API_VERSION"),
            llm_extra_headers=_json_dict("LLM_EXTRA_HEADERS"),
            llm_timeout=_int("LLM_TIMEOUT", 60),
            llm_max_tokens=_int("LLM_MAX_TOKENS", 1500),
            llm_temperature=_float_opt("LLM_TEMPERATURE"),
            llm_max_findings_per_run=_int("LLM_MAX_FINDINGS_PER_RUN", 10),
            llm_concurrency=_int("LLM_CONCURRENCY", 3),
            llm_min_severity=_str("LLM_MIN_SEVERITY", "warning").lower(),
            llm_language=_str("LLM_LANGUAGE", "Bahasa Indonesia"),
            llm_send_logs=_bool("LLM_SEND_LOGS", True),
            state_file=_str("STATE_FILE"),
            health_port=_int("HEALTH_PORT", 8081),
            log_level=_str("LOG_LEVEL", "INFO").upper(),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        unknown = [c for c in self.enabled_checks if c not in ALL_CHECKS]
        if unknown:
            raise ValueError(f"ENABLED_CHECKS tidak dikenal: {unknown}. Pilihan: {list(ALL_CHECKS)}")
        if self.min_severity not in SEVERITY_ORDER:
            raise ValueError(f"MIN_SEVERITY harus salah satu dari {list(SEVERITY_ORDER)}")
        if self.auth_mode not in ("auto", "token", "incluster"):
            raise ValueError("K8S_AUTH_MODE harus auto | token | incluster")
        if self.check_interval_seconds < 10:
            raise ValueError("CHECK_INTERVAL_SECONDS minimal 10")
        if self.llm_min_severity not in SEVERITY_ORDER:
            raise ValueError(f"LLM_MIN_SEVERITY harus salah satu dari {list(SEVERITY_ORDER)}")
        if self.llm_enabled:
            from .llm import PROVIDERS  # import lokal untuk hindari siklus
            if self.llm_provider not in PROVIDERS:
                raise ValueError(f"LLM_PROVIDER tidak dikenal: {self.llm_provider!r}. Pilihan: {sorted(PROVIDERS)}")
            if not self.llm_model:
                raise ValueError("LLM_MODEL wajib diisi bila LLM_PROVIDER diset")
            if self.llm_provider in ("openai", "anthropic", "gemini", "azure") and not self.llm_api_key:
                raise ValueError(f"LLM_API_KEY wajib diisi untuk provider {self.llm_provider}")
            if self.llm_provider in ("openai-compatible", "azure") and not self.llm_base_url:
                raise ValueError(f"LLM_BASE_URL wajib diisi untuk provider {self.llm_provider}")

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_provider) and self.remediation_enabled

    @property
    def llm_status(self) -> str:
        """Alasan singkat status LLM — ditampilkan di log & footer notifikasi."""
        if self.llm_enabled:
            return f"aktif ({self.llm_provider}/{self.llm_model})"
        if not self.remediation_enabled:
            return "dimatikan (REMEDIATION_ENABLED=false)"
        if self.llm_api_key or self.llm_model:
            return "nonaktif: LLM_API_KEY/LLM_MODEL terisi tetapi LLM_PROVIDER kosong"
        return "nonaktif: LLM_PROVIDER belum diisi"

    def namespace_allowed(self, namespace: str | None) -> bool:
        if not namespace:  # resource cluster-scoped
            return True
        if self.namespaces_include and namespace not in self.namespaces_include:
            return False
        return namespace not in self.namespaces_exclude

    def check_enabled(self, name: str) -> bool:
        return name in self.enabled_checks

    def redacted(self) -> dict:
        """Ringkasan konfigurasi untuk log — tanpa nilai rahasia."""
        return {
            "cluster_name": self.cluster_name,
            "auth_mode": self.auth_mode,
            "api_server": self.api_server or "(in-cluster)",
            "token": "set" if (self.token or self.token_file) else "unset",
            "insecure_skip_tls_verify": self.insecure_skip_tls_verify,
            "check_interval_seconds": self.check_interval_seconds,
            "enabled_checks": self.enabled_checks,
            "namespaces_include": self.namespaces_include,
            "namespaces_exclude": self.namespaces_exclude,
            "min_severity": self.min_severity,
            "notify_webhook_url": "set" if self.notify_webhook_url else "unset",
            "diagnostics_enabled": self.diagnostics_enabled,
            "llm": {
                "enabled": self.llm_enabled,
                "status": self.llm_status,
                "provider": self.llm_provider or None,
                "model": self.llm_model or None,
                "base_url": self.llm_base_url or "(default)",
                "api_key": "set" if self.llm_api_key else "unset",
                "send_logs": self.llm_send_logs,
            },
        }
