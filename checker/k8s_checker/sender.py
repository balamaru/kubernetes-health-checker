# Mengirim laporan ke service webhook notifier.
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime

from . import __version__
from .config import SEVERITY_ORDER, Config
from .models import Finding, iso, utcnow
from .state import Delta

log = logging.getLogger(__name__)


def _item(f: Finding, status: str, first_seen: datetime) -> dict:
    d = f.to_dict()
    d["status"] = status
    d["first_seen"] = iso(first_seen)
    return d


def build_payload(cfg: Config, delta: Delta, total_active: list[Finding], check_errors: list[str],
                  remediation_enabled: bool) -> dict:
    items = (
        [_item(f, "firing", fs) for f, fs in delta.firing]
        + [_item(f, "reminder", fs) for f, fs in delta.reminders]
        + [_item(f, "resolved", fs) for f, fs in delta.resolved]
    )
    # Urutkan: firing critical dulu, lalu warning, reminder, resolved
    status_rank = {"firing": 0, "reminder": 1, "resolved": 2}
    items.sort(key=lambda x: (status_rank[x["status"]], -SEVERITY_ORDER.get(x["severity"], 0), x["title"]))
    truncated = max(0, len(items) - cfg.max_findings_per_report)
    items = items[: cfg.max_findings_per_report]
    return {
        "version": 1,
        "source": f"k8s-health-checker/{__version__}",
        "cluster": cfg.cluster_name,
        "generated_at": iso(utcnow()),
        "summary": {
            "active_critical": sum(1 for f in total_active if f.severity == "critical"),
            "active_warning": sum(1 for f in total_active if f.severity == "warning"),
            "active_info": sum(1 for f in total_active if f.severity == "info"),
            "new": len(delta.firing),
            "reminder": len(delta.reminders),
            "resolved": len(delta.resolved),
            "truncated": truncated,
        },
        "remediation_enabled": remediation_enabled,
        "check_errors": check_errors,
        "findings": items,
    }


def send(cfg: Config, payload: dict, attempts: int = 3) -> bool:
    if not cfg.notify_webhook_url:
        log.warning("NOTIFY_WEBHOOK_URL tidak diset — laporan hanya ditulis ke log:\n%s",
                    json.dumps(payload, ensure_ascii=False, indent=2))
        return True
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": payload["source"]}
    if cfg.notify_webhook_token:
        headers["Authorization"] = f"Bearer {cfg.notify_webhook_token}"
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(cfg.notify_webhook_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=cfg.notify_timeout) as resp:
                log.info("Laporan terkirim ke notifier (HTTP %s, %d temuan)", resp.status, len(payload["findings"]))
                return True
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            log.error("Notifier membalas HTTP %s: %s", exc.code, detail)
            if 400 <= exc.code < 500 and exc.code != 429:
                return False  # salah konfigurasi (token/payload) — tidak perlu retry
        except Exception as exc:  # noqa: BLE001
            log.error("Gagal mengirim ke notifier (percobaan %d/%d): %s", attempt, attempts, exc)
        time.sleep(min(2 ** attempt, 10))
    return False
