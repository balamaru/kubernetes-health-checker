# Entry point checker: loop pemeriksaan + HTTP health/status endpoint.
from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .checks import HealthChecker
from .config import SEVERITY_ORDER, Config
from .k8s import K8sClient
from .models import iso, parse_time, utcnow
from .remediation import Analyzer
from .sender import build_payload, send
from .state import StateStore

log = logging.getLogger("checker")


class Runtime:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last_run_at = None
        self.last_run_ok = False
        self.last_duration = 0.0
        self.api_reachable = False
        self.runs = 0
        self.active: list[dict] = []
        self.check_errors: list[str] = []
        self.started = time.time()


RT = Runtime()
STOP = threading.Event()


def run_once(cfg: Config, checker: HealthChecker, store: StateStore, analyzer: Analyzer) -> bool:
    t0 = time.time()
    result = checker.run()

    min_rank = SEVERITY_ORDER[cfg.min_severity]
    current = [f for f in result.findings if SEVERITY_ORDER.get(f.severity, 0) >= min_rank]

    # Jika sebagian pemeriksaan gagal (mis. API down / izin kurang), pertahankan temuan lama dari pemeriksaan tsb agar tidak keliru dianggap "resolved".
    if result.failed_checks:
        cur_ids = {f.id for f in current}
        for t in store.active.values():
            if t.finding.extra.get("source") in result.failed_checks and t.finding.id not in cur_ids:
                current.append(t.finding)

    delta = store.diff(current)

    # Pakai ulang analisis yang sudah ada (mis. dari siklus sebelumnya / sebelum restart)
    for f in current:
        t = store.active.get(f.id)
        if t and t.finding.analysis and not f.analysis:
            f.analysis = t.finding.analysis
            f.remediation = t.finding.remediation
            for key in ("insights", "log_excerpt"):
                if key in t.finding.extra and key not in f.extra:
                    f.extra[key] = t.finding.extra[key]
    # Analisis berbasis data nyata untuk temuan yang akan dikirim dan belum dianalisis
    to_analyze = [f for f, _ in delta.firing + delta.reminders if not f.analysis]
    analyzer.process(to_analyze, current, checker.cache)

    delivered = True
    if not delta.is_empty():
        payload = build_payload(cfg, delta, current, result.check_errors, analyzer.llm_enabled)
        payload["llm_status"] = cfg.llm_status
        delivered = send(cfg, payload)
    store.commit(current, delta, delivered)

    dur = time.time() - t0
    with RT.lock:
        RT.runs += 1
        RT.last_run_at = iso(utcnow())
        RT.last_run_ok = delivered
        RT.last_duration = round(dur, 2)
        RT.api_reachable = result.api_reachable
        RT.check_errors = result.check_errors
        RT.active = [f.to_dict() for f in current]

    counts = {s: sum(1 for f in current if f.severity == s) for s in ("critical", "warning", "info")}
    log.info(
        "Pemeriksaan selesai dalam %.1fs — aktif: %s | baru=%d pengingat=%d resolved=%d | api=%s",
        dur, counts, len(delta.firing), len(delta.reminders), len(delta.resolved),
        "ok" if result.api_reachable else "DOWN",
    )
    for err in result.check_errors:
        log.warning(err)
    return delivered


# HTTP
class Handler(BaseHTTPRequestHandler):
    cfg: Config

    def log_message(self, fmt, *args):  # noqa: D401 - matikan access log default
        log.debug("http: " + fmt, *args)

    def _json(self, code: int, data) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        with RT.lock:
            if path in ("/healthz", "/livez"):
                # Liveness: loop tidak macet (run terakhir < 3x interval + timeout)
                stale_limit = 3 * self.cfg.check_interval_seconds + 120
                last = parse_time(RT.last_run_at)
                since = (utcnow() - last).total_seconds() if last else time.time() - RT.started
                ok = since < stale_limit
                return self._json(200 if ok else 503, {"status": "ok" if ok else "stale"})
            if path == "/readyz":
                ok = RT.runs > 0
                return self._json(200 if ok else 503, {"ready": ok})
            if path == "/status":
                return self._json(200, {
                    "version": __version__,
                    "cluster": self.cfg.cluster_name,
                    "runs": RT.runs,
                    "last_run_at": RT.last_run_at,
                    "last_run_delivered": RT.last_run_ok,
                    "last_duration_seconds": RT.last_duration,
                    "api_reachable": RT.api_reachable,
                    "check_errors": RT.check_errors,
                    "active_findings": RT.active,
                    "config": self.cfg.redacted(),
                })
            if path == "/metrics":
                lines = [
                    "# TYPE k8s_health_checker_runs_total counter",
                    f"k8s_health_checker_runs_total {RT.runs}",
                    "# TYPE k8s_health_checker_api_reachable gauge",
                    f"k8s_health_checker_api_reachable {1 if RT.api_reachable else 0}",
                    "# TYPE k8s_health_checker_last_run_duration_seconds gauge",
                    f"k8s_health_checker_last_run_duration_seconds {RT.last_duration}",
                    "# TYPE k8s_health_checker_active_findings gauge",
                ]
                for sev in ("critical", "warning", "info"):
                    n = sum(1 for f in RT.active if f["severity"] == sev)
                    lines.append(f'k8s_health_checker_active_findings{{severity="{sev}"}} {n}')
                body = ("\n".join(lines) + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return None
        return self._json(404, {"error": "not found"})


def start_http(cfg: Config) -> ThreadingHTTPServer | None:
    if cfg.health_port <= 0:
        return None
    Handler.cfg = cfg
    srv = ThreadingHTTPServer(("0.0.0.0", cfg.health_port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="http").start()
    log.info("Health endpoint aktif di :%d (/healthz /readyz /status /metrics)", cfg.health_port)
    return srv


def main() -> int:
    try:
        cfg = Config.from_env()
    except ValueError as exc:
        logging.basicConfig(level="ERROR")
        log.error("Konfigurasi tidak valid: %s", exc)
        return 2

    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
    )
    log.info("k8s-health-checker %s mulai — %s", __version__, json.dumps(cfg.redacted()))

    try:
        client = K8sClient(cfg)
    except ValueError as exc:
        log.error("Konfigurasi koneksi Kubernetes tidak valid: %s", exc)
        return 2

    checker = HealthChecker(client, cfg)
    store = StateStore(cfg.state_file, cfg.reminder_interval_minutes, cfg.notify_resolved)
    analyzer = Analyzer(cfg, client)
    if analyzer.llm_enabled:
        log.info("Analisis & remediasi LLM AKTIF: %s", analyzer.llm.label)
    elif cfg.llm_api_key or cfg.llm_model:
        log.warning("Analisis LLM %s. Pastikan env LLM_PROVIDER benar-benar sampai ke container "
                    "(cek: kubectl exec ... -- env | grep LLM_ atau endpoint /status).", cfg.llm_status)
    else:
        log.info("Analisis LLM %s — memakai penjelasan aturan + diagnostik cluster", cfg.llm_status)

    if cfg.run_once:
        ok = run_once(cfg, checker, store, analyzer)
        return 0 if ok else 1

    def _stop(signum, _frame):
        log.info("Menerima sinyal %s, berhenti...", signum)
        STOP.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    srv = start_http(cfg)

    while not STOP.is_set():
        try:
            run_once(cfg, checker, store, analyzer)
        except Exception:  # noqa: BLE001
            log.exception("Siklus pemeriksaan gagal")
        STOP.wait(cfg.check_interval_seconds)

    if srv:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
