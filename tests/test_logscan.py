"""Pemindaian log pod Running/Ready yang sebenarnya error (check "logs" -> pod.log_errors).

Jalankan:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import re
import socket
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "checker"))
sys.path.insert(0, os.path.join(ROOT, "notifier"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fakes import FakeK8s  # noqa: E402
from k8s_checker import logscan  # noqa: E402
from k8s_checker.checks import HealthChecker  # noqa: E402
from k8s_checker.config import Config  # noqa: E402
from k8s_checker.k8s import K8sClient  # noqa: E402
from k8s_checker.remediation import Analyzer  # noqa: E402
from discord_notifier.discord import finding_embed  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


ERR = re.compile(logscan.DEFAULT_ERROR_PATTERN, re.M)


class Patterns(unittest.TestCase):
    POSITIVE = [
        "2026-10-13T03:00:01Z ERROR PaymentGateway timeout",
        "[ERROR] could not connect",
        "level=error msg=\"dial tcp: connection refused\"",
        'lvl=FATAL msg="boom"',
        '{"level":"error","msg":"failed"}',
        '{"severity": "ERROR", "message": "x"}',
        "E1013 10:00:00.123456       1 reflector.go:150] failed to list",
        "Traceback (most recent call last):",
        "panic: runtime error: invalid memory address",
        "java.lang.NullPointerException: Cannot invoke",
        "Error: connect ECONNREFUSED 127.0.0.1:5432",
        "2026/10/13 03:00:00 [error] 29#29: *1 upstream timed out",
        "SEVERE: Servlet.service() threw exception",
        "PHP Fatal error:  Uncaught Error",
        "UnhandledPromiseRejectionWarning: Error",
    ]
    NEGATIVE = [
        "processed batch errors=0 retries=0",
        'level=info msg="no error"',
        "GET /api/errors 200",
        "error_rate=0.00",
        "INFO  GET /healthz 200 1ms",
        "WARN retrying request",
        "loaded ErrorHandler middleware",
        "I1013 10:00:00.123456 1 leaderelection.go:250] attempting to acquire lease",
    ]

    def test_positive(self):
        for line in self.POSITIVE:
            self.assertTrue(ERR.search(line), f"seharusnya terdeteksi: {line}")

    def test_negative(self):
        for line in self.NEGATIVE:
            self.assertFalse(ERR.search(line), f"seharusnya TIDAK terdeteksi: {line}")

    def test_signature_groups_and_redacts(self):
        lines = [f"2026-10-13T03:00:{i:02d}Z ERROR timeout order={i} host 10.0.0.{i}:8080" for i in range(10)]
        lines += ["ERROR db password=SuperSecret123 auth failed"]
        res = logscan.scan_lines(lines, ERR, sample_lines=3)
        self.assertEqual(res.error_count, 11)
        self.assertEqual(res.signatures[0][1], 10, "error serupa harus dikelompokkan jadi satu signature")
        self.assertEqual(len(res.samples), 3)
        self.assertFalse(any("SuperSecret123" in x for x in res.samples), "rahasia harus disamarkan")

    def test_ignore_pattern(self):
        ign = re.compile(r"healthcheck")
        res = logscan.scan_lines(["ERROR healthcheck flaky", "ERROR real"], ERR, ign)
        self.assertEqual(res.error_count, 1)

    def test_workload_of(self):
        p = {"metadata": {"name": "api-5c6d-x1", "labels": {"pod-template-hash": "5c6d"},
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "api-5c6d", "controller": True}]}}
        self.assertEqual(logscan.workload_of(p), ("Deployment", "api"))
        p = {"metadata": {"name": "db-0", "ownerReferences": [{"kind": "StatefulSet", "name": "db"}]}}
        self.assertEqual(logscan.workload_of(p), ("StatefulSet", "db"))
        self.assertEqual(logscan.workload_of({"metadata": {"name": "solo"}}), ("Pod", "solo"))


class LogCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k8s = FakeK8s(free_port()).start()

    @classmethod
    def tearDownClass(cls):
        cls.k8s.stop()

    def cfg(self, **kw) -> Config:
        base = {
            "CLUSTER_NAME": "uji", "K8S_API_SERVER": f"http://127.0.0.1:{self.k8s.port}", "K8S_TOKEN": "test-token",
            "NAMESPACES_EXCLUDE": "ignored-ns", "HEALTH_PORT": "0", "ENABLED_CHECKS": "",
        }
        for k in [k for k in os.environ if k.startswith(("LLM_", "LOG_SCAN_"))]:
            os.environ.pop(k)
        os.environ.update(base)
        os.environ.update(kw)
        return Config.from_env()

    def findings(self, cfg, checker=None):
        checker = checker or HealthChecker(K8sClient(cfg), cfg)
        res = checker.run()
        return res, [f for f in res.findings if f.check == "pod.log_errors"]

    def test_running_ready_pod_with_error_logs_is_detected(self):
        cfg = self.cfg()
        res, found = self.findings(cfg)
        self.assertEqual(res.check_errors, [])
        self.assertEqual(len(found), 1, [f.title for f in found])
        f = found[0]
        self.assertEqual(f.resource.ref(), "Deployment/shop/pay", "digabung per workload, bukan per pod")
        self.assertIn("Running & Ready", f.title)
        self.assertEqual(f.severity, "warning")
        self.assertEqual(f.extra["error_count"], 17)
        self.assertEqual(f.extra["pods_affected"], 2)
        self.assertEqual(f.extra["pod"], "pay-6f7b-k2")
        self.assertTrue(any("13× " in e and "PaymentGateway" in e for e in f.evidence), f.evidence)
        self.assertFalse(any("SuperSecret123" in x for x in f.extra["log_excerpt"]))
        refs = {x.resource.ref() for x in found}
        self.assertNotIn("Pod/shop/chatty-1", refs, "kata 'error' biasa tidak boleh memicu")
        self.assertNotIn("Pod/shop/optout-1", refs, "anotasi opt-out harus dihormati")
        # Pod yang sudah punya temuan lain (slow-1 not_ready, api crashloop) tidak dipindai ulang
        scanned = [r for r in self.k8s.requests if "/log?" in r and "sinceSeconds" in r]
        self.assertFalse(any("/pods/slow-1/" in r or "/pods/api-5c6d-x1/" in r for r in scanned))

    def test_thresholds_and_critical(self):
        _, found = self.findings(self.cfg(LOG_SCAN_MIN_ERRORS="50", LOG_SCAN_CRITICAL_ERRORS="60"))
        self.assertEqual(found, [])
        _, found = self.findings(self.cfg(LOG_SCAN_CRITICAL_ERRORS="10"))
        self.assertEqual(found[0].severity, "critical")

    def test_namespace_exclude_and_disable(self):
        _, found = self.findings(self.cfg(LOG_SCAN_NAMESPACES_EXCLUDE="shop"))
        self.assertEqual(found, [])
        _, found = self.findings(self.cfg(ENABLED_CHECKS="pods,workloads"))
        self.assertEqual(found, [])

    def test_custom_pattern(self):
        _, found = self.findings(self.cfg(LOG_SCAN_ERROR_PATTERN=r"errors=0", LOG_SCAN_MIN_ERRORS="1"))
        self.assertEqual([f.resource.ref() for f in found], ["Pod/shop/chatty-1"])
        with self.assertRaises(ValueError):
            self.cfg(LOG_SCAN_ERROR_PATTERN="(unclosed")

    def test_interval_reuses_last_result(self):
        cfg = self.cfg(LOG_SCAN_INTERVAL_SECONDS="3600")
        checker = HealthChecker(K8sClient(cfg), cfg)
        _, first = self.findings(cfg, checker)
        n_before = len([r for r in self.k8s.requests if "sinceSeconds" in r])
        _, second = self.findings(cfg, checker)
        n_after = len([r for r in self.k8s.requests if "sinceSeconds" in r])
        self.assertEqual(n_before, n_after, "log tidak boleh diambil ulang sebelum interval")
        self.assertEqual([f.id for f in first], [f.id for f in second], "temuan harus tetap aktif (tidak resolved)")

    def test_rotation_keeps_unscanned_findings(self):
        cfg = self.cfg(LOG_SCAN_MAX_CONTAINERS="1")
        checker = HealthChecker(K8sClient(cfg), cfg)
        ids = set()
        for _ in range(6):  # 4 kandidat container -> semua terpindai setelah beberapa siklus
            _, found = self.findings(cfg, checker)
            ids |= {f.resource.ref() for f in found}
            if "Deployment/shop/pay" in ids:
                break
        self.assertIn("Deployment/shop/pay", ids)
        _, found = self.findings(cfg, checker)
        self.assertIn("Deployment/shop/pay", {f.resource.ref() for f in found},
                      "temuan dari container yang belum giliran dipindai harus dipertahankan")

    def test_diagnostics_insights_and_discord_embed(self):
        cfg = self.cfg(NOTIFY_LOG_LINES="5")
        checker = HealthChecker(K8sClient(cfg), cfg)
        _, found = self.findings(cfg, checker)
        Analyzer(cfg, K8sClient(cfg)).process(found, found, checker.cache)
        f = found[0]
        ins = " ".join(f.extra["insights"])
        self.assertIn("17 baris error", ins)
        self.assertIn("livenessProbe", ins, "probe yang hilang harus disebut")
        self.assertLessEqual(len(f.extra["log_excerpt"]), 5)
        self.assertTrue(all("ERROR" in x or "error" in x for x in f.extra["log_excerpt"]),
                        "potongan log harus berisi baris error, bukan tail log")
        d = f.to_dict() | {"status": "firing", "first_seen": None}
        embed = finding_embed(d, remediation_enabled=False)
        names = [x["name"] for x in embed["fields"]]
        self.assertTrue(any(n.startswith("Baris error di log (pay-6f7b-k2)") for n in names), names)
        self.assertIn("Running & Ready", embed["title"])


if __name__ == "__main__":
    unittest.main()
