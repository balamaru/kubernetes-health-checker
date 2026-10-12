"""Pengujian end-to-end: fake K8s API -> checker -> notifier (proses terpisah) -> fake Discord.

Jalankan:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "checker"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fakes import FakeDiscord, FakeK8s, FakeLLM  # noqa: E402
from k8s_checker import main as cmain  # noqa: E402
from k8s_checker.checks import HealthChecker  # noqa: E402
from k8s_checker.config import Config  # noqa: E402
from k8s_checker.k8s import K8sClient  # noqa: E402
from k8s_checker.remediation import Analyzer  # noqa: E402
from k8s_checker.state import StateStore  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 10) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    raise RuntimeError(f"{url} tidak siap")


class E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k8s = FakeK8s(free_port()).start()
        cls.discord = FakeDiscord(free_port(), rate_limit_first=True).start()
        cls.notifier_port = free_port()
        env = dict(os.environ,
                   PORT=str(cls.notifier_port),
                   DISCORD_WEBHOOK_URL=f"http://127.0.0.1:{cls.discord.port}/api/webhooks/1/abc",
                   WEBHOOK_AUTH_TOKEN="s3cret",
                   DISCORD_MENTION_ON_CRITICAL="@here",
                   PYTHONPATH=os.path.join(ROOT, "notifier"))
        cls.notifier = subprocess.Popen([sys.executable, "-m", "discord_notifier.main"], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        wait_http(f"http://127.0.0.1:{cls.notifier_port}/healthz")

    @classmethod
    def tearDownClass(cls):
        cls.notifier.terminate()
        cls.notifier.wait(5)
        cls.k8s.stop()
        cls.discord.stop()

    def setUp(self):
        self.discord.messages.clear()
        self.k8s.mode = "problems"
        self.k8s.readyz_fail = False

    def cfg(self, **kw) -> Config:
        os.environ.update({
            "CLUSTER_NAME": "uji",
            "K8S_API_SERVER": f"http://127.0.0.1:{self.k8s.port}",
            "K8S_TOKEN": "test-token",
            "NAMESPACES_EXCLUDE": "ignored-ns",
            "NOTIFY_WEBHOOK_URL": f"http://127.0.0.1:{self.notifier_port}/webhook",
            "NOTIFY_WEBHOOK_TOKEN": "s3cret",
            "HEALTH_PORT": "0",
        })
        for k in [k for k in os.environ if k.startswith("LLM_")]:
            os.environ.pop(k)
        for k, v in kw.items():
            os.environ[k] = v
        return Config.from_env()

    def run_cycle(self, cfg, store):
        client = K8sClient(cfg)
        checker = HealthChecker(client, cfg)
        return cmain.run_once(cfg, checker, store, Analyzer(cfg, client))

    # ------------------------------------------------------------------
    def test_detects_problems_and_notifies(self):
        cfg = self.cfg()
        result = HealthChecker(K8sClient(cfg), cfg).run()
        checks = {f.check for f in result.findings}
        expected = {
            "node.not_ready", "node.diskpressure", "node.cordoned", "pod.crashloop", "pod.image_pull",
            "pod.container_config", "pod.unschedulable", "pod.not_ready", "pod.evicted",
            "cluster.control_plane_component", "workload.deployment_unavailable",
            "workload.deployment_rollout_stuck", "network.cni_daemonset", "workload.job_failed",
            "network.dns", "network.service_no_endpoints", "network.lb_pending", "storage.pvc_pending",
            "event.warning",
        }
        self.assertTrue(expected <= checks, f"kurang: {expected - checks}")
        self.assertFalse(any(f.resource.namespace == "ignored-ns" for f in result.findings), "namespace exclude tidak bekerja")
        self.assertEqual(result.check_errors, [])

        crash = next(f for f in result.findings if f.check == "pod.crashloop")
        self.assertIn("OOMKilled", crash.title)
        self.assertIn("memori", crash.explanation)
        unsched = next(f for f in result.findings if f.check == "pod.unschedulable")
        self.assertIn("taint", unsched.explanation)
        self.assertIn("memory", unsched.explanation)
        # Event Unhealthy untuk slow-1 tidak boleh duplikat dengan pod.not_ready
        ev_refs = [f.resource.ref() for f in result.findings if f.check == "event.warning"]
        self.assertNotIn("Pod/shop/slow-1", ev_refs)
        self.assertNotIn("Pod/shop/old-1", ev_refs, "event lama di luar window seharusnya diabaikan")
        # service 'legacy' tanpa pod -> info (default MIN_SEVERITY=warning memfilter)
        legacy = next(f for f in result.findings if f.resource.ref() == "Service/shop/legacy")
        self.assertEqual(legacy.severity, "info")

        store = StateStore(reminder_minutes=60)
        self.assertTrue(self.run_cycle(cfg, store))
        self.assertGreaterEqual(len(self.discord.messages), 2, "seharusnya dipecah ke beberapa pesan")
        first = self.discord.messages[0]
        self.assertTrue(first["content"].startswith("@here"))
        self.assertIn("cluster `uji`", first["content"])
        all_titles = [e["title"] for m in self.discord.messages for e in m["embeds"]]
        self.assertTrue(all("[BARU]" in t for t in all_titles))
        self.assertFalse(any("cordon" in t for t in all_titles), "info seharusnya terfilter")
        e0 = first["embeds"][0]
        self.assertIn("**Penjelasan:**", e0["description"])
        self.assertIn("Analisis LLM nonaktif", e0["footer"]["text"])
        self.assertEqual(e0["color"], 0xE03E3E)

        # Siklus ke-2 tanpa perubahan: tidak ada notifikasi (dedup)
        self.discord.messages.clear()
        self.run_cycle(cfg, store)
        self.assertEqual(self.discord.messages, [])

        # Cluster pulih -> notifikasi RESOLVED (temuan auto_expire tidak dikirim)
        self.k8s.mode = "healthy"
        self.run_cycle(cfg, store)
        titles = [e["title"] for m in self.discord.messages for e in m["embeds"]]
        self.assertTrue(titles and all("[RESOLVED]" in t for t in titles))
        self.assertFalse(any("Event" in t or "Job gagal" in t for t in titles))
        self.assertEqual(store.active, {})

    def test_api_down_then_recovery(self):
        cfg = self.cfg()
        store = StateStore()
        self.run_cycle(cfg, store)
        n_active = len(store.active)
        self.discord.messages.clear()

        self.k8s.mode = "down"
        self.run_cycle(cfg, store)
        titles = [e["title"] for m in self.discord.messages for e in m["embeds"]]
        self.assertEqual(len(titles), 1)
        self.assertIn("API server tidak dapat diakses", titles[0])
        # Temuan lama tidak boleh dianggap resolved selama API down
        self.assertEqual(len(store.active), n_active + 1)

        self.discord.messages.clear()
        self.k8s.mode = "problems"
        self.run_cycle(cfg, store)
        titles = [e["title"] for m in self.discord.messages for e in m["embeds"]]
        self.assertEqual(len(titles), 1)
        self.assertIn("[RESOLVED]", titles[0])

    def test_unauthorized_token_and_readyz(self):
        cfg = self.cfg(K8S_TOKEN="salah")
        result = HealthChecker(K8sClient(cfg), cfg).run()
        self.assertEqual(result.findings[0].check, "cluster.api_unreachable")
        self.assertIn("401", result.findings[0].explanation)

        self.k8s.readyz_fail = True
        cfg = self.cfg(K8S_TOKEN="test-token")
        result = HealthChecker(K8sClient(cfg), cfg).run()
        rz = [f for f in result.findings if f.check == "cluster.apiserver_not_ready"]
        self.assertEqual(len(rz), 1)
        self.assertIn("[-]etcd failed", rz[0].evidence[0])

    def test_notifier_auth_and_validation(self):
        url = f"http://127.0.0.1:{self.notifier_port}/webhook"

        def post(body, token=None):
            req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json",
                                                  **({"Authorization": f"Bearer {token}"} if token else {})})
            try:
                return urllib.request.urlopen(req, timeout=10).status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post({"findings": []}), 401)
        self.assertEqual(post({"findings": []}, "salah"), 401)
        self.assertEqual(post({"x": 1}, "s3cret"), 422)
        req = urllib.request.Request(url + "/test", data=b"", method="POST", headers={"Authorization": "Bearer s3cret"})
        self.assertEqual(urllib.request.urlopen(req, timeout=10).status, 200)
        self.assertIn("Pesan uji", self.discord.messages[-1]["embeds"][0]["title"])

    def test_notifier_down_retries_next_cycle(self):
        cfg = self.cfg(NOTIFY_WEBHOOK_URL="http://127.0.0.1:1/webhook")
        store = StateStore()
        import k8s_checker.sender as sender
        orig = sender.time.sleep
        sender.time.sleep = lambda s: None
        try:
            self.assertFalse(self.run_cycle(cfg, store))
        finally:
            sender.time.sleep = orig
        self.assertTrue(all(t.last_notified is None for t in store.active.values()))
        cfg = self.cfg()
        self.assertTrue(self.run_cycle(cfg, store))
        self.assertTrue(self.discord.messages)

    def test_state_file_persistence(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "state.json")
        cfg = self.cfg()
        store = StateStore(path)
        self.run_cycle(cfg, store)
        self.discord.messages.clear()
        store2 = StateStore(path)  # simulasi restart container
        self.assertEqual(set(store2.active), set(store.active))
        self.run_cycle(cfg, store2)
        self.assertEqual(self.discord.messages, [], "setelah restart tidak boleh kirim ulang temuan yang sama")


if __name__ == "__main__":
    unittest.main()
