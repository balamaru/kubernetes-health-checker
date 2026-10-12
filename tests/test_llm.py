"""Pengujian diagnostik nyata + analisis LLM multi-provider (dengan fake LLM)."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "checker"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fakes import FakeDiscord, FakeK8s, FakeLLM  # noqa: E402
from k8s_checker import llm as llm_mod  # noqa: E402
from k8s_checker import main as cmain  # noqa: E402
from k8s_checker.checks import HealthChecker  # noqa: E402
from k8s_checker.config import Config  # noqa: E402
from k8s_checker.k8s import K8sClient  # noqa: E402
from k8s_checker.llm import extract_json  # noqa: E402
from k8s_checker.redact import redact  # noqa: E402
from k8s_checker.remediation import Analyzer  # noqa: E402
from k8s_checker.state import StateStore  # noqa: E402

SECRETS = ("SuperSecret123", "literal-secret-should-not-leak")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k8s = FakeK8s(free_port()).start()
        cls.llm = FakeLLM(free_port()).start()
        cls.discord = FakeDiscord(free_port()).start()
        cls.notifier_port = free_port()
        env = dict(os.environ, PORT=str(cls.notifier_port), WEBHOOK_AUTH_TOKEN="s3cret",
                   DISCORD_WEBHOOK_URL=f"http://127.0.0.1:{cls.discord.port}/api/webhooks/1/abc",
                   PYTHONPATH=os.path.join(ROOT, "notifier"))
        cls.notifier = subprocess.Popen([sys.executable, "-m", "discord_notifier.main"], env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.notifier_port}/healthz", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        cls._sleep = llm_mod.time.sleep
        llm_mod.time.sleep = lambda s: None

    @classmethod
    def tearDownClass(cls):
        llm_mod.time.sleep = cls._sleep
        cls.notifier.terminate()
        cls.notifier.wait(5)
        for srv in (cls.k8s, cls.llm, cls.discord):
            srv.stop()

    def setUp(self):
        self.llm.requests.clear()
        self.llm.fail = False
        self.llm.fail_code = 500
        self.discord.messages.clear()

    def cfg(self, **kw) -> Config:
        for k in [k for k in os.environ if k.startswith("LLM_")]:
            os.environ.pop(k)
        os.environ.update({
            "CLUSTER_NAME": "uji",
            "K8S_API_SERVER": f"http://127.0.0.1:{self.k8s.port}",
            "K8S_TOKEN": "test-token",
            "NAMESPACES_EXCLUDE": "ignored-ns",
            "NOTIFY_WEBHOOK_URL": f"http://127.0.0.1:{self.notifier_port}/webhook",
            "NOTIFY_WEBHOOK_TOKEN": "s3cret",
            "HEALTH_PORT": "0",
        })
        os.environ.update(kw)
        return Config.from_env()

    def llm_env(self, provider="openai", **kw):
        base = f"http://127.0.0.1:{self.llm.port}" + ("/v1" if provider in ("openai", "openai-compatible", "ollama") else "")
        env = {"LLM_PROVIDER": provider, "LLM_MODEL": "model-x", "LLM_API_KEY": "sk-test-key-1234567890abcdef",
               "LLM_BASE_URL": base}
        env.update(kw)
        return env

    def analyze(self, cfg, check="pod.crashloop"):
        client = K8sClient(cfg)
        checker = HealthChecker(client, cfg)
        result = checker.run()
        target = [f for f in result.findings if f.check == check][:1]
        Analyzer(cfg, client).process(target, result.findings, checker.cache)
        return target[0]


class DiagnosticsWithoutLLM(Base):
    def test_insights_and_logs_from_real_data(self):
        f = self.analyze(self.cfg())
        joined = " ".join(f.extra["insights"])
        self.assertIn("256Mi", joined, "limit memori nyata harus muncul")
        self.assertIn("OutOfMemoryError", joined, "baris error dari log harus muncul")
        self.assertTrue(any("OutOfMemoryError" in ln for ln in f.extra["log_excerpt"]))
        self.assertIsNone(f.analysis)
        dump = json.dumps(f.to_dict())
        for s in SECRETS:
            self.assertNotIn(s, dump)
        self.assertEqual(self.llm.requests, [])

    def test_other_insights(self):
        cfg = self.cfg()
        f = self.analyze(cfg, "pod.unschedulable")
        self.assertIn("24.0Gi", " ".join(f.extra["insights"]))
        f = self.analyze(cfg, "storage.pvc_pending")
        self.assertIn("fast-ssd' TIDAK ditemukan", " ".join(f.extra["insights"]))
        f = self.analyze(cfg, "pod.not_ready")
        self.assertIn("redis:6379", " ".join(f.extra["insights"]))

    def test_discord_shows_insights_without_llm(self):
        store = StateStore()
        cfg = self.cfg()
        client = K8sClient(cfg)
        cmain.run_once(cfg, HealthChecker(client, cfg), store, Analyzer(cfg, client))
        embeds = [e for m in self.discord.messages for e in m["embeds"]]
        crash = next(e for e in embeds if "OOMKilled berulang" in e["title"])
        self.assertIn("Temuan dari data cluster", crash["description"])
        self.assertIn("256Mi", crash["description"])
        self.assertTrue(any(fl["name"] == "Log terakhir" for fl in crash["fields"]))
        self.assertIn("Analisis LLM nonaktif", crash["footer"]["text"])
        raw = json.dumps(self.discord.messages)
        for s in SECRETS:
            self.assertNotIn(s, raw)


class Providers(Base):
    def check_request(self, req):
        body = json.dumps(req["body"])
        self.assertIn("OutOfMemoryError", body, "log nyata harus dikirim ke LLM")
        self.assertIn("256Mi", body, "spec nyata harus dikirim ke LLM")
        for s in SECRETS:
            self.assertNotIn(s, body, "rahasia tidak boleh terkirim ke LLM")

    def run_provider(self, provider, **kw):
        f = self.analyze(self.cfg(**self.llm_env(provider, **kw)))
        self.assertEqual(len(self.llm.requests), 1)
        req = self.llm.requests[0]
        self.check_request(req)
        self.assertEqual(f.analysis["source"], "llm")
        self.assertIn("OutOfMemoryError", f.analysis["root_cause"])
        self.assertEqual(len(f.analysis["remediation"]), 2)
        self.assertEqual(f.analysis["confidence"], "high")
        return req

    def test_openai(self):
        req = self.run_provider("openai")
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["Authorization"], "Bearer sk-test-key-1234567890abcdef")
        self.assertIn("max_completion_tokens", req["body"])
        self.assertEqual(req["body"]["response_format"], {"type": "json_object"})

    def test_openai_compatible_with_extra_headers(self):
        req = self.run_provider("openai-compatible", LLM_EXTRA_HEADERS='{"HTTP-Referer": "https://pajakku.local"}',
                                LLM_TEMPERATURE="0.1")
        self.assertIn("max_tokens", req["body"])
        self.assertEqual(req["body"]["temperature"], 0.1)
        hdrs = {k.lower(): v for k, v in req["headers"].items()}
        self.assertEqual(hdrs["http-referer"], "https://pajakku.local")

    def test_ollama_without_key(self):
        req = self.run_provider("ollama", LLM_API_KEY="")
        self.assertNotIn("Authorization", req["headers"])

    def test_azure(self):
        req = self.run_provider("azure", LLM_API_VERSION="2024-10-21")
        self.assertEqual(req["path"], "/openai/deployments/model-x/chat/completions?api-version=2024-10-21")
        self.assertEqual(req["headers"]["Api-Key"], "sk-test-key-1234567890abcdef")
        self.assertNotIn("model", req["body"])

    def test_anthropic(self):
        req = self.run_provider("anthropic")
        self.assertEqual(req["path"], "/v1/messages")
        self.assertEqual(req["headers"]["X-Api-Key"], "sk-test-key-1234567890abcdef")
        self.assertEqual(req["headers"]["Anthropic-Version"], "2023-06-01")
        self.assertIn("system", req["body"])

    def test_gemini(self):
        req = self.run_provider("gemini")
        self.assertEqual(req["path"], "/models/model-x:generateContent")
        self.assertEqual(req["headers"]["X-Goog-Api-Key"], "sk-test-key-1234567890abcdef")
        self.assertEqual(req["body"]["generationConfig"]["responseMimeType"], "application/json")


class EndToEndWithLLM(Base):
    def test_full_flow_cache_and_discord(self):
        cfg = self.cfg(**self.llm_env("anthropic", LLM_MAX_FINDINGS_PER_RUN="3"))
        client = K8sClient(cfg)
        checker, analyzer, store = HealthChecker(client, cfg), Analyzer(cfg, client), StateStore()
        self.assertTrue(cmain.run_once(cfg, checker, store, analyzer))
        self.assertEqual(len(self.llm.requests), 3, "dibatasi LLM_MAX_FINDINGS_PER_RUN")

        embeds = [e for m in self.discord.messages for e in m["embeds"]]
        analyzed = [e for e in embeds if "Analisis AI" in e["footer"]["text"]]
        self.assertEqual(len(analyzed), 3)
        e = analyzed[0]
        self.assertTrue(e["description"].startswith("**Akar masalah:**"))
        self.assertIn("**Bukti dari cluster:**", e["description"])
        names = [fl["name"] for fl in e["fields"]]
        self.assertIn("Rekomendasi remediasi", names)
        self.assertIn("Perintah", names)
        self.assertTrue(any("dilewati" in x["footer"]["text"] for x in embeds))
        for s in SECRETS:
            self.assertNotIn(s, json.dumps(self.discord.messages))

        # Siklus berikut tanpa perubahan: tidak ada panggilan LLM baru
        self.llm.requests.clear()
        cmain.run_once(cfg, checker, store, analyzer)
        self.assertEqual(self.llm.requests, [])

        # Pengingat: temuan yang sudah dianalisis memakai cache, yang belum dianalisis kini dianalisis
        store.reminder = timedelta(microseconds=1)
        self.discord.messages.clear()
        cmain.run_once(cfg, checker, store, analyzer)
        self.assertEqual(len(self.llm.requests), 3, "hanya temuan yang belum punya analisis")
        reminder_embeds = [e for m in self.discord.messages for e in m["embeds"]]
        self.assertTrue(all("[MASIH TERJADI]" in e["title"] for e in reminder_embeds))
        self.assertEqual(sum("Analisis AI" in e["footer"]["text"] for e in reminder_embeds), 6)

    def test_llm_failure_falls_back_to_rules(self):
        self.llm.fail = True
        cfg = self.cfg(**self.llm_env("openai", LLM_MAX_FINDINGS_PER_RUN="1"))
        client = K8sClient(cfg)
        store = StateStore()
        self.assertTrue(cmain.run_once(cfg, HealthChecker(client, cfg), store, Analyzer(cfg, client)))
        embeds = [e for m in self.discord.messages for e in m["embeds"]]
        failed = [e for e in embeds if "Analisis LLM gagal" in e["footer"]["text"]]
        self.assertEqual(len(failed), 1)
        self.assertIn("**Penjelasan:**", failed[0]["description"])


class Regressions(Base):
    """Kasus dari uji coba nyata di cluster."""

    def test_image_pull_insight_not_masked(self):
        f = self.analyze(self.cfg(), "pod.image_pull")
        text = " ".join(f.extra["insights"])
        self.assertNotIn("***", text)
        self.assertIn("pod tidak memakai imagePullSecrets", text)

    def test_secret_reference_names_visible(self):
        f = self.analyze(self.cfg(), "pod.container_config")
        self.assertNotIn("***", " ".join(f.extra.get("insights") or []))

    def test_provider_missing_is_reported(self):
        cfg = self.cfg(LLM_API_KEY="AIza-test", LLM_MODEL="m")   # LLM_PROVIDER tidak ikut terbaca
        self.assertFalse(cfg.llm_enabled)
        self.assertIn("LLM_PROVIDER kosong", cfg.llm_status)
        client = K8sClient(cfg)
        cmain.run_once(cfg, HealthChecker(client, cfg), StateStore(), Analyzer(cfg, client))
        footer = self.discord.messages[0]["embeds"][0]["footer"]["text"]
        self.assertIn("LLM_PROVIDER kosong", footer)

    def test_model_not_found_hint(self):
        self.llm.fail, self.llm.fail_code = True, 404
        f = self.analyze(self.cfg(**self.llm_env("gemini", LLM_MODEL="gemini-1.5-flash")))
        self.assertIsNone(f.analysis)
        self.assertIn("tidak ditemukan / sudah dihentikan", f.extra["llm_error"])

    def test_manifest_reads_llm_config_from_secret(self):
        import yaml  # noqa: PLC0415 - hanya untuk test ini
        docs = list(yaml.safe_load_all(open(os.path.join(ROOT, "deploy/k8s/checker.yaml"))))
        dep = next(d for d in docs if d["kind"] == "Deployment")
        env_from = dep["spec"]["template"]["spec"]["containers"][0]["envFrom"]
        self.assertIn("configMapRef", env_from[0])
        self.assertEqual(env_from[1]["secretRef"]["name"], "k8s-health-secrets", "Secret harus setelah ConfigMap agar menimpa")


class Units(unittest.TestCase):
    def test_extract_json(self):
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(extract_json('Berikut hasilnya: {"a": {"b": "x}"}} selesai'), {"a": {"b": "x}"}})
        with self.assertRaises(llm_mod.LLMError):
            extract_json("tidak ada json")

    def test_redact(self):
        samples = {
            "password=hunter2xyz": "hunter2xyz",
            "Authorization: Bearer abcdefghijklmnop": "abcdefghijklmnop",
            "mysql://root:toor123@db:3306": "toor123",
            "key sk-ant-api03-abcdefghijklmnopqrstuv": "abcdefghijklmnopqrstuv",
            '"api_key": "AKIAABCDEFGHIJKLMNOP"': "AKIAABCDEFGHIJKLMNOP",
        }
        for text, secret in samples.items():
            self.assertNotIn(secret, redact(text), text)
        self.assertEqual(redact("GET /healthz 200"), "GET /healthz 200")

    def test_config_validation(self):
        base = {"K8S_API_SERVER": "http://x", "K8S_TOKEN": "t"}
        for bad in ({"LLM_PROVIDER": "openai", "LLM_API_KEY": "k"},               # model kosong
                    {"LLM_PROVIDER": "openai", "LLM_MODEL": "m"},                 # key kosong
                    {"LLM_PROVIDER": "openai-compatible", "LLM_MODEL": "m"},      # base url kosong
                    {"LLM_PROVIDER": "foo", "LLM_MODEL": "m"}):
            for k in [k for k in os.environ if k.startswith("LLM_")]:
                os.environ.pop(k)
            os.environ.update({**base, **bad})
            with self.assertRaises(ValueError, msg=str(bad)):
                Config.from_env()
        for k in [k for k in os.environ if k.startswith("LLM_")]:
            os.environ.pop(k)
        os.environ.update({**base, "LLM_PROVIDER": "ollama", "LLM_MODEL": "llama3.1"})
        self.assertTrue(Config.from_env().llm_enabled)
        os.environ["REMEDIATION_ENABLED"] = "false"
        self.assertFalse(Config.from_env().llm_enabled)
        os.environ.pop("REMEDIATION_ENABLED")
        os.environ.pop("LLM_PROVIDER")


if __name__ == "__main__":
    unittest.main()
