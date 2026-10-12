# Service webhook: menerima laporan dari checker lalu meneruskannya ke Discord.
from __future__ import annotations

import hmac
import json
import logging
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import discord

log = logging.getLogger("notifier")
__version__ = "1.1.1"
MAX_BODY = 2 * 1024 * 1024


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return default if raw == "" else raw in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.port = int(os.environ.get("PORT", "8080"))
        self.discord_webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
        self.auth_token = os.environ.get("WEBHOOK_AUTH_TOKEN", "").strip()
        self.username = os.environ.get("DISCORD_USERNAME", "K8s Health Checker").strip()
        self.avatar_url = os.environ.get("DISCORD_AVATAR_URL", "").strip()
        self.mention_critical = os.environ.get("DISCORD_MENTION_ON_CRITICAL", "").strip()
        self.timeout = int(os.environ.get("DISCORD_TIMEOUT", "15"))
        self.max_retries = int(os.environ.get("DISCORD_MAX_RETRIES", "5"))
        self.max_messages = int(os.environ.get("DISCORD_MAX_MESSAGES_PER_REPORT", "5"))
        self.dry_run = _env_bool("DRY_RUN", False)
        self.log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

    def validate(self) -> None:
        if not self.dry_run and not self.discord_webhook_url:
            raise ValueError("DISCORD_WEBHOOK_URL wajib diisi (atau set DRY_RUN=true)")
        if self.discord_webhook_url and not self.discord_webhook_url.startswith(("https://", "http://")):
            raise ValueError("DISCORD_WEBHOOK_URL harus berupa URL http(s)")


S: Settings
SEND_LOCK = threading.Lock()  # serialisasi pengiriman agar rate limit Discord terjaga
STATS = {"received": 0, "delivered": 0, "failed": 0}


def deliver(report: dict) -> int:
    messages = discord.build_messages(
        report, username=S.username, avatar_url=S.avatar_url,
        mention_critical=S.mention_critical, max_messages=S.max_messages,
    )
    if S.dry_run:
        log.info("DRY_RUN — %d pesan tidak dikirim:\n%s", len(messages),
                 json.dumps(messages, ensure_ascii=False, indent=2))
        return len(messages)
    with SEND_LOCK:
        for msg in messages:
            discord.post(S.discord_webhook_url, msg, timeout=S.timeout, max_retries=S.max_retries)
    return len(messages)


SAMPLE_REPORT = {
    "version": 1,
    "cluster": "test",
    "summary": {"active_critical": 0, "active_warning": 1, "new": 1, "reminder": 0, "resolved": 0},
    "remediation_enabled": False,
    "findings": [{
        "id": "test",
        "status": "firing",
        "severity": "warning",
        "category": "pod",
        "title": "Pesan uji dari k8s-health-notifier",
        "explanation": "Jika pesan ini muncul, koneksi notifier ke Discord sudah berfungsi.",
        "resource": {"kind": "Test", "name": "notifier", "ref": "Test/notifier"},
        "evidence": ["ini hanya pesan uji"],
    }],
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"k8s-health-notifier/{__version__}"

    def log_message(self, fmt, *args):
        log.debug("http: " + fmt, *args)

    def _json(self, code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not S.auth_token:
            return True
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else self.headers.get("X-Webhook-Token", "")
        return hmac.compare_digest(token.encode(), S.auth_token.encode())

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/healthz", "/readyz", "/livez"):
            return self._json(200, {"status": "ok", "dry_run": S.dry_run, **STATS})
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path not in ("/webhook", "/webhook/test"):
            return self._json(404, {"error": "not found"})
        if not self._authorized():
            log.warning("Permintaan ditolak (token salah) dari %s", self.client_address[0])
            return self._json(401, {"error": "unauthorized"})

        if path == "/webhook/test":
            report = SAMPLE_REPORT
        else:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._json(413 if length > MAX_BODY else 400, {"error": "body kosong atau terlalu besar"})
            try:
                report = json.loads(self.rfile.read(length))
            except json.JSONDecodeError as exc:
                return self._json(400, {"error": f"JSON tidak valid: {exc}"})
            if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
                return self._json(422, {"error": "payload harus memiliki field 'findings' (list)"})

        STATS["received"] += 1
        try:
            n = deliver(report)
        except discord.DiscordError as exc:
            STATS["failed"] += 1
            log.error("Gagal meneruskan ke Discord: %s", exc)
            return self._json(502, {"error": str(exc)})
        STATS["delivered"] += 1
        log.info("Laporan cluster=%s diteruskan ke Discord (%d temuan, %d pesan)",
                 report.get("cluster"), len(report.get("findings") or []), n)
        return self._json(200, {"status": "delivered", "messages": n})


def main() -> int:
    global S
    S = Settings()
    logging.basicConfig(level=S.log_level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s", stream=sys.stdout)
    try:
        S.validate()
    except ValueError as exc:
        log.error("Konfigurasi tidak valid: %s", exc)
        return 2
    if not S.auth_token:
        log.warning("WEBHOOK_AUTH_TOKEN kosong — endpoint /webhook terbuka tanpa autentikasi")

    srv = ThreadingHTTPServer(("0.0.0.0", S.port), Handler)

    def _stop(signum, _frame):
        log.info("Menerima sinyal %s, berhenti...", signum)
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("k8s-health-notifier %s mendengarkan di :%d (dry_run=%s)", __version__, S.port, S.dry_run)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
