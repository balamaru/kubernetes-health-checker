# Klien REST Kubernetes minimal (stdlib saja), read-only.
from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

from .config import Config

log = logging.getLogger(__name__)

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class K8sError(Exception):
    def __init__(self, message: str, status: int | None = None, kind: str = "error", body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body
        # kind: unreachable | unauthorized | forbidden | notfound | error
        self.kind = kind


class K8sClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.timeout = cfg.request_timeout
        mode = cfg.auth_mode
        if mode == "auto":
            mode = "token" if cfg.api_server else "incluster"
        self.mode = mode

        if mode == "incluster":
            host = os.environ.get("KUBERNETES_SERVICE_HOST")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if not host:
                raise ValueError(
                    "K8S_API_SERVER kosong dan tidak berjalan di dalam cluster "
                    "(KUBERNETES_SERVICE_HOST tidak ada). Set K8S_API_SERVER + K8S_TOKEN."
                )
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            self.base_url = f"https://{host}:{port}"
            self._token_file = cfg.token_file or f"{SA_DIR}/token"
            self._static_token = cfg.token
            ca_file = cfg.ca_cert_file or f"{SA_DIR}/ca.crt"
            self.ssl_ctx = self._build_ssl(ca_file=ca_file, ca_b64=cfg.ca_cert_b64)
        else:
            if not cfg.api_server:
                raise ValueError("K8S_API_SERVER wajib diisi untuk K8S_AUTH_MODE=token")
            if not (cfg.token or cfg.token_file):
                raise ValueError("K8S_TOKEN atau K8S_TOKEN_FILE wajib diisi")
            self.base_url = cfg.api_server
            self._token_file = cfg.token_file
            self._static_token = cfg.token
            self.ssl_ctx = self._build_ssl(ca_file=cfg.ca_cert_file, ca_b64=cfg.ca_cert_b64)

        # Catatan: proxy mengikuti HTTPS_PROXY/NO_PROXY standar bila diset di container.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ssl_ctx)
        )

    # setup
    def _build_ssl(self, ca_file: str = "", ca_b64: str = "") -> ssl.SSLContext | None:
        if not self.base_url_is_https():
            return None
        if self.cfg.insecure_skip_tls_verify:
            log.warning("K8S_INSECURE_SKIP_TLS_VERIFY=true — verifikasi TLS API server dimatikan")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        ctx = ssl.create_default_context()
        if ca_b64:
            pem = base64.b64decode(ca_b64).decode()
            ctx.load_verify_locations(cadata=pem)
        elif ca_file and os.path.exists(ca_file):
            ctx.load_verify_locations(cafile=ca_file)
        return ctx

    def base_url_is_https(self) -> bool:
        url = getattr(self, "base_url", "")
        return url.startswith("https://")

    def _token(self) -> str:
        # Token file dibaca ulang setiap request agar rotasi projected token didukung.
        if self._token_file and os.path.exists(self._token_file):
            with open(self._token_file, encoding="utf-8") as fh:
                return fh.read().strip()
        return self._static_token

    # requests
    def request_raw(self, path: str, params: dict[str, Any] | None = None) -> tuple[int, str]:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(url, method="GET")
        token = self._token()
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "k8s-health-checker/1.0")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            kind = {401: "unauthorized", 403: "forbidden", 404: "notfound"}.get(exc.code, "error")
            raise K8sError(f"HTTP {exc.code} untuk {path}: {body[:500]}", exc.code, kind, body) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise K8sError(f"Tidak dapat terhubung ke {self.base_url}: {reason}", None, "unreachable") from None

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        _, body = self.request_raw(path, params)
        return json.loads(body)

    def list_all(self, path: str, params: dict[str, Any] | None = None, page_size: int = 500) -> list[dict]:
        return list(self.iter_list(path, params, page_size))

    def iter_list(self, path: str, params: dict[str, Any] | None = None, page_size: int = 500) -> Iterator[dict]:
        params = dict(params or {})
        params["limit"] = page_size
        while True:
            data = self.get(path, params)
            yield from data.get("items") or []
            cont = (data.get("metadata") or {}).get("continue")
            if not cont:
                break
            params["continue"] = cont
