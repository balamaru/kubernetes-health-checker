"""Server palsu untuk pengujian lokal: Kubernetes API (berisi skenario error) dan Discord webhook.

Jalankan manual:
    python tests/fakes.py k8s 18443        # fake API server
    python tests/fakes.py discord 19100    # fake Discord (mencetak payload yang diterima)
"""
from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def ts(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def lst(items):
    return {"kind": "List", "metadata": {}, "items": items}


def pod(ns, name, phase="Running", ready=True, labels=None, statuses=None, conditions=None, owner=None,
        created=60, status_extra=None, deletion=None, node="node-1", containers=None):
    conds = conditions if conditions is not None else [
        {"type": "PodScheduled", "status": "True"},
        {"type": "Ready", "status": "True" if ready else "False", "lastTransitionTime": ts(30),
         "message": None if ready else "containers with unready status: [app]"},
    ]
    meta = {"namespace": ns, "name": name, "labels": labels or {}, "creationTimestamp": ts(created)}
    if owner:
        meta["ownerReferences"] = [{"kind": owner, "name": name.rsplit("-", 1)[0]}]
    if deletion:
        meta["deletionTimestamp"] = ts(deletion)
    st = {"phase": phase, "conditions": conds, "containerStatuses": statuses or []}
    st.update(status_extra or {})
    spec = {"nodeName": node, "containers": containers or [{"name": "app", "image": "nginx:1.27"}]}
    return {"metadata": meta, "spec": spec, "status": st}


def cs(name="app", ready=True, restarts=0, waiting=None, last=None, image="nginx:1.27"):
    state = {"waiting": waiting} if waiting else {"running": {"startedAt": ts(5)}}
    return {"name": name, "ready": ready, "restartCount": restarts, "image": image, "state": state,
            "lastState": {"terminated": last} if last else {}}


def scenario() -> dict[str, dict]:
    """Cluster dengan berbagai masalah sekaligus."""
    node_ok = {"metadata": {"name": "node-1"}, "spec": {}, "status": {
        "allocatable": {"cpu": "4", "memory": "16Gi", "pods": "110"},
        "nodeInfo": {"kubeletVersion": "v1.31.2", "containerRuntimeVersion": "containerd://1.7.22"}, "conditions": [
        {"type": "Ready", "status": "True"}, {"type": "MemoryPressure", "status": "False"}]}}
    node_bad = {"metadata": {"name": "node-2"}, "spec": {"unschedulable": True}, "status": {"conditions": [
        {"type": "Ready", "status": "Unknown", "reason": "NodeStatusUnknown",
         "message": "Kubelet stopped posting node status.", "lastTransitionTime": ts(12)},
        {"type": "DiskPressure", "status": "True", "reason": "KubeletHasDiskPressure",
         "message": "kubelet has disk pressure"}]}}
    node_3 = {"metadata": {"name": "node-3"}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}

    pods = [
        pod("default", "web-7d9f-abc", labels={"app": "web"}),
        pod("shop", "api-5c6d-x1", ready=False, labels={"app": "api"}, owner="ReplicaSet", containers=[
            {"name": "app", "image": "registry.local/api:2.3.1", "ports": [{"containerPort": 8080}],
             "resources": {"requests": {"memory": "128Mi", "cpu": "100m"}, "limits": {"memory": "256Mi"}},
             "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pass"}}},
                     {"name": "API_TOKEN", "value": "literal-secret-should-not-leak"}]}], statuses=[
            cs(ready=False, restarts=14, waiting={"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"},
               last={"reason": "OOMKilled", "exitCode": 137, "finishedAt": ts(2)})]),
        pod("shop", "worker-1", ready=False, statuses=[
            cs(ready=False, waiting={"reason": "ImagePullBackOff", "message": "Back-off pulling image \"registry.local/worker:v9\""},
               image="registry.local/worker:v9")]),
        pod("shop", "cfg-1", ready=False, statuses=[
            cs(ready=False, waiting={"reason": "CreateContainerConfigError", "message": "secret \"db-pass\" not found"})]),
        pod("shop", "big-1", phase="Pending", containers=[
            {"name": "app", "image": "big:1", "resources": {"requests": {"memory": "24Gi", "cpu": "2"}}}], conditions=[
            {"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
             "message": "0/3 nodes are available: 1 node(s) had untolerated taint {node.kubernetes.io/unreachable: }, 2 Insufficient memory."}],
            created=20, node=None),
        pod("shop", "slow-1", ready=False, labels={"app": "slow"}, statuses=[cs(ready=False)]),
        pod("batch", "ev-1", phase="Failed", status_extra={"reason": "Evicted", "message": "The node was low on resource: memory."}),
        pod("batch", "ev-2", phase="Failed", status_extra={"reason": "Evicted", "message": "The node was low on resource: ephemeral-storage."}),
        pod("kube-system", "coredns-1", ready=False, labels={"k8s-app": "kube-dns"}, statuses=[cs(ready=False)]),
        pod("kube-system", "coredns-2", ready=False, labels={"k8s-app": "kube-dns"}, statuses=[cs(ready=False)]),
        pod("kube-system", "etcd-cp1", ready=False, labels={"tier": "control-plane", "component": "etcd"}, statuses=[cs(ready=False)]),
        pod("ignored-ns", "noise-1", ready=False, statuses=[cs(ready=False, waiting={"reason": "CrashLoopBackOff"})]),
    ]
    deployments = [
        {"metadata": {"namespace": "shop", "name": "api"}, "spec": {"replicas": 3},
         "status": {"availableReplicas": 0, "readyReplicas": 0, "conditions": [
             {"type": "Available", "status": "False", "message": "Deployment does not have minimum availability."},
             {"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded",
              "message": "ReplicaSet \"api-5c6d\" has timed out progressing."}]}},
        {"metadata": {"namespace": "default", "name": "web"}, "spec": {"replicas": 1},
         "status": {"availableReplicas": 1, "conditions": [{"type": "Available", "status": "True"}]}},
    ]
    daemonsets = [
        {"metadata": {"namespace": "kube-system", "name": "calico-node"},
         "status": {"desiredNumberScheduled": 3, "numberReady": 2, "numberUnavailable": 1, "updatedNumberScheduled": 3}},
    ]
    jobs = [
        {"metadata": {"namespace": "batch", "name": "report-2910"}, "status": {"conditions": [
            {"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded",
             "message": "Job has reached the specified backoff limit", "lastTransitionTime": ts(30)}]}},
    ]
    services = [
        {"metadata": {"namespace": "shop", "name": "api", "creationTimestamp": ts(100)},
         "spec": {"type": "ClusterIP", "selector": {"app": "api"}}},
        {"metadata": {"namespace": "default", "name": "web", "creationTimestamp": ts(100)},
         "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}, "status": {"loadBalancer": {}}},
        {"metadata": {"namespace": "shop", "name": "legacy", "creationTimestamp": ts(100)},
         "spec": {"type": "ClusterIP", "selector": {"app": "legacy"}}},
    ]
    slices = [
        {"metadata": {"namespace": "default", "name": "web-x", "labels": {"kubernetes.io/service-name": "web"}},
         "endpoints": [{"addresses": ["10.0.0.5"], "conditions": {"ready": True}}]},
        {"metadata": {"namespace": "shop", "name": "api-x", "labels": {"kubernetes.io/service-name": "api"}},
         "endpoints": [{"addresses": ["10.0.0.9"], "conditions": {"ready": False}}]},
    ]
    pvcs = [
        {"metadata": {"namespace": "shop", "name": "data-db-0", "creationTimestamp": ts(30)},
         "spec": {"storageClassName": "fast-ssd", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "20Gi"}}},
         "status": {"phase": "Pending"}},
    ]
    events = [
        {"metadata": {"namespace": "shop", "name": "e1"}, "type": "Warning", "reason": "FailedCreatePodSandBox",
         "message": "Failed to create pod sandbox: plugin type=\"calico\" failed (add): error getting ClusterInformation: connection is unauthorized",
         "involvedObject": {"kind": "Pod", "namespace": "shop", "name": "net-1"}, "count": 7, "lastTimestamp": ts(1)},
        {"metadata": {"namespace": "shop", "name": "e2"}, "type": "Warning", "reason": "Unhealthy",
         "message": "Readiness probe failed: HTTP probe failed with statuscode: 503",
         "involvedObject": {"kind": "Pod", "namespace": "shop", "name": "slow-1"}, "count": 40, "lastTimestamp": ts(1)},
        {"metadata": {"namespace": "shop", "name": "e3"}, "type": "Warning", "reason": "FailedMount",
         "message": "MountVolume.SetUp failed for volume \"certs\" : secret \"tls-certs\" not found",
         "involvedObject": {"kind": "Pod", "namespace": "shop", "name": "mount-1"}, "count": 4, "lastTimestamp": ts(3)},
        {"metadata": {"namespace": "shop", "name": "old"}, "type": "Warning", "reason": "FailedMount",
         "message": "old event", "involvedObject": {"kind": "Pod", "namespace": "shop", "name": "old-1"},
         "count": 4, "lastTimestamp": ts(600)},
    ]
    return {
        "/version": {"gitVersion": "v1.31.2"},
        "/api/v1/nodes": lst([node_ok, node_bad, node_3]),
        "/api/v1/pods": lst(pods),
        "/apis/apps/v1/deployments": lst(deployments),
        "/apis/apps/v1/statefulsets": lst([]),
        "/apis/apps/v1/daemonsets": lst(daemonsets),
        "/apis/batch/v1/jobs": lst(jobs),
        "/apis/autoscaling/v2/horizontalpodautoscalers": lst([]),
        "/api/v1/services": lst(services),
        "/apis/discovery.k8s.io/v1/endpointslices": lst(slices),
        "/api/v1/persistentvolumeclaims": lst(pvcs),
        "/api/v1/persistentvolumes": lst([]),
        "/api/v1/events": lst(events),
    }


def healthy_scenario() -> dict[str, dict]:
    s = scenario()
    node = lambda n: {"metadata": {"name": n}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    s["/api/v1/nodes"] = lst([node("node-1"), node("node-2"), node("node-3")])
    s["/api/v1/pods"] = lst([pod("default", "web-1", labels={"app": "web"}),
                             pod("kube-system", "coredns-1", labels={"k8s-app": "kube-dns"})])
    for k in ("/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets", "/apis/batch/v1/jobs",
              "/api/v1/services", "/api/v1/persistentvolumeclaims", "/api/v1/events"):
        s[k] = lst([])
    return s


class FakeK8s:
    """Fake API server. Atribut `mode`: 'problems' | 'healthy' | 'down' | 'unauthorized'."""

    def __init__(self, port: int, token: str = "test-token"):
        self.port, self.token, self.mode = port, token, "problems"
        self.readyz_fail = False
        self.requests: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                path = self.path.split("?")[0]
                outer.requests.append(self.path)
                if outer.mode == "down":
                    self.send_response(503); self.end_headers(); self.wfile.write(b"down"); return
                if self.headers.get("Authorization") != f"Bearer {outer.token}" or outer.mode == "unauthorized":
                    self.send_response(401); self.end_headers(); self.wfile.write(b'{"message":"Unauthorized"}'); return
                if path == "/readyz":
                    if outer.readyz_fail:
                        self.send_response(500); self.end_headers()
                        self.wfile.write(b"[+]ping ok\n[-]etcd failed: reason withheld\nreadyz check failed"); return
                    self.send_response(200); self.end_headers(); self.wfile.write(b"[+]ping ok\nreadyz check passed"); return
                sc = healthy_scenario() if outer.mode == "healthy" else scenario()
                data = sc.get(path)
                if data is None:
                    data = outer.resolve(sc, path, self.path)
                if isinstance(data, str):
                    body = data.encode()
                    self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
                    self.wfile.write(body); return
                if data is None:
                    self.send_response(404); self.end_headers(); self.wfile.write(b'{"message":"not found"}'); return
                body = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), H)

    LOGS = {
        ("shop", "api-5c6d-x1", True): "2026-10-12 starting api v2.3.1\n"
            "connecting to postgres://app:SuperSecret123@db.shop:5432/app\n"
            "loading product cache into memory (2.1 GB)\n"
            "FATAL: java.lang.OutOfMemoryError: Java heap space\n",
        ("shop", "api-5c6d-x1", False): "2026-10-12 starting api v2.3.1\n",
        ("shop", "slow-1", False): "GET /healthz 503 - dependency redis:6379 connection refused\n",
    }

    def resolve(self, sc: dict, path: str, raw: str):
        import re as _re
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(raw).query)
        m = _re.fullmatch(r"/api/v1/namespaces/([^/]+)/pods/([^/]+)/log", path)
        if m:
            return self.LOGS.get((m.group(1), m.group(2), q.get("previous") == ["true"]), "")
        m = _re.fullmatch(r"/api/v1/namespaces/([^/]+)/events", path)
        if m:
            fs = dict(x.split("=", 1) for x in q.get("fieldSelector", [""])[0].split(",") if "=" in x)
            items = [e for e in sc["/api/v1/events"]["items"]
                     if all((e.get("involvedObject") or {}).get(k.split(".")[1]) == v for k, v in fs.items())]
            return lst(items)
        m = _re.fullmatch(r"/apis/storage.k8s.io/v1/storageclasses(?:/([^/]+))?", path)
        if m:
            scs = [{"metadata": {"name": "standard", "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}},
                    "provisioner": "rancher.io/local-path", "volumeBindingMode": "WaitForFirstConsumer"}]
            if m.group(1):
                return next((x for x in scs if x["metadata"]["name"] == m.group(1)), None)
            return lst(scs)
        if path == "/apis/apps/v1/namespaces/shop/replicasets/api-5c6d":
            return {"metadata": {"name": "api-5c6d", "ownerReferences": [{"kind": "Deployment", "name": "api"}]}}
        # GET objek tunggal: /api/v1/namespaces/<ns>/<plural>/<name> atau /apis/<g>/<v>/namespaces/...
        m = _re.fullmatch(r"(/api/v1|/apis/[^/]+/[^/]+)/namespaces/([^/]+)/([^/]+)/([^/]+)", path)
        if m:
            items = (sc.get(f"{m.group(1)}/{m.group(3)}") or {}).get("items") or []
            return next((i for i in items if i["metadata"].get("namespace") == m.group(2)
                         and i["metadata"]["name"] == m.group(4)), None)
        m = _re.fullmatch(r"/api/v1/nodes/([^/]+)", path)
        if m:
            return next((i for i in sc["/api/v1/nodes"]["items"] if i["metadata"]["name"] == m.group(1)), None)
        return None

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()


class FakeLLM:
    """Meniru OpenAI / Azure / Anthropic / Gemini. Mencatat request untuk diperiksa test."""

    ANSWER = {
        "root_cause": "Container app pada pod shop/api-5c6d-x1 kehabisan heap Java (OutOfMemoryError) saat memuat product cache 2.1 GB, sementara memory limit hanya 256Mi.",
        "evidence": ["log: FATAL: java.lang.OutOfMemoryError: Java heap space", "limits.memory=256Mi, exitCode=137"],
        "impact": "Deployment shop/api tidak memiliki replica tersedia sehingga Service api tidak melayani trafik.",
        "remediation": ["Naikkan limits.memory container app menjadi minimal 3Gi", "Batasi ukuran product cache atau set -Xmx sesuai limit"],
        "commands": ["kubectl -n shop logs api-5c6d-x1 -c app --previous", "kubectl -n shop set resources deploy/api -c app --limits=memory=3Gi"],
        "confidence": "high",
        "needs_more_info": "",
    }

    def __init__(self, port: int, fail: bool = False):
        self.port, self.fail, self.fail_code = port, fail, 500
        self.requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if outer.fail:
                    self.send_response(outer.fail_code); self.end_headers()
                    self.wfile.write(b'{"error":{"code":404,"message":"models/x is not found"}}' if outer.fail_code == 404
                                     else b'{"error":"boom"}')
                    return
                text = "```json\n" + json.dumps(outer.ANSWER) + "\n```"
                if self.path.startswith("/v1/messages"):
                    resp = {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 10, "output_tokens": 5}}
                elif ":generateContent" in self.path:
                    resp = {"candidates": [{"content": {"parts": [{"text": text}]}}], "usageMetadata": {"promptTokenCount": 10}}
                else:
                    resp = {"choices": [{"message": {"content": text}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
                data = json.dumps(resp).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()


class FakeDiscord:
    def __init__(self, port: int, rate_limit_first: bool = False, verbose: bool = False):
        self.port = port
        self.messages: list[dict] = []
        self.rate_limit_first = rate_limit_first
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if outer.rate_limit_first:
                    outer.rate_limit_first = False
                    self.send_response(429); self.send_header("Content-Type", "application/json"); self.end_headers()
                    self.wfile.write(b'{"message":"You are being rate limited.","retry_after":0.2,"global":false}')
                    return
                # Validasi batas Discord
                assert len(body.get("embeds", [])) <= 10, "lebih dari 10 embed"
                assert len(body.get("content", "")) <= 2000, "content > 2000"
                total = 0
                for e in body.get("embeds", []):
                    assert len(e["title"]) <= 256 and len(e["description"]) <= 4096
                    total += len(e["title"]) + len(e["description"]) + len(e.get("footer", {}).get("text", ""))
                    for f in e.get("fields", []):
                        assert len(f["value"]) <= 1024 and len(f["name"]) <= 256
                        total += len(f["value"]) + len(f["name"])
                assert total <= 6000, f"total embed {total} > 6000"
                outer.messages.append(body)
                if verbose:
                    print(json.dumps(body, ensure_ascii=False, indent=2), flush=True)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"id":"1"}')

        self.server = ThreadingHTTPServer(("127.0.0.1", port), H)

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()


if __name__ == "__main__":
    kind, port = sys.argv[1], int(sys.argv[2])
    srv = FakeK8s(port) if kind == "k8s" else FakeDiscord(port, verbose=True)
    print(f"fake {kind} di :{port}", flush=True)
    srv.server.serve_forever()
