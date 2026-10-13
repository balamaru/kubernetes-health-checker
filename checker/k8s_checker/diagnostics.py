"""Mengumpulkan data diagnostik NYATA dari cluster untuk setiap temuan (read-only):
spec & status objek, event terkait, log container, kondisi node, owner, endpoint, dsb.

Data ini menjadi dasar analisis LLM (akar masalah + remediasi) dan potongan log
yang ditampilkan di notifikasi. Nilai env/Secret TIDAK pernah dibaca; log disamarkan.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from .config import Config
from .k8s import K8sClient, K8sError
from .models import Finding, parse_time
from .redact import redact, redact_lines

log = logging.getLogger(__name__)

MAX_CONTEXT_CHARS = 14000


# utilities
def _meta(o: dict) -> dict:
    return o.get("metadata") or {}


def _cut(s: Any, n: int = 300) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


_Q = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50,
      "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "m": 1e-3, "n": 1e-9, "u": 1e-6}


def parse_quantity(q: str | int | float | None) -> float:
    if q is None or q == "":
        return 0.0
    if isinstance(q, (int, float)):
        return float(q)
    m = re.fullmatch(r"([+-]?[0-9.]+(?:[eE][+-]?\d+)?)([A-Za-z]*)", str(q).strip())
    if not m:
        return 0.0
    return float(m.group(1)) * _Q.get(m.group(2), 1.0)


def fmt_mem(b: float) -> str:
    for unit, size in (("Gi", 2**30), ("Mi", 2**20), ("Ki", 2**10)):
        if b >= size:
            return f"{b / size:.1f}{unit}"
    return f"{b:.0f}"


def fmt_cpu(c: float) -> str:
    return f"{c * 1000:.0f}m"


def _probe(p: dict | None) -> str | None:
    if not p:
        return None
    if "httpGet" in p:
        h = p["httpGet"]
        how = f"httpGet {h.get('scheme', 'HTTP')} :{h.get('port')}{h.get('path', '/')}"
    elif "tcpSocket" in p:
        how = f"tcpSocket :{p['tcpSocket'].get('port')}"
    elif "exec" in p:
        how = "exec " + _cut(" ".join(p["exec"].get("command") or []), 120)
    elif "grpc" in p:
        how = f"grpc :{p['grpc'].get('port')}"
    else:
        how = "?"
    return (f"{how} initialDelay={p.get('initialDelaySeconds', 0)}s period={p.get('periodSeconds', 10)}s "
            f"timeout={p.get('timeoutSeconds', 1)}s failureThreshold={p.get('failureThreshold', 3)}")


def container_spec_summary(c: dict) -> dict:
    env = []
    for e in c.get("env") or []:
        vf = e.get("valueFrom") or {}
        if "secretKeyRef" in vf:
            src = f"secret:{vf['secretKeyRef'].get('name')}/{vf['secretKeyRef'].get('key')}"
        elif "configMapKeyRef" in vf:
            src = f"configmap:{vf['configMapKeyRef'].get('name')}/{vf['configMapKeyRef'].get('key')}"
        elif "fieldRef" in vf:
            src = f"field:{vf['fieldRef'].get('fieldPath')}"
        elif "resourceFieldRef" in vf:
            src = f"resource:{vf['resourceFieldRef'].get('resource')}"
        else:
            src = "literal"  # nilai sengaja tidak disertakan
        env.append(f"{e.get('name')}<-{src}")
    env_from = []
    for ef in c.get("envFrom") or []:
        if "secretRef" in ef:
            env_from.append(f"secret:{ef['secretRef'].get('name')}")
        if "configMapRef" in ef:
            env_from.append(f"configmap:{ef['configMapRef'].get('name')}")
    return {
        "name": c.get("name"),
        "image": c.get("image"),
        "command": redact(_cut(" ".join(c.get("command") or []), 200)) or None,
        "args": redact(_cut(" ".join(c.get("args") or []), 200)) or None,
        "ports": [f"{p.get('containerPort')}/{p.get('protocol', 'TCP')}" + (f"({p['name']})" if p.get("name") else "")
                  for p in c.get("ports") or []] or None,
        "resources": c.get("resources") or {},
        "livenessProbe": _probe(c.get("livenessProbe")),
        "readinessProbe": _probe(c.get("readinessProbe")),
        "startupProbe": _probe(c.get("startupProbe")),
        "env": env[:40] or None,
        "envFrom": env_from or None,
        "volumeMounts": [f"{v.get('name')}->{v.get('mountPath')}" for v in c.get("volumeMounts") or []][:20] or None,
    }


def _volume_summary(v: dict) -> str:
    for key in ("persistentVolumeClaim", "secret", "configMap", "emptyDir", "hostPath", "projected", "csi", "nfs"):
        if key in v:
            ref = v[key] or {}
            name = ref.get("claimName") or ref.get("secretName") or ref.get("name") or ref.get("path") or ref.get("driver") or ""
            return f"{v.get('name')}: {key}{(' ' + name) if name else ''}"
    return f"{v.get('name')}: {next(iter(k for k in v if k != 'name'), '?')}"


def pod_summary(p: dict, with_spec: bool = True) -> dict:
    m, spec, st = _meta(p), p.get("spec") or {}, p.get("status") or {}
    out: dict[str, Any] = {
        "name": m.get("name"),
        "namespace": m.get("namespace"),
        "owner": [f"{o.get('kind')}/{o.get('name')}" for o in m.get("ownerReferences") or []] or None,
        "node": spec.get("nodeName"),
        "phase": st.get("phase"),
        "reason": st.get("reason"),
        "message": _cut(st.get("message"), 300) or None,
        "qosClass": st.get("qosClass"),
        "created": m.get("creationTimestamp"),
        "conditions": [f"{c.get('type')}={c.get('status')}" + (f" ({c.get('reason')}: {_cut(c.get('message'), 200)})" if c.get("reason") else "")
                       for c in st.get("conditions") or []],
        "containerStatuses": [],
    }
    for cs in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []):
        state = cs.get("state") or {}
        k = next(iter(state), "unknown")
        last = (cs.get("lastState") or {}).get("terminated")
        out["containerStatuses"].append({
            "name": cs.get("name"),
            "ready": cs.get("ready"),
            "restartCount": cs.get("restartCount"),
            "state": {k: {x: _cut(y, 300) for x, y in (state.get(k) or {}).items()}},
            "lastTerminated": {x: _cut(y, 300) for x, y in last.items()} if last else None,
        })
    if with_spec:
        out["containers"] = [container_spec_summary(c) for c in spec.get("containers") or []]
        if spec.get("initContainers"):
            out["initContainers"] = [container_spec_summary(c) for c in spec["initContainers"]]
        out["volumes"] = [_volume_summary(v) for v in spec.get("volumes") or []][:20] or None
        out["nodeSelector"] = spec.get("nodeSelector")
        out["tolerations"] = [f"{t.get('key', '*')}:{t.get('effect', '*')}" for t in spec.get("tolerations") or []][:10] or None
        out["affinity"] = list((spec.get("affinity") or {}).keys()) or None
        out["serviceAccount"] = spec.get("serviceAccountName")
        out["imagePullSecrets"] = [s.get("name") for s in spec.get("imagePullSecrets") or []] or None
        out["priorityClassName"] = spec.get("priorityClassName")
    return out


def _labels_match(labels: dict, selector: dict) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


# collector
class DiagnosticsCollector:
    def __init__(self, client: K8sClient, cfg: Config, cache: dict[str, list[dict]] | None = None):
        self.k = client
        self.cfg = cfg
        self.cache = cache if cache is not None else {}

    # --- akses data (cache dari siklus pemeriksaan bila ada) ---
    def _cached(self, key: str, path: str) -> list[dict]:
        if key not in self.cache:
            self.cache[key] = self.k.list_all(path)
        return self.cache[key]

    def _get(self, path: str) -> dict | None:
        try:
            return self.k.get(path)
        except K8sError as exc:
            if exc.kind in ("notfound", "forbidden"):
                return None
            raise

    def find_pod(self, ns: str, name: str) -> dict | None:
        for p in self.cache.get("pods", []):
            if _meta(p).get("namespace") == ns and _meta(p).get("name") == name:
                return p
        return self._get(f"/api/v1/namespaces/{ns}/pods/{name}")

    def pods_by_selector(self, ns: str, selector: dict) -> list[dict]:
        return [p for p in self._cached("pods", "/api/v1/pods")
                if _meta(p).get("namespace") == ns and _labels_match(_meta(p).get("labels") or {}, selector)]

    def events_for(self, kind: str, name: str, ns: str | None, limit: int = 12) -> list[str]:
        path = f"/api/v1/namespaces/{ns}/events" if ns else "/api/v1/events"
        try:
            items = self.k.list_all(path, {"fieldSelector": f"involvedObject.name={name},involvedObject.kind={kind}"})
        except K8sError as exc:
            return [f"(event tidak dapat dibaca: {exc.kind})"]
        items = [e for e in items if (e.get("involvedObject") or {}).get("name") == name
                 and (e.get("involvedObject") or {}).get("kind") == kind]

        def when(e):
            return parse_time(e.get("lastTimestamp")) or parse_time(e.get("eventTime")) \
                or parse_time(_meta(e).get("creationTimestamp")) or parse_time("1970-01-01T00:00:00Z")
        items.sort(key=when)
        out = []
        for e in items[-limit:]:
            t = e.get("lastTimestamp") or e.get("eventTime") or _meta(e).get("creationTimestamp")
            cnt = e.get("count") or (e.get("series") or {}).get("count") or 1
            out.append(f"{t} {e.get('type')} {e.get('reason')} x{cnt}: {redact(_cut(e.get('message'), 300))}")
        return out

    def logs(self, ns: str, pod: str, container: str, previous: bool) -> list[str] | None:
        if not self.cfg.include_logs:
            return None
        params = {"container": container, "tailLines": self.cfg.log_tail_lines, "limitBytes": 32000,
                  "timestamps": "false"}
        if previous:
            params["previous"] = "true"
        try:
            _, body = self.k.request_raw(f"/api/v1/namespaces/{ns}/pods/{pod}/log", params)
        except K8sError as exc:
            log.debug("Log %s/%s[%s] previous=%s tidak tersedia: %s", ns, pod, container, previous, exc)
            return None
        lines = [ln[:400] for ln in body.splitlines() if ln.strip()]
        return redact_lines(lines[-self.cfg.log_tail_lines:])

    def pod_logs(self, p: dict, container: str | None = None) -> dict[str, dict]:
        """Ambil log container bermasalah: 'previous' bila pernah restart, plus log saat ini."""
        m, st = _meta(p), p.get("status") or {}
        out: dict[str, dict] = {}
        statuses = (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or [])
        targets = [cs for cs in statuses if (container is None and not cs.get("ready")) or cs.get("name") == container]
        if not targets and statuses:
            targets = statuses[:1]
        for cs in targets[:2]:
            name = cs.get("name")
            entry: dict[str, Any] = {}
            waiting = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
            if waiting in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CreateContainerConfigError",
                           "ContainerCreating"):
                continue  # container belum pernah berjalan — tidak ada log
            if cs.get("restartCount", 0) > 0 or (cs.get("lastState") or {}).get("terminated"):
                prev = self.logs(m.get("namespace"), m.get("name"), name, previous=True)
                if prev:
                    entry["previous_container"] = prev
            cur = self.logs(m.get("namespace"), m.get("name"), name, previous=False)
            if cur:
                entry["current"] = cur
            if entry:
                out[name] = entry
        return out

    def node_summary(self, name: str) -> dict | None:
        n = next((x for x in self.cache.get("nodes", []) if _meta(x).get("name") == name), None) \
            or self._get(f"/api/v1/nodes/{name}")
        if not n:
            return None
        st, spec = n.get("status") or {}, n.get("spec") or {}
        alloc = st.get("allocatable") or {}
        req_cpu = req_mem = 0.0
        pods_on = 0
        for p in self._cached("pods", "/api/v1/pods"):
            if (p.get("spec") or {}).get("nodeName") != name or (p.get("status") or {}).get("phase") in ("Succeeded", "Failed"):
                continue
            pods_on += 1
            for c in (p.get("spec") or {}).get("containers") or []:
                r = (c.get("resources") or {}).get("requests") or {}
                req_cpu += parse_quantity(r.get("cpu"))
                req_mem += parse_quantity(r.get("memory"))
        a_cpu, a_mem = parse_quantity(alloc.get("cpu")), parse_quantity(alloc.get("memory"))
        info = st.get("nodeInfo") or {}
        return {
            "name": name,
            "unschedulable": spec.get("unschedulable", False),
            "taints": [f"{t.get('key')}={t.get('value', '')}:{t.get('effect')}" for t in spec.get("taints") or []] or None,
            "conditions": [f"{c.get('type')}={c.get('status')} ({c.get('reason')}) {_cut(c.get('message'), 150)} sejak {c.get('lastTransitionTime')}"
                           for c in st.get("conditions") or []],
            "allocatable": {"cpu": alloc.get("cpu"), "memory": alloc.get("memory"), "pods": alloc.get("pods")},
            "requested": {
                "cpu": f"{fmt_cpu(req_cpu)} ({req_cpu / a_cpu * 100:.0f}%)" if a_cpu else fmt_cpu(req_cpu),
                "memory": f"{fmt_mem(req_mem)} ({req_mem / a_mem * 100:.0f}%)" if a_mem else fmt_mem(req_mem),
                "pods": pods_on,
            },
            "kubelet": info.get("kubeletVersion"),
            "containerRuntime": info.get("containerRuntimeVersion"),
            "os": f"{info.get('osImage')} / kernel {info.get('kernelVersion')}",
        }

    # per jenis temuan
    def collect(self, f: Finding) -> dict:
        ctx: dict[str, Any] = {}
        errors: list[str] = []
        try:
            self._collect_into(f, ctx)
        except K8sError as exc:
            errors.append(f"{exc.kind}: {_cut(str(exc), 200)}")
        except Exception as exc:  # noqa: BLE001
            log.exception("Gagal mengumpulkan diagnostik untuk %s", f.resource.ref())
            errors.append(repr(exc)[:200])
        if errors:
            ctx["collection_errors"] = errors
        return ctx

    def _collect_into(self, f: Finding, ctx: dict) -> None:
        r = f.resource
        kind, ns, name = r.kind, r.namespace, r.name

        if f.check == "pod.log_errors":
            # Resource = workload; diagnostik diambil dari pod dengan error terbanyak.
            ctx["log_error_scan"] = {
                "window_minutes": f.extra.get("window_minutes"),
                "error_lines_total": f.extra.get("error_count"),
                "pods_affected": f.extra.get("pods_affected"),
                "pods_scanned": f.extra.get("pods_scanned"),
                "all_pods_ready": f.extra.get("ready"),
                "top_error_signatures": f.extra.get("signatures"),
                "sample_error_lines": f.extra.get("log_excerpt"),
            }
            p = self.find_pod(ns, f.extra.get("pod") or "")
            if not p:
                ctx["note"] = "Pod sudah tidak ada saat diagnostik dikumpulkan"
                return
            ctx["pod"] = pod_summary(p)
            ctx["events"] = self.events_for("Pod", _meta(p).get("name"), ns)
            cname = f.extra.get("container")
            cur = self.logs(ns, _meta(p).get("name"), cname, previous=False) if cname else None
            if cur:
                ctx["logs"] = {cname: {"current": cur}}
            self._owner_chain(p, ctx)
            return

        if kind == "Pod":
            p = self.find_pod(ns, name)
            if not p:
                ctx["note"] = "Pod sudah tidak ada saat diagnostik dikumpulkan"
                return
            ctx["pod"] = pod_summary(p)
            ctx["events"] = self.events_for("Pod", name, ns)
            ctx["logs"] = self.pod_logs(p, f.extra.get("container"))
            node = (p.get("spec") or {}).get("nodeName")
            if node and f.check in ("pod.crashloop", "pod.oomkilled", "pod.stuck_creating", "pod.stuck_terminating", "pod.evicted"):
                ctx["node"] = self.node_summary(node)
            if f.check == "pod.unschedulable":
                ctx["nodes_capacity"] = [self.node_summary(_meta(n).get("name")) for n in self._cached("nodes", "/api/v1/nodes")[:15]]
            self._owner_chain(p, ctx)
            return

        if kind == "Node":
            ctx["node"] = self.node_summary(name)
            ctx["events"] = self.events_for("Node", name, None)
            problem_pods = [pod_summary(p, with_spec=False) for p in self._cached("pods", "/api/v1/pods")
                            if (p.get("spec") or {}).get("nodeName") == name
                            and (p.get("status") or {}).get("phase") not in ("Running", "Succeeded")][:10]
            if problem_pods:
                ctx["non_running_pods_on_node"] = problem_pods
            return

        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            plural = {"Deployment": "deployments", "StatefulSet": "statefulsets", "DaemonSet": "daemonsets"}[kind]
            obj = self._get(f"/apis/apps/v1/namespaces/{ns}/{plural}/{name}")
            selector = {}
            if obj:
                spec, st = obj.get("spec") or {}, obj.get("status") or {}
                selector = (spec.get("selector") or {}).get("matchLabels") or {}
                tpl = (spec.get("template") or {}).get("spec") or {}
                ctx["workload"] = {
                    "kind": kind, "name": name, "namespace": ns,
                    "replicas": spec.get("replicas"),
                    "strategy": (spec.get("strategy") or spec.get("updateStrategy") or {}).get("type"),
                    "status": {k: v for k, v in st.items() if k != "conditions"},
                    "conditions": [f"{c.get('type')}={c.get('status')} ({c.get('reason')}): {_cut(c.get('message'), 250)}"
                                   for c in st.get("conditions") or []],
                    "template_containers": [container_spec_summary(c) for c in tpl.get("containers") or []],
                }
                ctx["events"] = self.events_for(kind, name, ns)
            if f.check == "network.dns":
                selector = {"k8s-app": "kube-dns"}
            self._pods_with_worst_logs(ns, selector, ctx)
            return

        if kind == "Service":
            svc = self._get(f"/api/v1/namespaces/{ns}/services/{name}")
            if svc:
                spec = svc.get("spec") or {}
                ctx["service"] = {
                    "type": spec.get("type"), "selector": spec.get("selector"),
                    "ports": [f"{p.get('name', '')} {p.get('port')}->{p.get('targetPort')}/{p.get('protocol', 'TCP')}" for p in spec.get("ports") or []],
                    "clusterIP": spec.get("clusterIP"),
                }
                pods = self.pods_by_selector(ns, spec.get("selector") or {})
                ctx["matching_pods"] = [pod_summary(p, with_spec=False) | {
                    "containerPorts": [cp.get("containerPort") for c in (p.get("spec") or {}).get("containers") or [] for cp in c.get("ports") or []]
                } for p in pods[:8]]
                if not pods:
                    # bantu mendeteksi salah ketik label: pod di namespace yang sama
                    ctx["pods_in_namespace_labels"] = [
                        {"name": _meta(p).get("name"), "labels": _meta(p).get("labels")}
                        for p in self._cached("pods", "/api/v1/pods") if _meta(p).get("namespace") == ns][:10]
            ctx["events"] = self.events_for("Service", name, ns)
            return

        if kind == "PersistentVolumeClaim":
            pvc = self._get(f"/api/v1/namespaces/{ns}/persistentvolumeclaims/{name}")
            if pvc:
                spec = pvc.get("spec") or {}
                ctx["pvc"] = {"spec": spec, "status": pvc.get("status"), "annotations": _meta(pvc).get("annotations")}
                sc_name = spec.get("storageClassName")
                if sc_name:
                    sc = self._get(f"/apis/storage.k8s.io/v1/storageclasses/{sc_name}")
                    ctx["storageClass"] = ({"name": sc_name, "provisioner": sc.get("provisioner"),
                                            "volumeBindingMode": sc.get("volumeBindingMode"),
                                            "reclaimPolicy": sc.get("reclaimPolicy")}
                                           if sc else f"StorageClass '{sc_name}' TIDAK ditemukan")
                else:
                    scs = self._get("/apis/storage.k8s.io/v1/storageclasses")
                    if scs:
                        ctx["available_storageclasses"] = [
                            f"{_meta(s).get('name')} ({s.get('provisioner')})"
                            + (" [default]" if (_meta(s).get("annotations") or {}).get("storageclass.kubernetes.io/is-default-class") == "true" else "")
                            for s in scs.get("items") or []]
            ctx["events"] = self.events_for("PersistentVolumeClaim", name, ns)
            return

        if kind == "Job":
            job = self._get(f"/apis/batch/v1/namespaces/{ns}/jobs/{name}")
            if job:
                ctx["job"] = {"spec": {k: (job.get("spec") or {}).get(k) for k in ("backoffLimit", "activeDeadlineSeconds", "completions", "parallelism")},
                              "status": job.get("status")}
            ctx["events"] = self.events_for("Job", name, ns)
            pods = self.pods_by_selector(ns, {"job-name": name}) or self.pods_by_selector(ns, {"batch.kubernetes.io/job-name": name})
            if pods:
                pods.sort(key=lambda p: _meta(p).get("creationTimestamp") or "")
                last = pods[-1]
                ctx["last_pod"] = pod_summary(last)
                ctx["logs"] = self.pod_logs(last)
            return

        if kind == "HorizontalPodAutoscaler":
            hpa = self._get(f"/apis/autoscaling/v2/namespaces/{ns}/horizontalpodautoscalers/{name}")
            if hpa:
                ctx["hpa"] = {"spec": hpa.get("spec"), "status": hpa.get("status")}
            ctx["events"] = self.events_for("HorizontalPodAutoscaler", name, ns)
            return

        if kind == "Namespace" and f.check == "pod.evicted":
            nodes = set()
            for p in self._cached("pods", "/api/v1/pods"):
                if _meta(p).get("namespace") == name and (p.get("status") or {}).get("reason") == "Evicted":
                    if (p.get("spec") or {}).get("nodeName"):
                        nodes.add(p["spec"]["nodeName"])
            ctx["nodes_involved"] = [self.node_summary(n) for n in sorted(nodes)[:5]]
            return

        if kind == "Cluster":
            if f.check != "cluster.api_unreachable":
                ctx["nodes"] = [self.node_summary(_meta(n).get("name")) for n in self._cached("nodes", "/api/v1/nodes")[:15]]
            return

        # Fallback (mis. event pada objek lain)
        ctx["events"] = self.events_for(kind, name, ns)

    def _owner_chain(self, pod: dict, ctx: dict) -> None:
        for o in _meta(pod).get("ownerReferences") or []:
            ns = _meta(pod).get("namespace")
            if o.get("kind") == "ReplicaSet":
                rs = self._get(f"/apis/apps/v1/namespaces/{ns}/replicasets/{o.get('name')}")
                for ro in _meta(rs or {}).get("ownerReferences") or []:
                    if ro.get("kind") == "Deployment":
                        d = self._get(f"/apis/apps/v1/namespaces/{ns}/deployments/{ro.get('name')}")
                        if d:
                            st = d.get("status") or {}
                            ctx["owner_deployment"] = {
                                "name": ro.get("name"),
                                "replicas": (d.get("spec") or {}).get("replicas"),
                                "available": st.get("availableReplicas", 0),
                                "updated": st.get("updatedReplicas", 0),
                                "revision": (_meta(d).get("annotations") or {}).get("deployment.kubernetes.io/revision"),
                                "conditions": [f"{c.get('type')}={c.get('status')} ({c.get('reason')})" for c in st.get("conditions") or []],
                            }
            elif o.get("kind") in ("StatefulSet", "DaemonSet", "Job"):
                ctx["owner"] = f"{o.get('kind')}/{o.get('name')}"

    def _pods_with_worst_logs(self, ns: str, selector: dict, ctx: dict) -> None:
        pods = self.pods_by_selector(ns, selector)
        if not pods:
            ctx["pods"] = "tidak ada pod yang cocok dengan selector"
            return

        def badness(p):
            sts = (p.get("status") or {}).get("containerStatuses") or []
            return (sum(0 if c.get("ready") else 1 for c in sts), sum(c.get("restartCount", 0) for c in sts))
        pods.sort(key=badness, reverse=True)
        ctx["pods"] = [pod_summary(p, with_spec=False) for p in pods[:6]]
        worst = pods[0]
        if badness(worst)[0] > 0:
            ctx["worst_pod_events"] = self.events_for("Pod", _meta(worst).get("name"), ns)
            ctx["worst_pod_logs"] = self.pod_logs(worst)


# helpers
def log_excerpt(ctx: dict, lines: int) -> list[str]:
    """Potongan log paling relevan (previous container lebih dulu) untuk notifikasi."""
    for key in ("logs", "worst_pod_logs"):
        logs = ctx.get(key) or {}
        for _cname, entry in logs.items():
            src = entry.get("previous_container") or entry.get("current")
            if src:
                return src[-lines:]
    return []


def to_prompt_json(ctx: dict, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Serialisasi konteks dengan batas ukuran: potong log lebih dulu bila terlalu besar."""
    def dump(c):
        return json.dumps(c, ensure_ascii=False, default=str, separators=(",", ":"))
    ctx = _prune(ctx)
    text = dump(ctx)
    if len(text) <= max_chars:
        return text
    ctx = json.loads(text)
    for limit in (30, 15, 8):
        for key in ("logs", "worst_pod_logs"):
            for entry in (ctx.get(key) or {}).values():
                for k in list(entry):
                    entry[k] = entry[k][-limit:]
        text = dump(ctx)
        if len(text) <= max_chars:
            return text
    return text[:max_chars] + "…(dipotong)"


def _prune(v):
    """Buang nilai kosong (None, [], {}, "") agar prompt hemat token."""
    if isinstance(v, dict):
        out = {k: _prune(x) for k, x in v.items()}
        return {k: x for k, x in out.items() if x not in (None, [], {}, "")}
    if isinstance(v, list):
        return [_prune(x) for x in v if x not in (None, [], {}, "")]
    return v
