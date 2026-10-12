# Seluruh pemeriksaan kesehatan cluster. Semua operasi read-only (GET/LIST)
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Callable

from . import knowledge as kb
from .config import ALL_CHECKS, Config
from .k8s import K8sClient, K8sError
from .models import Finding, Resource, parse_time, utcnow

log = logging.getLogger(__name__)


def _cond(obj: dict, ctype: str) -> dict | None:
    for c in (obj.get("status") or {}).get("conditions") or []:
        if c.get("type") == ctype:
            return c
    return None


def _meta(obj: dict) -> dict:
    return obj.get("metadata") or {}


def _owner_kinds(obj: dict) -> set[str]:
    return {o.get("kind") for o in _meta(obj).get("ownerReferences") or []}


def _trim(text: str | None, limit: int = 300) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _age_minutes(ts: str | None) -> float:
    dt = parse_time(ts)
    if not dt:
        return 0.0
    return (utcnow() - dt).total_seconds() / 60


class RunResult:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.check_errors: list[str] = []
        self.api_reachable = True
        self.failed_checks: set[str] = set()
        self.stats: dict[str, int] = {}

    def add(self, f: Finding) -> None:
        self.findings.append(f)


class HealthChecker:
    def __init__(self, client: K8sClient, cfg: Config):
        self.k = client
        self.cfg = cfg
        self._cache: dict[str, list[dict]] = {}

    # helpers
    @property
    def cache(self) -> dict[str, list[dict]]:
        """Data list dari siklus terakhir (dipakai ulang oleh collector diagnostik)."""
        return self._cache

    def _list(self, key: str, path: str, params: dict | None = None) -> list[dict]:
        if key not in self._cache:
            self._cache[key] = self.k.list_all(path, params)
        return self._cache[key]

    def _ns_ok(self, obj: dict) -> bool:
        return self.cfg.namespace_allowed(_meta(obj).get("namespace"))

    def pods(self) -> list[dict]:
        return [p for p in self._list("pods", "/api/v1/pods") if self._ns_ok(p)]

    def all_pods(self) -> list[dict]:
        return self._list("pods", "/api/v1/pods")

    def nodes(self) -> list[dict]:
        return self._list("nodes", "/api/v1/nodes")

    # run
    def run(self) -> RunResult:
        self._cache = {}
        result = RunResult()

        # 1. API server harus dapat dijangkau; jika tidak, pemeriksaan lain tidak berarti.
        try:
            version = self.k.get("/version")
            result.stats["server_version"] = version.get("gitVersion", "?")  # type: ignore[assignment]
        except K8sError as exc:
            result.api_reachable = False
            result.add(Finding(
                check="cluster.api_unreachable",
                category="cluster",
                severity="critical",
                title="Kubernetes API server tidak dapat diakses",
                explanation=kb.explain_api_error(exc.kind, str(exc)),
                resource=Resource(kind="Cluster", name=self.cfg.cluster_name),
                evidence=[_trim(str(exc), 500)],
                reason=exc.kind,
                extra={"source": "api"},
            ))
            result.failed_checks = {c for c in ALL_CHECKS}
            return result

        checks: list[tuple[str, Callable[[RunResult], None]]] = [
            ("cluster", self.check_cluster),
            ("nodes", self.check_nodes),
            ("pods", self.check_pods),
            ("workloads", self.check_workloads),
            ("network", self.check_network),
            ("storage", self.check_storage),
            ("events", self.check_events),
        ]
        for name, fn in checks:
            if not self.cfg.check_enabled(name):
                continue
            before = len(result.findings)
            try:
                fn(result)
            except K8sError as exc:
                result.failed_checks.add(name)
                if exc.kind == "unreachable":
                    result.api_reachable = False
                msg = f"Pemeriksaan '{name}' gagal: {exc}"
                log.warning(msg)
                result.check_errors.append(_trim(msg, 300))
            except Exception as exc:  # noqa: BLE001 - satu check gagal tidak boleh menghentikan yang lain
                result.failed_checks.add(name)
                log.exception("Pemeriksaan %s error tak terduga", name)
                result.check_errors.append(f"Pemeriksaan '{name}' error: {exc!r}"[:300])
            for f in result.findings[before:]:
                f.extra.setdefault("source", name)

        result.stats["nodes"] = len(self._cache.get("nodes", []))
        result.stats["pods"] = len(self._cache.get("pods", []))
        return result

    # cluster
    def check_cluster(self, r: RunResult) -> None:
        try:
            _, body = self.k.request_raw("/readyz", {"verbose": "true"})
            failed_lines = [ln for ln in body.splitlines() if ln.startswith("[-]")]
        except K8sError as exc:
            if exc.kind in ("forbidden", "notfound"):
                log.debug("/readyz tidak diizinkan, dilewati")
                failed_lines = []
            elif exc.status in (500, 503):
                # readyz mengembalikan 500 dengan daftar check yang gagal di body
                failed_lines = [ln for ln in exc.body.splitlines() if ln.startswith("[-]")] or [_trim(str(exc), 300)]
            else:
                raise
        if failed_lines:
            r.add(Finding(
                check="cluster.apiserver_not_ready",
                category="cluster",
                severity="critical",
                title="Komponen API server melaporkan tidak siap (/readyz)",
                explanation=(
                    "Endpoint /readyz API server melaporkan satu atau lebih pemeriksaan internal gagal. "
                    "Jika 'etcd' gagal, penyimpanan state cluster bermasalah dan perubahan apa pun dapat gagal; "
                    "jika 'informer-sync' atau 'poststarthook' gagal, API server belum sepenuhnya siap."
                ),
                resource=Resource(kind="Cluster", name=self.cfg.cluster_name),
                evidence=[_trim(ln, 200) for ln in failed_lines[:10]],
                reason="readyz",
            ))

        nodes = self.nodes()
        if not nodes:
            r.add(Finding(
                check="cluster.no_nodes",
                category="cluster",
                severity="critical",
                title="Cluster tidak memiliki node",
                explanation="Tidak ada objek Node yang terdaftar sehingga tidak ada pod yang dapat berjalan.",
                resource=Resource(kind="Cluster", name=self.cfg.cluster_name),
                reason="no_nodes",
            ))
            return
        ready = [n for n in nodes if (_cond(n, "Ready") or {}).get("status") == "True"]
        if not ready:
            r.add(Finding(
                check="cluster.all_nodes_not_ready",
                category="cluster",
                severity="critical",
                title=f"Cluster down: seluruh {len(nodes)} node NotReady",
                explanation=(
                    "Tidak ada satu pun node dalam keadaan Ready. Workload tidak dapat berjalan atau dijadwalkan. "
                    "Biasanya terjadi karena gangguan jaringan besar, control plane tidak menerima heartbeat, "
                    "atau masalah infrastruktur (cloud/hypervisor)."
                ),
                resource=Resource(kind="Cluster", name=self.cfg.cluster_name),
                evidence=[_meta(n).get("name", "?") for n in nodes[:10]],
                reason="all_not_ready",
            ))
        elif len(ready) / len(nodes) < 0.5:
            r.add(Finding(
                check="cluster.majority_nodes_not_ready",
                category="cluster",
                severity="critical",
                title=f"Mayoritas node NotReady ({len(nodes) - len(ready)}/{len(nodes)})",
                explanation="Lebih dari separuh node tidak siap; kapasitas cluster turun drastis dan pod dapat ter-evict.",
                resource=Resource(kind="Cluster", name=self.cfg.cluster_name),
                reason="majority_not_ready",
            ))

        # Komponen control plane (static pod di kube-system, jika terlihat)
        for p in self.all_pods():
            m = _meta(p)
            labels = m.get("labels") or {}
            if m.get("namespace") != "kube-system" or labels.get("tier") != "control-plane":
                continue
            ready_c = _cond(p, "Ready")
            if (ready_c or {}).get("status") != "True" and _age_minutes((ready_c or {}).get("lastTransitionTime")) >= 2:
                comp = labels.get("component", m.get("name"))
                r.add(Finding(
                    check="cluster.control_plane_component",
                    category="cluster",
                    severity="critical",
                    title=f"Komponen control plane tidak Ready: {comp}",
                    explanation=(
                        f"Static pod control plane '{comp}' tidak dalam keadaan Ready. Komponen seperti "
                        "kube-apiserver, etcd, kube-scheduler, atau kube-controller-manager yang tidak sehat "
                        "membuat penjadwalan, rekonsiliasi, atau akses API terganggu."
                    ),
                    resource=Resource(kind="Pod", name=m.get("name", "?"), namespace="kube-system"),
                    evidence=[_trim((ready_c or {}).get("message") or (p.get("status") or {}).get("phase"))],
                    reason=comp,
                ))

    # nodes
    def check_nodes(self, r: RunResult) -> None:
        for n in self.nodes():
            name = _meta(n).get("name", "?")
            res = Resource(kind="Node", name=name)
            ready = _cond(n, "Ready")
            if ready and ready.get("status") != "True":
                state = "Unknown" if ready.get("status") == "Unknown" else "NotReady"
                r.add(Finding(
                    check="node.not_ready",
                    category="node",
                    severity="critical",
                    title=f"Node {state}: {name}",
                    explanation=kb.NODE_CONDITIONS["Ready"],
                    resource=res,
                    evidence=[
                        f"status={ready.get('status')} reason={ready.get('reason')}",
                        _trim(ready.get("message")),
                        f"sejak {ready.get('lastTransitionTime')}",
                    ],
                    reason="Ready",
                ))
            for ctype in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
                c = _cond(n, ctype)
                if c and c.get("status") == "True":
                    is_net = ctype == "NetworkUnavailable"
                    r.add(Finding(
                        check=f"node.{ctype.lower()}",
                        category="network" if is_net else "node",
                        severity="critical" if is_net else "warning",
                        title=f"Node {name} mengalami {ctype}",
                        explanation=kb.NODE_CONDITIONS[ctype],
                        resource=res,
                        evidence=[f"reason={c.get('reason')}", _trim(c.get("message"))],
                        reason=ctype,
                    ))
            if (n.get("spec") or {}).get("unschedulable"):
                r.add(Finding(
                    check="node.cordoned",
                    category="node",
                    severity="info",
                    title=f"Node {name} dalam keadaan cordon (unschedulable)",
                    explanation="Node ditandai unschedulable — pod baru tidak akan dijadwalkan ke node ini. Bisa disengaja (maintenance).",
                    resource=res,
                    reason="cordoned",
                ))

    # pods
    def check_pods(self, r: RunResult) -> None:
        cfg = self.cfg
        window = timedelta(minutes=cfg.event_window_minutes)
        evicted: dict[str, list[str]] = defaultdict(list)

        for p in self.pods():
            m = _meta(p)
            ns, name = m.get("namespace"), m.get("name", "?")
            status = p.get("status") or {}
            phase = status.get("phase")
            res = Resource(kind="Pod", name=name, namespace=ns)
            owners = _owner_kinds(p)

            if m.get("deletionTimestamp"):
                if _age_minutes(m.get("deletionTimestamp")) > 10:
                    r.add(Finding(
                        check="pod.stuck_terminating",
                        category="pod",
                        severity="warning",
                        title=f"Pod tertahan Terminating: {ns}/{name}",
                        explanation=(
                            "Pod sudah dihapus lebih dari 10 menit tetapi belum hilang. Biasanya karena finalizer "
                            "yang tidak selesai, node tempat pod berjalan NotReady, atau container runtime tidak "
                            "merespons sinyal stop."
                        ),
                        resource=res,
                        evidence=[f"deletionTimestamp={m.get('deletionTimestamp')}", f"node={(p.get('spec') or {}).get('nodeName')}"],
                        reason="terminating",
                    ))
                continue

            if phase == "Succeeded":
                continue

            if phase == "Failed":
                if status.get("reason") == "Evicted":
                    evicted[ns].append(f"{name}: {_trim(status.get('message'), 150)}")
                    continue
                if "Job" in owners:
                    continue  # ditangani oleh pemeriksaan Job
                r.add(Finding(
                    check="pod.failed",
                    category="pod",
                    severity="warning",
                    title=f"Pod dalam status Failed: {ns}/{name}",
                    explanation="Semua container di pod telah berhenti dan setidaknya satu keluar dengan error, dan pod tidak akan di-restart.",
                    resource=res,
                    evidence=[f"reason={status.get('reason')}", _trim(status.get("message"))],
                    reason="Failed",
                ))
                continue

            container_problem = False
            statuses = (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or [])
            for cs in statuses:
                cname = cs.get("name")
                state = cs.get("state") or {}
                last = (cs.get("lastState") or {}).get("terminated") or {}
                waiting = state.get("waiting") or {}
                w_reason = waiting.get("reason")
                restarts = cs.get("restartCount", 0)
                last_finished = parse_time(last.get("finishedAt"))
                recent_restart = bool(last_finished and utcnow() - last_finished <= window)

                term_expl = kb.explain_termination(last.get("reason"), last.get("exitCode"))
                last_ev = []
                if last:
                    last_ev.append(
                        f"terminasi terakhir: reason={last.get('reason')} exitCode={last.get('exitCode')} "
                        f"selesai={last.get('finishedAt')}"
                    )
                    if last.get("message"):
                        last_ev.append(_trim(last.get("message")))

                if w_reason == "CrashLoopBackOff" or (restarts >= cfg.pod_restart_threshold and recent_restart):
                    container_problem = True
                    oom = last.get("reason") == "OOMKilled"
                    title = (
                        f"Container OOMKilled berulang: {ns}/{name} [{cname}]" if oom
                        else f"Container crash berulang (CrashLoopBackOff): {ns}/{name} [{cname}]"
                    )
                    r.add(Finding(
                        check="pod.crashloop",
                        category="pod",
                        severity="critical",
                        title=title,
                        explanation=(kb.CONTAINER_WAITING["CrashLoopBackOff"] + (" " + term_expl if term_expl else "")).strip(),
                        resource=res,
                        evidence=[f"container={cname} restartCount={restarts} state={w_reason or 'Running'}"] + last_ev,
                        reason=f"crash:{cname}",
                        extra={"container": cname, "restarts": restarts, "exit_code": last.get("exitCode"),
                               "last_reason": last.get("reason"), "node": (p.get("spec") or {}).get("nodeName")},
                    ))
                    continue

                if w_reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName",
                                "CreateContainerConfigError", "CreateContainerError",
                                "RunContainerError", "ContainerCannotRun"):
                    container_problem = True
                    image_issue = "Image" in w_reason
                    r.add(Finding(
                        check="pod.image_pull" if image_issue else "pod.container_config",
                        category="pod",
                        severity="critical",
                        title=f"{w_reason}: {ns}/{name} [{cname}]",
                        explanation=kb.CONTAINER_WAITING.get(w_reason, "Container gagal dibuat."),
                        resource=res,
                        evidence=[f"container={cname} image={cs.get('image')}", _trim(waiting.get("message"))],
                        reason=f"{'image' if image_issue else 'config'}:{cname}",
                        extra={"container": cname, "image": cs.get("image")},
                    ))
                    continue

                if w_reason in ("ContainerCreating", "PodInitializing") and _age_minutes(m.get("creationTimestamp")) >= cfg.pod_pending_minutes:
                    container_problem = True
                    r.add(Finding(
                        check="pod.stuck_creating",
                        category="pod",
                        severity="warning",
                        title=f"Pod tertahan {w_reason} > {cfg.pod_pending_minutes} menit: {ns}/{name}",
                        explanation=kb.CONTAINER_WAITING[w_reason],
                        resource=res,
                        evidence=[f"container={cname}", f"node={(p.get('spec') or {}).get('nodeName')}",
                                  f"dibuat {m.get('creationTimestamp')}"],
                        reason=f"creating:{cname}",
                    ))
                    continue

                # OOMKilled sekali (belum sampai crashloop) dalam jendela waktu
                if last.get("reason") == "OOMKilled" and recent_restart:
                    container_problem = True
                    r.add(Finding(
                        check="pod.oomkilled",
                        category="pod",
                        severity="warning",
                        title=f"Container OOMKilled: {ns}/{name} [{cname}]",
                        explanation=kb.TERMINATION_REASON["OOMKilled"],
                        resource=res,
                        evidence=[f"container={cname} restartCount={restarts}"] + last_ev,
                        reason=f"oom:{cname}:{last.get('finishedAt')}",
                        auto_expire=True,
                    ))

            if container_problem:
                continue

            if phase == "Pending":
                sched = _cond(p, "PodScheduled")
                if sched and sched.get("status") == "False" and _age_minutes(m.get("creationTimestamp")) >= cfg.pod_pending_minutes:
                    msg = sched.get("message") or ""
                    r.add(Finding(
                        check="pod.unschedulable",
                        category="pod",
                        severity="warning",
                        title=f"Pod tidak dapat dijadwalkan (Pending): {ns}/{name}",
                        explanation=kb.explain_scheduling(msg),
                        resource=res,
                        evidence=[f"reason={sched.get('reason')}", _trim(msg, 500), f"dibuat {m.get('creationTimestamp')}"],
                        reason="unschedulable",
                    ))
                continue

            if phase == "Running":
                ready = _cond(p, "Ready")
                if ready and ready.get("status") == "False" and _age_minutes(ready.get("lastTransitionTime")) >= cfg.pod_not_ready_minutes:
                    not_ready = [cs.get("name") for cs in status.get("containerStatuses") or [] if not cs.get("ready")]
                    r.add(Finding(
                        check="pod.not_ready",
                        category="pod",
                        severity="warning",
                        title=f"Pod Running tetapi tidak Ready > {cfg.pod_not_ready_minutes} menit: {ns}/{name}",
                        explanation=(
                            "Container berjalan tetapi readiness probe terus gagal, sehingga pod dikeluarkan dari "
                            "endpoint Service dan tidak menerima trafik. Biasanya aplikasi belum siap (dependensi "
                            "seperti database tidak terjangkau) atau konfigurasi probe (path/port/timeout) tidak sesuai."
                        ),
                        resource=res,
                        evidence=[f"container tidak ready: {', '.join(filter(None, not_ready)) or '-'}",
                                  _trim(ready.get("message")), f"sejak {ready.get('lastTransitionTime')}"],
                        reason="not_ready",
                    ))

        for ns, items in evicted.items():
            r.add(Finding(
                check="pod.evicted",
                category="pod",
                severity="warning",
                title=f"{len(items)} pod Evicted di namespace {ns}",
                explanation=(
                    "Kubelet mengeluarkan pod karena node kekurangan resource (memori/disk/ephemeral-storage) "
                    "atau pod melebihi limit ephemeral-storage. Pod Evicted tetap tersisa sebagai objek Failed "
                    "sampai dihapus."
                ),
                resource=Resource(kind="Namespace", name=ns),
                evidence=items[:8] + ([f"... dan {len(items) - 8} lainnya"] if len(items) > 8 else []),
                reason="evicted",
                extra={"count": len(items)},
            ))

    # workloads
    def check_workloads(self, r: RunResult) -> None:
        cfg = self.cfg
        for d in self._list("deployments", "/apis/apps/v1/deployments"):
            if not self._ns_ok(d):
                continue
            m, spec, st = _meta(d), d.get("spec") or {}, d.get("status") or {}
            ns, name = m.get("namespace"), m.get("name")
            desired = spec.get("replicas", 1)
            if desired == 0:
                continue
            available = st.get("availableReplicas", 0) or 0
            res = Resource(kind="Deployment", name=name, namespace=ns)
            avail_c = _cond(d, "Available")
            prog_c = _cond(d, "Progressing")
            if avail_c and avail_c.get("status") == "False":
                r.add(Finding(
                    check="workload.deployment_unavailable",
                    category="workload",
                    severity="critical" if available == 0 else "warning",
                    title=(f"Deployment tidak memiliki replica tersedia: {ns}/{name}" if available == 0
                           else f"Deployment kekurangan replica: {ns}/{name} ({available}/{desired})"),
                    explanation=(
                        "Jumlah replica yang tersedia di bawah batas minimum (replicas - maxUnavailable). "
                        "Layanan dapat terganggu sebagian atau total. Lihat temuan pod terkait untuk penyebab detail."
                    ),
                    resource=res,
                    evidence=[f"available={available} ready={st.get('readyReplicas', 0)} desired={desired}",
                              _trim(avail_c.get("message"))],
                    reason="unavailable",
                ))
            if prog_c and prog_c.get("reason") == "ProgressDeadlineExceeded":
                r.add(Finding(
                    check="workload.deployment_rollout_stuck",
                    category="workload",
                    severity="warning",
                    title=f"Rollout Deployment macet (ProgressDeadlineExceeded): {ns}/{name}",
                    explanation=(
                        "Rollout tidak mengalami kemajuan dalam progressDeadlineSeconds. Pod versi baru kemungkinan "
                        "gagal start/ready (crash, image salah, kuota tidak cukup) sehingga rollout tertahan."
                    ),
                    resource=res,
                    evidence=[_trim(prog_c.get("message")), f"updated={st.get('updatedReplicas', 0)} desired={desired}"],
                    reason="rollout_stuck",
                ))

        for s in self._list("statefulsets", "/apis/apps/v1/statefulsets"):
            if not self._ns_ok(s):
                continue
            m, spec, st = _meta(s), s.get("spec") or {}, s.get("status") or {}
            desired = spec.get("replicas", 1)
            ready = st.get("readyReplicas", 0) or 0
            if desired and ready < desired and st.get("currentRevision") == st.get("updateRevision"):
                r.add(Finding(
                    check="workload.statefulset_degraded",
                    category="workload",
                    severity="critical" if ready == 0 else "warning",
                    title=f"StatefulSet tidak lengkap: {m.get('namespace')}/{m.get('name')} ({ready}/{desired} ready)",
                    explanation=(
                        "Sebagian replica StatefulSet tidak Ready. Karena StatefulSet membuat pod secara berurutan, "
                        "satu pod yang bermasalah (mis. PVC tidak bound atau crash) dapat menahan pod berikutnya."
                    ),
                    resource=Resource(kind="StatefulSet", name=m.get("name"), namespace=m.get("namespace")),
                    evidence=[f"ready={ready} current={st.get('currentReplicas', 0)} desired={desired}"],
                    reason="degraded",
                ))

        for ds in self._list("daemonsets", "/apis/apps/v1/daemonsets"):
            if not self._ns_ok(ds):
                continue
            m, st = _meta(ds), ds.get("status") or {}
            desired = st.get("desiredNumberScheduled", 0) or 0
            ready = st.get("numberReady", 0) or 0
            unavailable = st.get("numberUnavailable", 0) or 0
            rolling = (st.get("updatedNumberScheduled", desired) or 0) < desired
            misscheduled = st.get("numberMisscheduled", 0) or 0
            if desired and (unavailable > 0 or ready < desired) and not rolling:
                is_cni = bool(kb.CNI_DAEMONSET_PATTERNS.search(m.get("name", "")))
                r.add(Finding(
                    check="network.cni_daemonset" if is_cni else "workload.daemonset_degraded",
                    category="network" if is_cni else "workload",
                    severity="critical" if is_cni or ready == 0 else "warning",
                    title=(f"Komponen jaringan cluster (CNI/kube-proxy) tidak sehat: {m.get('namespace')}/{m.get('name')} ({ready}/{desired})"
                           if is_cni else f"DaemonSet tidak lengkap: {m.get('namespace')}/{m.get('name')} ({ready}/{desired})"),
                    explanation=(
                        "DaemonSet jaringan (CNI/kube-proxy) tidak berjalan di semua node. Pod di node terdampak "
                        "dapat kehilangan konektivitas antar-pod, gagal mendapatkan IP, atau Service ClusterIP "
                        "tidak dapat diakses dari node tersebut."
                        if is_cni else
                        "Pod DaemonSet tidak berjalan/ready di semua node yang seharusnya — fungsi per-node "
                        "(logging, monitoring, storage driver, dll.) tidak tersedia di node terdampak."
                    ),
                    resource=Resource(kind="DaemonSet", name=m.get("name"), namespace=m.get("namespace")),
                    evidence=[f"desired={desired} ready={ready} unavailable={unavailable} misscheduled={misscheduled}"],
                    reason="degraded",
                ))

        lookback = timedelta(hours=cfg.job_failed_lookback_hours)
        for j in self._list("jobs", "/apis/batch/v1/jobs"):
            if not self._ns_ok(j):
                continue
            c = _cond(j, "Failed")
            if not c or c.get("status") != "True":
                continue
            when = parse_time(c.get("lastTransitionTime"))
            if when and utcnow() - when > lookback:
                continue
            m = _meta(j)
            reason = c.get("reason", "Failed")
            expl = {
                "BackoffLimitExceeded": "Job gagal karena pod-nya gagal melebihi backoffLimit. Lihat log pod Job terakhir untuk penyebab error aplikasi.",
                "DeadlineExceeded": "Job melewati activeDeadlineSeconds sebelum selesai sehingga dihentikan.",
                "PodFailurePolicy": "Job dihentikan oleh aturan podFailurePolicy.",
            }.get(reason, "Job berakhir dengan status Failed.")
            owner = ", ".join(f"{o.get('kind')}/{o.get('name')}" for o in m.get("ownerReferences") or [])
            r.add(Finding(
                check="workload.job_failed",
                category="workload",
                severity="warning",
                title=f"Job gagal ({reason}): {m.get('namespace')}/{m.get('name')}",
                explanation=expl,
                resource=Resource(kind="Job", name=m.get("name"), namespace=m.get("namespace")),
                evidence=[_trim(c.get("message")), f"waktu={c.get('lastTransitionTime')}"] + ([f"owner={owner}"] if owner else []),
                reason=reason,
                auto_expire=True,
            ))

        try:
            hpas = self._list("hpas", "/apis/autoscaling/v2/horizontalpodautoscalers")
        except K8sError as exc:
            if exc.kind != "notfound":
                raise
            hpas = []
        for h in hpas:
            if not self._ns_ok(h):
                continue
            m = _meta(h)
            for ctype in ("ScalingActive", "AbleToScale"):
                c = _cond(h, ctype)
                if c and c.get("status") == "False" and c.get("reason") not in ("ScalingDisabled",):
                    r.add(Finding(
                        check="workload.hpa_not_scaling",
                        category="workload",
                        severity="warning",
                        title=f"HPA tidak dapat melakukan scaling: {m.get('namespace')}/{m.get('name')}",
                        explanation=(
                            "HorizontalPodAutoscaler tidak dapat menghitung atau menerapkan scaling. Umumnya "
                            "metrics-server tidak tersedia, resources.requests belum diset pada container target, "
                            "atau target scaleRef tidak ditemukan."
                        ),
                        resource=Resource(kind="HorizontalPodAutoscaler", name=m.get("name"), namespace=m.get("namespace")),
                        evidence=[f"{ctype}=False reason={c.get('reason')}", _trim(c.get("message"))],
                        reason=ctype,
                    ))
                    break

    # network
    def check_network(self, r: RunResult) -> None:
        cfg = self.cfg
        pods_all = self.all_pods()

        # 1. DNS cluster (CoreDNS / kube-dns)
        dns_pods = [p for p in pods_all
                    if _meta(p).get("namespace") == "kube-system"
                    and (_meta(p).get("labels") or {}).get("k8s-app") == "kube-dns"]
        if dns_pods:
            ready = [p for p in dns_pods if (_cond(p, "Ready") or {}).get("status") == "True"]
            if len(ready) < len(dns_pods):
                r.add(Finding(
                    check="network.dns",
                    category="network",
                    severity="critical" if not ready else "warning",
                    title=("DNS cluster DOWN: tidak ada pod CoreDNS/kube-dns yang Ready" if not ready
                           else f"DNS cluster terdegradasi: {len(ready)}/{len(dns_pods)} pod CoreDNS Ready"),
                    explanation=(
                        "Resolusi nama di dalam cluster (service.namespace.svc.cluster.local) bergantung pada "
                        "CoreDNS. Jika tidak ada pod DNS yang Ready, hampir semua komunikasi antar-service yang "
                        "memakai nama DNS akan gagal; jika sebagian, sebagian query DNS bisa timeout."
                    ),
                    resource=Resource(kind="Deployment", name="coredns", namespace="kube-system"),
                    evidence=[f"{_meta(p).get('name')}: phase={(p.get('status') or {}).get('phase')} "
                              f"ready={(_cond(p, 'Ready') or {}).get('status')}" for p in dns_pods[:6]],
                    reason="dns",
                ))
        else:
            log.debug("Pod kube-dns tidak ditemukan (label k8s-app=kube-dns), pemeriksaan DNS dilewati")

        # 2. Service tanpa endpoint yang siap
        services = [s for s in self._list("services", "/api/v1/services") if self._ns_ok(s)]
        ready_by_svc = self._ready_endpoints_by_service()
        pods_by_ns: dict[str, list[dict]] = defaultdict(list)
        for p in pods_all:
            pods_by_ns[_meta(p).get("namespace")].append(p)

        for s in services:
            m, spec = _meta(s), s.get("spec") or {}
            ns, name = m.get("namespace"), m.get("name")
            selector = spec.get("selector") or {}
            stype = spec.get("type", "ClusterIP")
            if stype == "ExternalName" or not selector:
                continue
            if ready_by_svc is not None and ready_by_svc.get((ns, name), 0) == 0:
                matching = [p for p in pods_by_ns.get(ns, [])
                            if all((_meta(p).get("labels") or {}).get(k) == v for k, v in selector.items())
                            and (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed")]
                if not matching:
                    sev, why = "info", (
                        "Tidak ada pod yang cocok dengan selector Service. Bisa disengaja (workload di-scale ke 0) "
                        "atau selector/label salah ketik sehingga Service tidak pernah mendapat backend."
                    )
                else:
                    sev, why = "warning", (
                        f"Ada {len(matching)} pod yang cocok dengan selector, tetapi tidak satu pun Ready. "
                        "Trafik ke Service ini akan gagal (connection refused/timeout) sampai pod backend Ready."
                    )
                r.add(Finding(
                    check="network.service_no_endpoints",
                    category="network",
                    severity=sev,
                    title=f"Service tanpa endpoint yang siap: {ns}/{name}",
                    explanation=why,
                    resource=Resource(kind="Service", name=name, namespace=ns),
                    evidence=[f"type={stype} selector={selector}", f"pod cocok={len(matching)}"],
                    reason="no_endpoints",
                ))

            if stype == "LoadBalancer":
                ingress = ((s.get("status") or {}).get("loadBalancer") or {}).get("ingress")
                if not ingress and _age_minutes(m.get("creationTimestamp")) >= cfg.lb_pending_minutes:
                    r.add(Finding(
                        check="network.lb_pending",
                        category="network",
                        severity="warning",
                        title=f"LoadBalancer belum mendapat IP eksternal: {ns}/{name}",
                        explanation=(
                            "Service type LoadBalancer belum mendapat alamat eksternal. Cloud controller manager / "
                            "load balancer controller (mis. MetalLB) tidak berjalan, kuota IP habis, atau anotasi "
                            "service tidak valid."
                        ),
                        resource=Resource(kind="Service", name=name, namespace=ns),
                        evidence=[f"dibuat {m.get('creationTimestamp')}"],
                        reason="lb_pending",
                    ))

    def _ready_endpoints_by_service(self) -> dict[tuple[str, str], int] | None:
        counts: dict[tuple[str, str], int] = defaultdict(int)
        try:
            slices = self._list("endpointslices", "/apis/discovery.k8s.io/v1/endpointslices")
            for es in slices:
                m = _meta(es)
                svc = (m.get("labels") or {}).get("kubernetes.io/service-name")
                if not svc:
                    continue
                key = (m.get("namespace"), svc)
                counts[key] += 0
                for ep in es.get("endpoints") or []:
                    if (ep.get("conditions") or {}).get("ready", True):
                        counts[key] += len(ep.get("addresses") or [])
            return counts
        except K8sError as exc:
            if exc.kind not in ("notfound", "forbidden"):
                raise
        try:
            for ep in self._list("endpoints", "/api/v1/endpoints"):
                m = _meta(ep)
                key = (m.get("namespace"), m.get("name"))
                counts[key] += sum(len(sub.get("addresses") or []) for sub in ep.get("subsets") or [])
            return counts
        except K8sError as exc:
            log.warning("Tidak dapat membaca Endpoints: %s", exc)
            return None

    # storage
    def check_storage(self, r: RunResult) -> None:
        cfg = self.cfg
        for pvc in self._list("pvcs", "/api/v1/persistentvolumeclaims"):
            if not self._ns_ok(pvc):
                continue
            m, st, spec = _meta(pvc), pvc.get("status") or {}, pvc.get("spec") or {}
            phase = st.get("phase")
            res = Resource(kind="PersistentVolumeClaim", name=m.get("name"), namespace=m.get("namespace"))
            if phase == "Lost":
                r.add(Finding(
                    check="storage.pvc_lost",
                    category="storage",
                    severity="critical",
                    title=f"PVC kehilangan volume (Lost): {m.get('namespace')}/{m.get('name')}",
                    explanation="PersistentVolume yang terikat ke PVC ini sudah tidak ada. Data dapat hilang dan pod yang memakainya tidak dapat berjalan.",
                    resource=res,
                    evidence=[f"volumeName={spec.get('volumeName')}"],
                    reason="Lost",
                ))
            elif phase == "Pending" and _age_minutes(m.get("creationTimestamp")) >= cfg.pvc_pending_minutes:
                mode = (m.get("annotations") or {}).get("volume.kubernetes.io/selected-node")
                r.add(Finding(
                    check="storage.pvc_pending",
                    category="storage",
                    severity="warning",
                    title=f"PVC belum bound (Pending): {m.get('namespace')}/{m.get('name')}",
                    explanation=(
                        "PVC belum terikat ke PersistentVolume. StorageClass tidak ada/salah, provisioner (CSI) "
                        "tidak berjalan, tidak ada PV statis yang cocok (ukuran/accessMode), atau StorageClass "
                        "memakai WaitForFirstConsumer dan belum ada pod yang memakainya."
                    ),
                    resource=res,
                    evidence=[f"storageClassName={spec.get('storageClassName')} accessModes={spec.get('accessModes')} "
                              f"request={((spec.get('resources') or {}).get('requests') or {}).get('storage')}"]
                    + ([f"selected-node={mode}"] if mode else []),
                    reason="Pending",
                ))

        for pv in self._list("pvs", "/api/v1/persistentvolumes"):
            st = pv.get("status") or {}
            if st.get("phase") == "Failed":
                m = _meta(pv)
                r.add(Finding(
                    check="storage.pv_failed",
                    category="storage",
                    severity="warning",
                    title=f"PersistentVolume Failed: {m.get('name')}",
                    explanation="Reclamation otomatis PersistentVolume gagal (biasanya saat menghapus volume di backend storage).",
                    resource=Resource(kind="PersistentVolume", name=m.get("name")),
                    evidence=[_trim(st.get("message"))],
                    reason="Failed",
                ))

    # events
    def check_events(self, r: RunResult) -> None:
        cfg = self.cfg
        window = timedelta(minutes=cfg.event_window_minutes)
        now = utcnow()
        groups: dict[tuple, dict] = {}
        # Objek yang sudah punya temuan spesifik tidak perlu dilaporkan ulang lewat event
        already = {f.resource.ref() for f in r.findings}
        for ev in self._list("events", "/api/v1/events", {"fieldSelector": "type=Warning"}):
            reason = ev.get("reason") or ""
            if reason in kb.EVENT_REASONS_COVERED_ELSEWHERE or reason not in kb.EVENT_REASONS:
                continue
            obj = ev.get("involvedObject") or {}
            ns = obj.get("namespace") or _meta(ev).get("namespace")
            if not cfg.namespace_allowed(ns):
                continue
            last = parse_time(ev.get("lastTimestamp")) or parse_time(ev.get("eventTime")) \
                or parse_time((ev.get("series") or {}).get("lastObservedTime")) or parse_time(_meta(ev).get("creationTimestamp"))
            if not last or now - last > window:
                continue
            count = ev.get("count") or (ev.get("series") or {}).get("count") or 1
            if Resource(kind=obj.get("kind") or "", name=obj.get("name") or "", namespace=ns).ref() in already:
                continue
            key = (reason, obj.get("kind"), ns, obj.get("name"))
            g = groups.setdefault(key, {"count": 0, "messages": [], "last": last})
            g["count"] += count
            msg = _trim(ev.get("message"), 250)
            if msg and msg not in g["messages"]:
                g["messages"].append(msg)
            g["last"] = max(g["last"], last)

        for (reason, kind, ns, name), g in groups.items():
            # Probe gagal sesekali itu wajar — perlu minimal N kejadian
            if reason == "Unhealthy" and g["count"] < cfg.event_min_count:
                continue
            is_net = reason in kb.NETWORK_EVENT_REASONS
            critical = reason in ("SystemOOM", "FailedCreatePodSandBox", "NetworkNotReady")
            r.add(Finding(
                check="event.warning",
                category="network" if is_net else "event",
                severity="critical" if critical else "warning",
                title=f"Event {reason} ({g['count']}x): {kind}/{ns + '/' if ns else ''}{name}",
                explanation=kb.EVENT_REASONS.get(reason, ""),
                resource=Resource(kind=kind or "Unknown", name=name or "?", namespace=ns),
                evidence=g["messages"][:3] + [f"terakhir {g['last'].isoformat()}"],
                reason=reason,
                auto_expire=True,
            ))
