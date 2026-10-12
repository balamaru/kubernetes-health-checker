"""Basis pengetahuan berbasis aturan: menerjemahkan reason/kode Kubernetes menjadi
penjelasan dalam Bahasa Indonesia (bagian "penjelasan kenapa errornya").

Remediasi TIDAK dibuat di sini — itu tugas modul LLM (saat ini di-skip).
"""
from __future__ import annotations

import re

CONTAINER_WAITING = {
    "CrashLoopBackOff": (
        "Container terus berhenti (crash) setelah dijalankan, sehingga kubelet menahan restart "
        "berikutnya dengan jeda yang makin lama (back-off). Penyebab sebenarnya terlihat dari "
        "alasan terminasi terakhir dan log container sebelumnya."
    ),
    "ImagePullBackOff": (
        "Kubelet gagal menarik image container dan sedang menunggu sebelum mencoba lagi. Umumnya "
        "karena nama/tag image salah, image tidak ada di registry, registry tidak dapat dijangkau "
        "dari node, atau kredensial imagePullSecrets tidak valid."
    ),
    "ErrImagePull": (
        "Percobaan menarik image container gagal. Umumnya karena nama/tag image salah, image "
        "privat tanpa imagePullSecrets yang benar, rate-limit registry, atau masalah DNS/jaringan "
        "dari node ke registry."
    ),
    "InvalidImageName": "Format nama image tidak valid sehingga tidak dapat di-pull sama sekali.",
    "CreateContainerConfigError": (
        "Kubelet tidak dapat menyusun konfigurasi container. Biasanya karena ConfigMap/Secret yang "
        "direferensikan (env/envFrom/volume) tidak ada, atau key di dalamnya tidak ditemukan."
    ),
    "CreateContainerError": (
        "Container runtime gagal membuat container, misalnya nama container bentrok, mount gagal, "
        "atau perintah/entrypoint tidak valid."
    ),
    "RunContainerError": (
        "Container runtime gagal menjalankan proses utama container (entrypoint tidak ditemukan, "
        "izin eksekusi, atau masalah security context)."
    ),
    "ContainerCannotRun": "Runtime tidak dapat menjalankan container — biasanya entrypoint/command tidak valid.",
    "ContainerCreating": (
        "Pod sudah dijadwalkan ke node tetapi container belum juga terbuat. Umumnya tertahan di "
        "proses mount volume (PVC/Secret/ConfigMap), pembuatan sandbox jaringan oleh CNI, atau "
        "pull image yang besar/lambat."
    ),
    "PodInitializing": "Init container belum selesai sehingga container utama belum dijalankan.",
}

TERMINATION_REASON = {
    "OOMKilled": (
        "Proses dimatikan oleh kernel karena memakai memori melebihi limit container "
        "(resources.limits.memory) atau node kehabisan memori."
    ),
    "Error": "Proses utama keluar dengan exit code bukan nol (error dari aplikasi).",
    "ContainerCannotRun": "Runtime tidak dapat menjalankan container.",
    "DeadlineExceeded": "Container melewati batas waktu activeDeadlineSeconds.",
    "Evicted": "Pod dikeluarkan (evicted) dari node.",
    "StartError": "Container gagal start — entrypoint/command tidak dapat dijalankan.",
}

EXIT_CODES = {
    1: "Exit code 1: kesalahan umum aplikasi (exception tidak tertangani, konfigurasi salah, dependensi tidak tersedia).",
    2: "Exit code 2: kesalahan penggunaan perintah/argumen shell.",
    126: "Exit code 126: perintah ditemukan tetapi tidak dapat dieksekusi (izin/format binary).",
    127: "Exit code 127: perintah/entrypoint tidak ditemukan di dalam image.",
    128: "Exit code 128: argumen exit tidak valid.",
    134: "Exit code 134 (SIGABRT): proses melakukan abort, biasanya assertion atau crash runtime.",
    137: "Exit code 137 (SIGKILL): proses dibunuh paksa — umumnya OOM atau liveness probe gagal lalu container dimatikan.",
    139: "Exit code 139 (SIGSEGV): segmentation fault — akses memori tidak valid di aplikasi/library native.",
    143: "Exit code 143 (SIGTERM): proses dihentikan secara normal oleh sinyal TERM (mis. liveness probe gagal atau shutdown).",
}

NODE_CONDITIONS = {
    "Ready": (
        "Kubelet di node tidak melaporkan status sehat. Status Unknown berarti control plane tidak "
        "menerima heartbeat dari kubelet (node mati, kubelet berhenti, atau jaringan node ke API "
        "server terputus). Status False berarti kubelet aktif tetapi menyatakan node tidak siap "
        "(mis. container runtime atau CNI bermasalah)."
    ),
    "MemoryPressure": "Memori yang tersedia di node di bawah ambang eviction; kubelet dapat mengeluarkan pod.",
    "DiskPressure": (
        "Ruang disk/inode di node (rootfs atau imagefs) di bawah ambang eviction; kubelet akan "
        "melakukan garbage collection image dan dapat mengeluarkan pod."
    ),
    "PIDPressure": "Jumlah proses di node mendekati batas; proses baru bisa gagal dibuat.",
    "NetworkUnavailable": (
        "Jaringan node belum dikonfigurasi dengan benar (route/CNI). Pod di node ini kemungkinan "
        "tidak dapat berkomunikasi dengan pod lain."
    ),
}

EVENT_REASONS = {
    "FailedMount": "Volume gagal di-mount ke pod (Secret/ConfigMap tidak ada, PVC belum bound, atau driver storage bermasalah).",
    "FailedAttachVolume": "Volume gagal di-attach ke node — biasanya volume masih ter-attach di node lain atau batas attach node tercapai.",
    "FailedCreatePodSandBox": (
        "Kubelet gagal membuat sandbox pod, paling sering karena plugin CNI gagal menyiapkan jaringan "
        "pod (IP pool habis, CNI daemon tidak berjalan di node)."
    ),
    "NetworkNotReady": "Plugin jaringan (CNI) di node belum siap sehingga pod tidak dapat dibuat.",
    "Unhealthy": "Probe (liveness/readiness/startup) berulang kali gagal — aplikasi tidak merespons sesuai konfigurasi probe.",
    "FailedCreate": "Controller gagal membuat pod/objek turunan — sering karena ResourceQuota, LimitRange, admission webhook, atau PodSecurity menolak.",
    "FailedKillPod": "Kubelet gagal menghentikan pod — container runtime kemungkinan bermasalah.",
    "Evicted": "Pod dikeluarkan oleh kubelet karena node kekurangan resource.",
    "EvictionThresholdMet": "Node mencapai ambang eviction (memori/disk) dan mulai mengeluarkan pod.",
    "SystemOOM": "Kernel node mengalami OOM di level sistem — node kehabisan memori.",
    "OOMKilling": "Kernel node membunuh proses karena kehabisan memori.",
    "NodeNotReady": "Node berubah status menjadi NotReady.",
    "Rebooted": "Node terdeteksi melakukan reboot.",
    "FreeDiskSpaceFailed": "Kubelet gagal membebaskan ruang disk lewat garbage collection image.",
    "ImageGCFailed": "Garbage collection image di node gagal.",
    "ContainerGCFailed": "Garbage collection container di node gagal — sering terkait container runtime.",
    "FailedBinding": "PersistentVolumeClaim tidak menemukan PersistentVolume yang cocok.",
    "ProvisioningFailed": "Provisioner StorageClass gagal membuat volume (kuota cloud, parameter salah, atau CSI driver bermasalah).",
    "FailedComputeMetricsReplicas": "HPA tidak dapat menghitung metrik — metrics-server/adapter tidak tersedia atau resources.requests belum diset.",
    "FailedGetResourceMetric": "HPA gagal mengambil metrik resource — periksa metrics-server.",
    "DNSConfigForming": "Konfigurasi DNS pod melebihi batas (terlalu banyak nameserver/search domain) sehingga sebagian dipotong.",
    "BackOff": "Kubelet menunda restart container/pull image karena kegagalan berulang.",
    "FailedSync": "Kubelet gagal menyinkronkan pod.",
    "FailedPreStopHook": "Hook preStop gagal dijalankan.",
    "FailedPostStartHook": "Hook postStart gagal sehingga container dimatikan.",
    "InvalidDiskCapacity": "Kubelet tidak dapat membaca kapasitas disk image filesystem.",
}

# Event yang sudah tercakup oleh pemeriksaan lain (hindari duplikasi notifikasi)
EVENT_REASONS_COVERED_ELSEWHERE = {"FailedScheduling", "BackOff", "Pulling", "Failed", "NodeNotReady"}
NETWORK_EVENT_REASONS = {"FailedCreatePodSandBox", "NetworkNotReady", "DNSConfigForming"}

CNI_DAEMONSET_PATTERNS = re.compile(
    r"(calico|cilium|flannel|weave|canal|antrea|kube-proxy|aws-node|kube-router|kindnet|ovn|multus|azure-cni|cni)",
    re.IGNORECASE,
)

SCHEDULING_HINTS = [
    (re.compile(r"Insufficient (cpu|memory|ephemeral-storage|nvidia\.com/gpu|[\w./-]+)", re.I),
     lambda m: f"Tidak ada node dengan sisa kapasitas {m.group(1)} yang cukup untuk memenuhi resources.requests pod."),
    (re.compile(r"untolerated taint", re.I),
     lambda m: "Node yang tersedia memiliki taint yang tidak ditoleransi oleh pod (tolerations tidak cocok)."),
    (re.compile(r"didn't match Pod's node affinity|node\(s\) didn't match node selector", re.I),
     lambda m: "nodeSelector/nodeAffinity pod tidak cocok dengan label node mana pun."),
    (re.compile(r"didn't match pod (anti-)?affinity", re.I),
     lambda m: "Aturan podAffinity/podAntiAffinity tidak dapat dipenuhi oleh node yang ada."),
    (re.compile(r"unbound immediate PersistentVolumeClaims|persistentvolumeclaim .* not found", re.I),
     lambda m: "Pod menunggu PersistentVolumeClaim yang belum bound atau tidak ada."),
    (re.compile(r"volume node affinity conflict", re.I),
     lambda m: "Volume berada di zona/node yang berbeda dari node yang memenuhi syarat (volume node affinity conflict)."),
    (re.compile(r"Too many pods", re.I),
     lambda m: "Node sudah mencapai batas maksimum jumlah pod (maxPods)."),
    (re.compile(r"didn't have free ports", re.I),
     lambda m: "hostPort yang diminta pod sudah dipakai di semua node yang memenuhi syarat."),
    (re.compile(r"node\(s\) were unschedulable", re.I),
     lambda m: "Sebagian node dalam keadaan cordon (unschedulable)."),
    (re.compile(r"no nodes available", re.I),
     lambda m: "Tidak ada node yang tersedia di cluster."),
]


def explain_scheduling(message: str) -> str:
    hints = []
    for pattern, fn in SCHEDULING_HINTS:
        m = pattern.search(message or "")
        if m:
            hints.append(fn(m))
    if not hints:
        return "Scheduler belum menemukan node yang memenuhi semua syarat penjadwalan pod."
    return " ".join(dict.fromkeys(hints))


def explain_termination(reason: str | None, exit_code: int | None) -> str:
    parts = []
    if reason and reason in TERMINATION_REASON and reason != "Error":
        parts.append(TERMINATION_REASON[reason])
    if exit_code is not None and exit_code in EXIT_CODES:
        if not (reason == "OOMKilled" and exit_code == 137):
            parts.append(EXIT_CODES[exit_code])
    elif exit_code not in (None, 0):
        parts.append(f"Exit code {exit_code}: proses keluar dengan error spesifik aplikasi.")
    return " ".join(parts)


def explain_api_error(kind: str, message: str) -> str:
    if kind == "unauthorized":
        return (
            "API server menolak token (HTTP 401). Token kemungkinan kedaluwarsa, dicabut, atau "
            "Secret ServiceAccount-nya terhapus."
        )
    if kind == "forbidden":
        return "Token valid tetapi tidak memiliki izin RBAC yang cukup (HTTP 403)."
    if "CERTIFICATE_VERIFY_FAILED" in message or "certificate" in message.lower():
        return "Verifikasi sertifikat TLS API server gagal — CA (K8S_CA_CERT) tidak cocok atau belum diset."
    if "timed out" in message.lower():
        return (
            "Permintaan ke API server melewati batas waktu. Control plane kemungkinan kelebihan beban, "
            "etcd lambat, atau jaringan menuju API server bermasalah."
        )
    return (
        "API server tidak dapat dihubungi. Kemungkinan control plane down (kube-apiserver/etcd), "
        "load balancer API bermasalah, atau jaringan dari service ini ke cluster terputus."
    )
