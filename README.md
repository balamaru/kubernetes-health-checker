# K8s Health Checker → Discord

**Versi 1.2.0**

Service untuk melakukan health check pada cluster Kubernetes (token **read-only**) dan mengirim laporan ke Discord berisi:

1. **Ada masalah apa**: judul temuan (cluster down, node NotReady, pod CrashLoopBackOff, DNS/CNI bermasalah, dsb.)
2. **Kenapa error**: dianalisis dari **data nyata cluster**, yaitu spec container (limit/request, probe, referensi Secret/ConfigMap), event objek, **log container sebelum crash**, kondisi & kapasitas node, status owner (Deployment/Job), endpoint Service, dan StorageClass.
3. **Remediasi**: langkah perbaikan spesifik untuk objek tersebut beserta perintah `kubectl`, dihasilkan oleh **LLM yang digunakan** (lihat [Kompatibilitas LLM](#kompatibilitas-llm)).

4. **Pod "Running" yang sebenarnya error**: pod yang terlihat sehat di `kubectl get pods` (Running, bahkan Ready, restart 0) tetapi log aplikasinya terus mencatat ERROR ikut dilaporkan (lihat [Pemindaian log](#pemindaian-log-pod-runningready)).

Tanpa LLM notifikasi tetap memuat **temuan dari data cluster** (mis. "memory limit 256Mi terlampaui", baris error dari log, targetPort tidak cocok, StorageClass tidak ada) dan potongan log, bukan sekadar template.

## Daftar isi

- [Arsitektur](#arsitektur)
- [Kompatibilitas](#kompatibilitas)
- [Apa saja yang diperiksa](#apa-saja-yang-diperiksa)
- [Pemindaian log pod Running/Ready](#pemindaian-log-pod-runningready)
- [Analisis & remediasi](#analisis--remediasi)
- [Menjalankan dengan Docker Compose](#menjalankan-dengan-docker-compose-checker-di-luar-cluster)
- [Deploy di dalam cluster](#deploy-di-dalam-cluster)
- [Token & kredensial](#token--kredensial)
- [Environment variable](#environment-variable)
- [Format pesan Discord](#format-pesan-discord)
- [Endpoint HTTP](#endpoint-http)
- [Troubleshooting](#troubleshooting)
- [Upgrade dari 1.0.0](#upgrade-dari-100--110)
- [Pengujian lokal](#pengujian-lokal)
- [Struktur proyek](#struktur-proyek)

## Arsitektur

```
                         GET/LIST + pods/log (read-only)
┌────────────────────────┐ ─────────────────────────▶ ┌────────────────────┐
│ checker (service utama)│                            │ Kubernetes API     │
│ - pemeriksaan tiap N s │                            └────────────────────┘
│ - diagnostik nyata     │  prompt (data disamarkan)
│ - insight + analisis   │ ─────────────────────────▶ ┌────────────────────┐
│ - dedup / resolved     │ ◀───────────────────────── │ LLM (opsional)     │
│ - /healthz /metrics    │      JSON analisis         └────────────────────┘
└────────────────────────┘
            │ POST /webhook (Bearer WEBHOOK_AUTH_TOKEN)
            ▼
┌────────────────────────┐      POST embed      ┌─────────┐
│ notifier (webhook)     │ ───────────────────▶ │ Discord │
│ - format embed         │                      └─────────┘
│ - rate limit / retry   │
└────────────────────────┘
```

Keduanya hanya memakai Python standard library (tanpa `pip install`), image berbasis `python:3.12-slim`, berjalan sebagai non-root dengan root filesystem read-only.

## Kompatibilitas

### Runtime

| Komponen | Versi | Catatan |
|---|---|---|
| Python (tanpa container) | 3.11, 3.12, 3.13 | Semua test lulus di ketiga versi. Tanpa dependensi eksternal. |
| Image container | `python:3.12-slim` | `linux/amd64` & `linux/arm64` (mengikuti base image) |
| Docker Engine | 20.10+ | Dibutuhkan untuk `extra_hosts: host-gateway` (akses Ollama di host) |
| Docker Compose | v2 (`docker compose`) | Memakai `depends_on.condition: service_healthy` dan `${VAR:?}` |

### Kubernetes

| Versi cluster | Status | Keterangan |
|---|---|---|
| 1.23 ke atas | Full support | Semua API yang dipakai tersedia (`autoscaling/v2`, `discovery.k8s.io/v1`, `batch/v1`) |
| 1.21 – 1.22 | Partial support | Pemeriksaan HPA dilewati otomatis (`autoscaling/v2` belum ada) |
| < 1.21 | Tidak diuji | EndpointSlice v1 belum ada, checker otomatis memakai `Endpoints` |

| API yang dipakai | Fallback bila tidak tersedia / tidak diizinkan |
|---|---|
| `/version` | Wajib (menentukan API server terjangkau atau tidak) |
| `/readyz?verbose` | Dilewati bila 403/404 (umum di cluster managed) |
| `discovery.k8s.io/v1` EndpointSlice | Turun ke `v1 Endpoints` |
| `autoscaling/v2` HPA | Pemeriksaan HPA dilewati |
| `pods/log` | Analisis tetap jalan tanpa log |
| `storage.k8s.io/v1` StorageClass | Insight StorageClass dilewati |

| Distribusi | Catatan |
|---|---|
| kubeadm, RKE2, kind, minikube | Control plane berjalan sebagai static pod berlabel `tier=control-plane`, jadi pemeriksaan `etcd` / `kube-apiserver` / scheduler / controller-manager ikut aktif |
| k3s, k0s | Komponen control plane tertanam di satu proses (bukan pod), sehingga pemeriksaan static pod tidak berlaku. Kesehatan API & `/readyz` tetap diperiksa. |
| EKS, GKE, AKS, DOKS, dan managed lain | Control plane tidak terlihat, sehingga pemeriksaan static pod otomatis tidak menghasilkan apa-apa. `/readyz` bisa dibatasi provider. Pemeriksaan lain berjalan normal. |
| OpenShift | Belum diuji; label namespace `pod-security.kubernetes.io` diabaikan oleh SCC |

- Label `pod-security.kubernetes.io/enforce: restricted` di `namespace.yaml` berlaku di Kubernetes 1.25+ (diabaikan di versi lebih lama). Manifest sudah memenuhi profil *restricted*.
- **CNI yang dikenali** untuk pemeriksaan jaringan: Calico, Cilium, Flannel, Weave, Canal, Antrea, kube-proxy, AWS VPC CNI (`aws-node`), kube-router, kindnet, OVN, Multus, Azure CNI.
- **DNS cluster** dideteksi lewat label `k8s-app=kube-dns` (CoreDNS & kube-dns standar).

### Kompatibilitas LLM

| `LLM_PROVIDER` | Layanan | `LLM_BASE_URL` | Autentikasi | Catatan |
|---|---|---|---|---|
| `openai` | OpenAI | default `https://api.openai.com/v1` | `Authorization: Bearer` | Memakai `max_completion_tokens` + JSON mode (`response_format`) |
| `azure` | Azure OpenAI | **wajib**: `https://<resource>.openai.azure.com` | header `api-key` | `LLM_MODEL` = nama *deployment*; `LLM_API_VERSION` default `2024-10-21` |
| `anthropic` | Anthropic (Claude) | default `https://api.anthropic.com` | header `x-api-key` | Messages API; `LLM_API_VERSION` mengisi header `anthropic-version` (default `2023-06-01`) |
| `gemini` | Google Gemini (AI Studio API key) | default `https://generativelanguage.googleapis.com/v1beta` | header `x-goog-api-key` | `generateContent` dengan output JSON |
| `ollama` | Ollama lokal | default `http://localhost:11434/v1` | tanpa key | Memakai endpoint kompatibel OpenAI milik Ollama. Dari docker compose: `http://host.docker.internal:11434/v1` |
| `openai-compatible` | Endpoint apa pun berformat OpenAI Chat Completions | **wajib** | `Authorization: Bearer` (bila key diisi) | Lihat contoh di bawah. JSON mode tidak dipaksakan; respons diparsing toleran (boleh ber-*code fence*). |

Contoh `LLM_BASE_URL` untuk `openai-compatible`:

| Layanan | `LLM_BASE_URL` |
|---|---|
| OpenRouter | `https://openrouter.ai/api/v1` (opsional `LLM_EXTRA_HEADERS={"HTTP-Referer":"...","X-Title":"..."}`) |
| Groq | `https://api.groq.com/openai/v1` |
| DeepSeek | `https://api.deepseek.com/v1` |
| Together AI | `https://api.together.xyz/v1` |
| Mistral | `https://api.mistral.ai/v1` |
| vLLM | `http://<host>:8000/v1` |
| LM Studio | `http://<host>:1234/v1` |
| LiteLLM proxy | `http://<host>:4000` |

Belum didukung langsung: **AWS Bedrock** dan **Google Vertex AI** (autentikasi SigV4/OAuth). Gunakan gateway kompatibel OpenAI seperti LiteLLM di depannya, lalu pakai `openai-compatible`.

Kebutuhan model: mampu mengikuti instruksi untuk membalas **satu objek JSON** dan konteks minimal ±8k token (prompt per temuan dibatasi ±14 ribu karakter data diagnostik). Model kecil lokal bisa dipakai, tapi kualitas analisis bergantung pada kemampuan modelnya. Untuk model *reasoning* yang tidak menerima `temperature`, biarkan `LLM_TEMPERATURE` kosong.

## Apa saja yang diperiksa

| Kategori | Pemeriksaan |
|---|---|
| Cluster / control plane | API server tidak terjangkau / token 401 / TLS error, `/readyz` gagal (mis. etcd), semua/mayoritas node NotReady, static pod control plane tidak Ready |
| Node | NotReady / Unknown, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable, cordon (info) |
| Pod | CrashLoopBackOff (dengan analisis exit code & OOMKilled), ImagePullBackOff/ErrImagePull, CreateContainerConfigError, tertahan ContainerCreating, Pending/Unschedulable (dengan analisis pesan scheduler), Running tapi tidak Ready, Evicted (diagregasi per namespace), Failed, tertahan Terminating |
| Log aplikasi | Pod **Running/Ready** yang log-nya berisi ERROR/FATAL/panic/exception melewati ambang dalam jendela waktu (digabung per workload + container) |
| Workload | Deployment tidak available / rollout macet, StatefulSet & DaemonSet tidak lengkap, Job gagal, HPA tidak dapat scaling |
| Jaringan in-cluster | CoreDNS/kube-dns down, DaemonSet CNI/kube-proxy tidak sehat, Service tanpa endpoint siap, LoadBalancer tanpa IP, event `FailedCreatePodSandBox`/`NetworkNotReady` |
| Storage | PVC Pending/Lost, PV Failed |
| Event | Warning event penting (FailedMount, Unhealthy, FailedCreate, SystemOOM, ProvisioningFailed, …) dalam jendela waktu |

## Pemindaian log pod Running/Ready

Kubernetes hanya memantau **proses** container dan **probe**. Aplikasi yang terus gagal (koneksi DB/cache ditolak, timeout ke service lain, exception per request, kredensial kedaluwarsa) tetap berstatus `Running`/`Ready` selama prosesnya hidup dan probe-nya lolos, sehingga DevOps/SRE mengira aman. Check `logs` menutup celah ini:

1. Setiap siklus, checker membaca log **terbaru** (`sinceSeconds` = `LOG_SCAN_WINDOW_MINUTES`) dari setiap container yang `Running` (read-only, izin `pods/log` yang sudah ada).
2. Baris dihitung sebagai error berdasarkan **level log**, bukan sekadar kata "error": `ERROR`/`FATAL`/`CRITICAL`/`SEVERE`, `level=error` (logfmt), `"level":"error"` (JSON), klog `E1013 …`, `panic:`, `Traceback`, `…Exception:`, `[error]` nginx, `PHP Fatal error`. Baris seperti `errors=0`, `GET /api/errors 200`, atau `level=info msg="no error"` **tidak** dihitung.
3. Error serupa dikelompokkan jadi *signature* (angka, IP, UUID, timestamp dihapus) sehingga notifikasi menampilkan mis. `13× ERROR PaymentGateway: request to https://psp.example/charge timed out after <n>ms`.
4. Hasil digabung **per workload + container** (mis. `Deployment/shop/pay [app]`), bukan per pod, sehingga 10 replika yang error sama menghasilkan satu notifikasi dan pod yang berganti nama saat rollout tidak memicu notifikasi baru.
5. Total error ≥ `LOG_SCAN_MIN_ERRORS` → **warning**, ≥ `LOG_SCAN_CRITICAL_ERRORS` → **critical**. Saat error berhenti (di bawah ambang dalam jendela waktu), dikirim **RESOLVED**.

Pod yang sudah punya temuan lain (CrashLoopBackOff, not Ready, dll.) tidak dipindai ulang karena log-nya sudah ikut di temuan tersebut. Contoh notifikasi:

```
🟠 [BARU] Pod Running & Ready tetapi log berisi error: shop/pay [app]
Temuan dari data cluster:
• Container 'app' berstatus Ready di 2/2 pod, namun mencatat 17 baris error dalam 10 menit terakhir — status pod & probe tidak mencerminkan kondisi aplikasi.
• Error terbanyak (13×): "ERROR PaymentGateway: request to https://psp.example/charge timed out after <n>ms (order=<n>)"
• Container 'app' tidak memiliki livenessProbe — Kubernetes tidak punya cara mengetahui aplikasi bermasalah.
Detail deteksi:   17 baris error … 2/2 pod terdampak · status: Running & Ready, total restart=0 · pod: pay-6f7b-k2 (16), pay-6f7b-k3 (1)
Baris error di log (pay-6f7b-k2):  …contoh baris ERROR (rahasia disamarkan)…
```

Pengaturan per pod lewat anotasi (di `spec.template.metadata.annotations`):

| Anotasi | Contoh | Fungsi |
|---|---|---|
| `health-checker.io/log-scan` | `"false"` | Jangan pindai log pod ini |
| `health-checker.io/log-error-pattern` | `"(?i)\\bpayment failed\\b"` | Regex error khusus aplikasi ini (menggantikan pola default) |
| `health-checker.io/log-ignore-pattern` | `"healthcheck\|deprecated"` | Regex baris error yang diabaikan |
| `health-checker.io/log-min-errors` | `"20"` | Ambang warning khusus aplikasi yang memang "berisik" |

Beban ke API server: satu request `pods/log` per container per pemindaian, dibatasi `LOG_SCAN_MAX_CONTAINERS` (bergiliran per workload bila lebih) dan `LOG_SCAN_CONCURRENCY`. Untuk cluster besar, set `LOG_SCAN_INTERVAL_SECONDS` (mis. `300`) — di antara pemindaian, hasil terakhir dipertahankan sehingga tidak dianggap resolved. Pemindaian bisa dimatikan dengan mengisi `ENABLED_CHECKS` tanpa `logs`. **Upgrade dari 1.1.x:** bila `ENABLED_CHECKS` Anda diisi eksplisit, tambahkan `logs` agar fitur ini aktif (bila kosong, otomatis aktif).

## Analisis & remediasi

```
temuan baru ──▶ kumpulkan diagnostik read-only ──▶ turunkan fakta (insight) ──▶ LLM (opsional) ──▶ Discord
                 spec · status · event · log          limit vs OOM, error log,     akar masalah, bukti,
                 (previous) · node · owner ·          port mismatch, kapasitas     dampak, langkah,
                 endpoint · StorageClass              node, StorageClass           perintah, confidence
```

Data diagnostik yang dikumpulkan per jenis temuan:

| Jenis temuan | Data nyata yang diambil |
|---|---|
| Log error pada pod Running/Ready | Ringkasan pemindaian (jumlah, signature, contoh baris), spec container & probe, event pod, log saat ini, Deployment pemilik |
| Pod (crash, OOM, image, config, pending, not ready) | Spec container, status & terminasi terakhir, event pod, log *previous* & saat ini, node (kapasitas & request terpakai), Deployment pemilik |
| Node | Kondisi, taint, allocatable vs request terpakai, versi kubelet/runtime, event node, pod non-Running di node |
| Deployment / StatefulSet / DaemonSet / DNS | Spec & kondisi, pod terkait, event + log pod terburuk |
| Service | Selector, port/targetPort, pod yang cocok beserta containerPort, label pod di namespace (deteksi salah label) |
| PVC | Spec, status, StorageClass (atau daftar StorageClass tersedia), event |
| Job | Spec, status, event, log pod terakhir |
| HPA | Spec, status, event |

Perilaku analisis:
- Analisis disimpan di state, jadi pengingat dan restart container **tidak** memanggil LLM ulang untuk masalah yang sama.
- Jumlah analisis dibatasi `LLM_MAX_FINDINGS_PER_RUN` per siklus (prioritas severity tertinggi). Sisanya dianalisis saat pengingat berikutnya.
- Bila LLM gagal atau timeout, notifikasi tetap terkirim dengan penjelasan aturan + insight + log, dan footer menyebut alasannya.

### Keamanan data yang dikirim ke LLM

- Nilai env dan isi Secret **tidak pernah dibaca**. Yang dikirim hanya nama referensinya (mis. `DB_PASSWORD<-secret:db/pass`).
- Log, pesan event, dan argumen command **disamarkan** dulu: password/token/API key, `Bearer ...`, kredensial di URL (`user:***@host`), JWT, AWS key, dan private key.
- `LLM_SEND_LOGS=false` membuat log tidak dikirim ke LLM. `DIAGNOSTICS_INCLUDE_LOGS=false` membuat log tidak dibaca sama sekali. Untuk data yang tidak boleh keluar jaringan sama sekali, gunakan `LLM_PROVIDER=ollama` atau server lokal lain (vLLM / LM Studio).
- Prompt memperlakukan log sebagai data tidak tepercaya (mitigasi prompt injection) dan menandai perintah berisiko dengan `[RISIKO]`. Rekomendasi AI tetap harus diverifikasi sebelum dieksekusi.

### Perilaku notifikasi

- Hanya temuan **baru** yang dikirim. Masalah yang masih berlangsung dikirim ulang sebagai **pengingat** tiap `REMINDER_INTERVAL_MINUTES`.
- Saat masalah hilang dikirim **RESOLVED** beserta durasi gangguan.
- Bila API server down atau sebagian pemeriksaan gagal, temuan lama **tidak** dianggap resolved.
- Bila pengiriman gagal, temuan dikirim ulang di siklus berikutnya. State disimpan di `STATE_FILE` sehingga restart container tidak memicu notifikasi ganda.

## Running dengan Docker Compose (checker di luar cluster)

```bash
# 1. Buat ServiceAccount read-only di cluster (sekali saja, butuh akses admin)
kubectl apply -f deploy/k8s/namespace.yaml -f deploy/k8s/rbac.yaml

# 2. Siapkan .env
cp .env.example .env
./scripts/get-readonly-token.sh      # cetak K8S_API_SERVER, K8S_TOKEN, K8S_CA_CERT
#    salin nilainya ke .env, lalu isi DISCORD_WEBHOOK_URL, WEBHOOK_AUTH_TOKEN, CLUSTER_NAME
#    (opsional) isi LLM_PROVIDER, LLM_API_KEY, LLM_MODEL, LLM_BASE_URL

# 3. Jalankan
docker compose up -d --build
docker compose logs -f checker       # baris "Analisis & remediasi LLM AKTIF: <provider>/<model>" bila LLM aktif

# 4. Uji koneksi ke Discord
curl -X POST -H "Authorization: Bearer <WEBHOOK_AUTH_TOKEN>" http://localhost:8080/webhook/test
```

> Jika sudah punya token read-only sendiri, cukup isi `K8S_API_SERVER`, `K8S_TOKEN`, dan `K8S_CA_CERT` (base64, dari `certificate-authority-data` di kubeconfig) di `.env`. Pastikan token tersebut punya izin `get` pada `pods/log` agar analisis menyertakan log.

## Deploy di dalam cluster

```bash
docker build -t registry.example.com/k8s-health-checker:1.2.0 ./checker
docker build -t registry.example.com/k8s-health-notifier:1.2.0 ./notifier
docker push registry.example.com/k8s-health-checker:1.2.0
docker push registry.example.com/k8s-health-notifier:1.2.0

kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n k8s-health create secret generic k8s-health-secrets \
  --from-literal=DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
  --from-literal=WEBHOOK_AUTH_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=LLM_PROVIDER='gemini' \
  --from-literal=LLM_MODEL='<model yang masih aktif>' \
  --from-literal=LLM_API_KEY="$LLM_API_KEY"

# Sesuaikan:
#   deploy/k8s/kustomization.yaml : registry image
#   deploy/k8s/checker.yaml       : CLUSTER_NAME (dan LLM_* bila tidak ditaruh di Secret)
kubectl apply -k deploy/k8s
```

Seluruh key di Secret `k8s-health-secrets` dimuat ke checker lewat `envFrom` **setelah** ConfigMap, jadi key `LLM_*` (atau env lain) di Secret **menimpa** nilai yang sama di ConfigMap. Konfigurasi LLM boleh ditaruh di salah satunya.

> Env container hanya dibaca saat pod start. Setelah mengubah Secret/ConfigMap, jalankan
> `kubectl -n k8s-health rollout restart deploy/k8s-health-checker`.

- Di dalam cluster checker memakai mode `incluster` (token ServiceAccount otomatis), tidak perlu `K8S_TOKEN`.
- Pod checker butuh **egress** ke endpoint LLM (atau ke Ollama/vLLM di dalam cluster). Periksa NetworkPolicy bila ada.
- Di belakang proxy korporat, tambahkan env `HTTPS_PROXY` dan `NO_PROXY` (berisi alamat API server / `.svc`).
- Jalankan **1 replica** checker saja; lebih dari itu akan mengirim notifikasi ganda.

## Token & kredensial

Ada tiga kredensial berbeda, jangan tertukar:

| Env | Isinya | Didapat dari |
|---|---|---|
| `K8S_TOKEN` | Token ServiceAccount/user Kubernetes yang read-only | Cluster, atau `./scripts/get-readonly-token.sh` |
| `DISCORD_WEBHOOK_URL` | URL webhook Discord (token Discord sudah termasuk di URL) | Discord: Server Settings → Integrations → Webhooks |
| `WEBHOOK_AUTH_TOKEN` | Password bersama checker ↔ notifier, string acak buatan sendiri | `openssl rand -hex 32` |
| `LLM_API_KEY` | API key provider LLM (opsional) | Dashboard provider LLM |

Di docker compose, `WEBHOOK_AUTH_TOKEN` cukup diisi sekali; checker membacanya sebagai `NOTIFY_WEBHOOK_TOKEN`.

## Environment variable

Daftar lengkap ada di [`.env.example`](.env.example).

### Checker (service utama)

| Variable | Default | Keterangan |
|---|---|---|
| `CLUSTER_NAME` | `kubernetes` | Nama cluster di notifikasi |
| `K8S_AUTH_MODE` | `auto` | `token` / `incluster` / `auto` (token jika `K8S_API_SERVER` diisi) |
| `K8S_API_SERVER` | – | URL API server, mis. `https://10.0.0.10:6443` |
| `K8S_TOKEN` / `K8S_TOKEN_FILE` | – | Bearer token read-only (file dibaca ulang tiap request) |
| `K8S_CA_CERT` / `K8S_CA_CERT_FILE` | – | CA cluster (base64 PEM) atau path file |
| `K8S_INSECURE_SKIP_TLS_VERIFY` | `false` | Hanya untuk uji coba |
| `K8S_REQUEST_TIMEOUT` | `15` | Detik |
| `CHECK_INTERVAL_SECONDS` | `60` | Interval pemeriksaan (min 10) |
| `RUN_ONCE` | `false` | Jalankan sekali lalu keluar (cocok untuk CronJob/CI) |
| `ENABLED_CHECKS` | semua | `cluster,nodes,pods,logs,workloads,network,storage,events` |
| `NAMESPACES_INCLUDE` / `NAMESPACES_EXCLUDE` | – | Daftar namespace dipisah koma |
| `MIN_SEVERITY` | `warning` | `info` / `warning` / `critical` |
| `POD_RESTART_THRESHOLD` | `5` | Restart dalam jendela event dianggap crash berulang |
| `POD_PENDING_MINUTES` | `5` | Batas Pending / ContainerCreating |
| `POD_NOT_READY_MINUTES` | `5` | Batas Running-tapi-tidak-Ready |
| `EVENT_WINDOW_MINUTES` | `15` | Jendela waktu event & restart |
| `EVENT_MIN_COUNT` | `3` | Minimal kejadian probe gagal (`Unhealthy`) |
| `JOB_FAILED_LOOKBACK_HOURS` | `24` | Job gagal yang masih dilaporkan |
| `PVC_PENDING_MINUTES` / `LB_PENDING_MINUTES` | `5` / `10` | Batas PVC Pending / LoadBalancer tanpa IP |
| `LOG_SCAN_WINDOW_MINUTES` | `10` | Jendela log yang dibaca untuk check `logs` |
| `LOG_SCAN_INTERVAL_SECONDS` | `0` | Jarak antar pemindaian log (0 = setiap siklus) |
| `LOG_SCAN_MIN_ERRORS` / `LOG_SCAN_CRITICAL_ERRORS` | `5` / `50` | Ambang warning / critical (total baris error per workload+container) |
| `LOG_SCAN_TAIL_LINES` / `LOG_SCAN_LIMIT_BYTES` | `1000` / `512000` | Batas log yang dibaca per container |
| `LOG_SCAN_MAX_CONTAINERS` / `LOG_SCAN_CONCURRENCY` | `300` / `5` | Batas container per siklus (bergiliran) / request paralel |
| `LOG_SCAN_SAMPLE_LINES` | `8` | Contoh baris error yang disimpan (ditampilkan maks. `NOTIFY_LOG_LINES`) |
| `LOG_SCAN_NAMESPACES_INCLUDE` / `_EXCLUDE` | – | Namespace khusus pemindaian log |
| `LOG_SCAN_ERROR_PATTERN` / `LOG_SCAN_IGNORE_PATTERN` | default level-log / – | Regex Python untuk baris error / baris yang diabaikan |
| `NOTIFY_WEBHOOK_URL` | – | URL notifier, mis. `http://notifier:8080/webhook` (kosong = hanya log) |
| `NOTIFY_WEBHOOK_TOKEN` | – | Harus sama dengan `WEBHOOK_AUTH_TOKEN` notifier |
| `NOTIFY_RESOLVED` | `true` | Kirim notifikasi saat masalah selesai |
| `REMINDER_INTERVAL_MINUTES` | `60` | Pengingat masalah berlangsung (0 = mati) |
| `MAX_FINDINGS_PER_REPORT` | `50` | Batas temuan per laporan |
| `DIAGNOSTICS_ENABLED` | `true` | Kumpulkan data nyata (spec, event, log, node) untuk temuan baru |
| `DIAGNOSTICS_INCLUDE_LOGS` | `true` | Baca log container (butuh izin `pods/log`) |
| `DIAGNOSTICS_LOG_TAIL_LINES` | `60` | Jumlah baris log yang dibaca |
| `NOTIFY_LOG_LINES` | `8` | Baris log yang ditampilkan di Discord (0 = sembunyikan) |
| `STATE_FILE` | `/data/state.json` (image) | Penyimpanan state dedup & cache analisis |
| `HEALTH_PORT` | `8081` | Port endpoint HTTP checker (0 = mati) |
| `LOG_LEVEL` | `INFO` | |

### LLM (analisis & remediasi)

| Variable | Default | Keterangan |
|---|---|---|
| `LLM_PROVIDER` | – (nonaktif) | `openai` · `azure` · `anthropic` · `gemini` · `ollama` · `openai-compatible` |
| `LLM_API_KEY` | – | Wajib untuk `openai`, `azure`, `anthropic`, `gemini`; opsional untuk lainnya |
| `LLM_MODEL` | – | **Wajib** bila provider diisi. Untuk Azure = nama deployment |
| `LLM_BASE_URL` | default per provider | **Wajib** untuk `azure` & `openai-compatible` |
| `LLM_API_VERSION` | – | Azure `api-version` (default `2024-10-21`) / header `anthropic-version` (default `2023-06-01`) |
| `LLM_EXTRA_HEADERS` | – | Header tambahan dalam JSON, mis. `{"X-Title":"k8s-health"}` |
| `LLM_TIMEOUT` | `60` | Request/second (retry otomatis untuk 429/5xx) |
| `LLM_MAX_TOKENS` | `1500` | Batas token output |
| `LLM_TEMPERATURE` | – | Kosong = default model |
| `LLM_MAX_FINDINGS_PER_RUN` | `10` | Batas analisis per siklus (cost control) |
| `LLM_CONCURRENCY` | `3` | Permintaan LLM paralel |
| `LLM_MIN_SEVERITY` | `warning` | Severity minimum yang dianalisis LLM |
| `LLM_LANGUAGE` | `Bahasa Indonesia` | Bahasa output analisis |
| `LLM_SEND_LOGS` | `true` | Kirim log container (sudah disamarkan) ke LLM |
| `REMEDIATION_ENABLED` | `true` | `false` = matikan LLM sementara tanpa menghapus konfigurasi |

Konfigurasi divalidasi saat start. Kombinasi yang salah (mis. provider tanpa model, `azure` tanpa base URL) membuat checker keluar dengan pesan error yang jelas (exit code 2).

Contoh:

```bash
# OpenAI
LLM_PROVIDER=openai             LLM_API_KEY=sk-...      LLM_MODEL=<model>
# Azure OpenAI
LLM_PROVIDER=azure              LLM_API_KEY=...         LLM_MODEL=<deployment>  LLM_BASE_URL=https://<resource>.openai.azure.com
# Anthropic (Claude)
LLM_PROVIDER=anthropic          LLM_API_KEY=sk-ant-...  LLM_MODEL=<model>
# Google Gemini
LLM_PROVIDER=gemini             LLM_API_KEY=AIza...     LLM_MODEL=<model>
# OpenRouter / Groq / DeepSeek / vLLM / LiteLLM
LLM_PROVIDER=openai-compatible  LLM_API_KEY=...         LLM_MODEL=<model>  LLM_BASE_URL=https://openrouter.ai/api/v1
# Ollama di host (dari docker compose)
LLM_PROVIDER=ollama             LLM_MODEL=<model>       LLM_BASE_URL=http://host.docker.internal:11434/v1
```

### Notifier (webhook)

| Variable | Default | Keterangan |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | – (wajib, kecuali `DRY_RUN`) | URL webhook Discord |
| `WEBHOOK_AUTH_TOKEN` | – | Shared secret; checker mengirim `Authorization: Bearer <token>` |
| `PORT` | `8080` | Port HTTP |
| `DISCORD_USERNAME` / `DISCORD_AVATAR_URL` | `K8s Health Checker` / – | Tampilan pengirim |
| `DISCORD_MENTION_ON_CRITICAL` | – | Mis. `@here` atau `<@&ROLE_ID>` saat ada critical baru |
| `DISCORD_MAX_MESSAGES_PER_REPORT` | `5` | 1 pesan = maks 10 temuan |
| `DISCORD_TIMEOUT` / `DISCORD_MAX_RETRIES` | `15` / `5` | Retry otomatis termasuk rate limit 429 |
| `DRY_RUN` | `false` | Hanya log, tidak kirim ke Discord |

## Format pesan Discord

Setiap temuan menjadi satu embed:

| Bagian | Dengan LLM | Tanpa LLM / LLM gagal |
|---|---|---|
| Judul | `🔴 [BARU] Container OOMKilled berulang: shop/api-5c6d-x1 [app]` | sama |
| Deskripsi | **Akar masalah**, **Dampak**, **Bukti dari cluster** | **Penjelasan** + **Temuan dari data cluster** |
| Field | Severity, Kategori, Resource, Detail deteksi, Log terakhir, **Rekomendasi remediasi** (bernomor), **Perintah**, Perlu dicek lebih lanjut | Severity, Kategori, Resource, Detail deteksi, Log terakhir |
| Footer | `Analisis AI: <provider>/<model> (confidence high)` | Status LLM beserta alasannya (nonaktif / gagal / dilewati) |

Status di judul: `BARU`, `MASIH TERJADI` (pengingat), `RESOLVED`. Embed otomatis dipotong agar tetap di bawah batas Discord (6000 karakter per pesan, 10 embed per pesan).

## Endpoint HTTP

| Service | Endpoint | Fungsi |
|---|---|---|
| checker `:8081` | `GET /healthz` | Liveness (loop pemeriksaan tidak macet) |
| | `GET /readyz` | Siap setelah siklus pertama |
| | `GET /status` | JSON temuan aktif (termasuk hasil analisis) & konfigurasi tanpa rahasia |
| | `GET /metrics` | Metrik Prometheus (jumlah temuan per severity, status API, durasi) |
| notifier `:8080` | `POST /webhook` | Menerima laporan dari checker |
| | `POST /webhook/test` | Kirim pesan uji ke Discord |
| | `GET /healthz` | Health check |

## Troubleshooting

**Footer notifikasi: `Analisis LLM nonaktif: ...`.** Footer menyebut alasannya:

| Pesan footer | Penyebab | Solusi |
|---|---|---|
| `LLM_PROVIDER belum diisi` | Env `LLM_PROVIDER` kosong di container | Isi `LLM_PROVIDER` di ConfigMap/Secret/`.env` |
| `LLM_API_KEY/LLM_MODEL terisi tetapi LLM_PROVIDER kosong` | Key/model sampai ke container, provider tidak | Biasanya `LLM_PROVIDER` hanya ditulis di Secret tetapi manifest lama (≤1.1.0) belum memuat Secret lewat `envFrom`. Apply `checker.yaml` terbaru lalu rollout restart |
| `dimatikan (REMEDIATION_ENABLED=false)` | Dimatikan sengaja | Set `REMEDIATION_ENABLED=true` |

Cek env yang benar-benar terbaca container:

```bash
kubectl -n k8s-health exec deploy/k8s-health-checker -- python -c \
  "import os; print({k: ('set' if 'KEY' in k else v) for k, v in os.environ.items() if k.startswith('LLM_')})"
kubectl -n k8s-health port-forward deploy/k8s-health-checker 8081 &
curl -s localhost:8081/status | python -m json.tool | grep -A8 '"llm"'
```

**Footer: `Analisis LLM gagal: HTTP 404 ... tidak ditemukan / sudah dihentikan`.** Nama model salah atau model sudah dipensiunkan provider (mis. keluarga Gemini 1.5 sudah dihentikan). Lihat model yang tersedia untuk API key Anda:

```bash
# Gemini
curl -s -H "x-goog-api-key: $LLM_API_KEY" https://generativelanguage.googleapis.com/v1beta/models | grep '"name"'
# OpenAI / kompatibel OpenAI
curl -s -H "Authorization: Bearer $LLM_API_KEY" https://api.openai.com/v1/models | grep '"id"'
```

**Footer: `Analisis LLM gagal: HTTP 401/403`.** API key salah, kedaluwarsa, atau tidak punya akses ke model tersebut.

**Footer: `Analisis LLM gagal: koneksi gagal`.** Pod tidak bisa keluar ke internet/endpoint LLM. Periksa NetworkPolicy, egress firewall, atau set `HTTPS_PROXY`.

**Satu masalah muncul sebagai dua temuan** (mis. `ErrImagePull` pada pod dan `Deployment tidak memiliki replica tersedia`). Ini disengaja: keduanya objek berbeda dan bisa berdiri sendiri. Gunakan `ENABLED_CHECKS` atau `MIN_SEVERITY` bila ingin lebih ringkas.

## Local testing

Tersedia fake Kubernetes API (±20 skenario error, termasuk log container), fake LLM (meniru format OpenAI/Azure/Anthropic/Gemini), dan fake Discord:

```bash
python -m unittest discover -s tests -v
```

Cakupan test (37 test): deteksi semua kategori, dedup/pengingat/resolved, API down & token salah, TLS, persistensi state, pemindaian log pod Running/Ready (pola, ambang, anotasi, rotasi, interval), autentikasi notifier, batas embed Discord, keenam provider LLM, cache analisis, fallback saat LLM gagal, penyamaran rahasia, dan validasi konfigurasi.

## Izin RBAC

ClusterRole di `deploy/k8s/rbac.yaml` hanya memakai verb `get/list/watch`, ditambah `get pods/log` (untuk analisis log & pemindaian log pod Running) dan `storageclasses`. Secret **tidak** termasuk.

## Struktur proyek

```
kubernetes-check/
├── checker/                    # service utama
│   ├── Dockerfile
│   └── k8s_checker/
│       ├── main.py             # loop, endpoint HTTP
│       ├── config.py           # semua env
│       ├── k8s.py              # klien REST Kubernetes (read-only)
│       ├── checks.py           # pemeriksaan kesehatan
│       ├── logscan.py          # deteksi error di log pod Running/Ready
│       ├── knowledge.py        # penjelasan berbasis aturan
│       ├── diagnostics.py      # pengumpul data nyata (spec, event, log, node)
│       ├── remediation.py      # insight + analisis LLM
│       ├── llm.py              # klien multi-provider LLM
│       ├── redact.py           # penyamaran rahasia
│       ├── state.py            # dedup, pengingat, resolved
│       └── sender.py           # kirim ke notifier
├── notifier/                   # service webhook → Discord
│   ├── Dockerfile
│   └── discord_notifier/
├── deploy/k8s/                 # manifest Kubernetes + RBAC read-only
├── scripts/get-readonly-token.sh
├── tests/                      # fake K8s / LLM / Discord + test
├── docker-compose.yml
└── .env.example
```
