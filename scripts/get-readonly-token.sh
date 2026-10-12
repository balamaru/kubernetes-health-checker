#!/usr/bin/env bash
#  Butuh kubectl dengan akses admin.
set -euo pipefail
NS="${NS:-k8s-health}"
SECRET="${SECRET:-k8s-health-checker-token}"

for i in $(seq 1 15); do
  TOKEN_B64=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' 2>/dev/null || true)
  [ -n "$TOKEN_B64" ] && break
  sleep 1
done
[ -n "${TOKEN_B64:-}" ] || { echo "Token belum tersedia di secret $NS/$SECRET" >&2; exit 1; }

SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.ca\.crt}')

echo "K8S_API_SERVER=${SERVER}"
echo "K8S_TOKEN=$(echo "$TOKEN_B64" | base64 -d)"
echo "K8S_CA_CERT=${CA}"
