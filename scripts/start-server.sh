#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

CERT_DIR="${PROJECT_ROOT}/bin/certs"
mkdir -p "${CERT_DIR}"

if [ ! -f "${CERT_DIR}/tls.crt" ] || [ ! -f "${CERT_DIR}/tls.key" ]; then
    echo "[INFO] Generating local TLS certificates in ${CERT_DIR}..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/tls.key" \
        -out "${CERT_DIR}/tls.crt" \
        -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi

cat <<EOF > "${PROJECT_ROOT}/bin/local-config.yaml"
server:
  port: 8443
  metricsPort: 9090
  tlsCertFile: "${CERT_DIR}/tls.crt"
  tlsKeyFile: "${CERT_DIR}/tls.key"
  healthCheckPath: "/healthz"
  webhookPath: "/validate"
policy:
  mode: "enforce"
  trustedRegistries:
    - "ghcr.io/ekrmcakir/*"
    - "registry.k8s.io/*"
  disallowLatestTag: true
  requireDigest: false
  excludedNamespaces:
    - "kube-system"
    - "zero-trust-system"
  cosign:
    enabled: true
    publicKeyPath: "${PROJECT_ROOT}/examples/cosign-test-keys/cosign.pub"
    cacheTTL: "5m"
    cacheMaxEntries: 1000
  attestations:
    requireSBOM: false
    requireScan: false
    maxCriticalCVEs: 0
    maxHighCVEs: 2
    disallowUnscanned: false
  podSecurity:
    enabled: true
    disallowPrivileged: true
    requireNonRoot: true
    requireReadOnlyRootFS: true
    requireDropAllCaps: true
    requireResourceLimits: false
EOF

echo "[INFO] Starting Zero-Trust Webhook Daemon on :8443 (HTTPS) and Visual Dashboard/Metrics on :9090 (HTTP)..."
exec "${PROJECT_ROOT}/bin/webhook" -config "${PROJECT_ROOT}/bin/local-config.yaml"
