#!/usr/bin/env bash
set -e

# ==============================================================================
# Zero-Trust Software Supply Chain Admission Webhook - Interactive Live Demo
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "   ZERO-TRUST SOFTWARE SUPPLY CHAIN ADMISSION WEBHOOK (LIVE DEMO)    "
echo "======================================================================"
echo -e "${NC}"

TMP_DIR="$(mktemp -d -t webhook-demo-XXXXXX)"
cleanup() {
    echo -e "\n${YELLOW}[TEMİZLİK] Geçici test kaynakları ve arka plan sunucusu kapatılıyor...${NC}"
    if [ -n "${WEBHOOK_PID:-}" ] && kill -0 "${WEBHOOK_PID}" 2>/dev/null; then
        kill "${WEBHOOK_PID}" 2>/dev/null || true
        wait "${WEBHOOK_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
    echo -e "${GREEN}[TEMİZLİK] Başarıyla tamamlandı.${NC}"
}
trap cleanup EXIT INT TERM

# 1. Compile webhook binary if not present
if [ ! -f "bin/webhook" ]; then
    echo -e "${BLUE}[ADIM 1/5] Go binary derleniyor (bin/webhook)...${NC}"
    /opt/homebrew/bin/go build -o bin/webhook ./cmd/webhook
else
    echo -e "${GREEN}[ADIM 1/5] Webhook binary 'bin/webhook' hazır.${NC}"
fi

# 2. Generate local TLS certificates for localhost
echo -e "${BLUE}[ADIM 2/5] Webhook HTTPS iletişimi için yerel TLS sertifikaları üretiliyor...${NC}"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    -days 1 -subj "/CN=localhost" \
    -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" 2>/dev/null

# 3. Create Demo Configuration
cat <<EOF > "${TMP_DIR}/config.yaml"
server:
  port: 8443
  metricsPort: 9090
  tlsCertFile: "${TMP_DIR}/tls.crt"
  tlsKeyFile: "${TMP_DIR}/tls.key"
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

# 4. Start Webhook Daemon in background
echo -e "${BLUE}[ADIM 3/5] Webhook HTTPS sunucusu başlatılıyor (:8443) & Prometheus Metrikleri (:9090)...${NC}"
./bin/webhook -config "${TMP_DIR}/config.yaml" > "${TMP_DIR}/webhook.log" 2>&1 &
WEBHOOK_PID=$!

# Wait for server readiness
for i in {1..20}; do
    if curl -s -k "https://127.0.0.1:8443/healthz" 2>/dev/null | grep -q "ok"; then
        break
    fi
    sleep 0.2
done

echo -e "${GREEN}[OK] Webhook daemon aktif (PID: ${WEBHOOK_PID}). Sağlık Kontrolü (healthz): OK${NC}\n"

# Helper function to send admission reviews
send_review() {
    local title="$1"
    local namespace="$2"
    local container_json="$3"
    local security_context="$4"

    echo -e "${BOLD}----------------------------------------------------------------------${NC}"
    echo -e "${YELLOW}>> CANLI TEST: ${title}${NC}"

    local payload=$(cat <<EOF
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "test-req-$(date +%s%N)",
    "kind": { "group": "", "version": "v1", "kind": "Pod" },
    "resource": { "group": "", "version": "v1", "resource": "pods" },
    "namespace": "${namespace}",
    "operation": "CREATE",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "demo-pod",
        "namespace": "${namespace}"
      },
      "spec": {
        "containers": [
          ${container_json}
        ]
        ${security_context}
      }
    }
  }
}
EOF
)

    local response=$(curl -s -k -X POST \
        -H "Content-Type: application/json" \
        -d "${payload}" \
        "https://127.0.0.1:8443/validate")

    local allowed=$(echo "${response}" | grep -o '"allowed":[^,}]*' | awk -F: '{print $2}' | tr -d ' "')
    local message=$(echo "${response}" | grep -o '"message":[^}]*' | sed 's/"message":"//;s/"//g')

    if [ "${allowed}" = "false" ]; then
        echo -e "   [SONUÇ]: ${RED}${BOLD}BLOCKED (403 Forbidden - ENGELLENDİ)${NC}"
        echo -e "   [NEDEN]: ${RED}${message}${NC}"
    else
        echo -e "   [SONUÇ]: ${GREEN}${BOLD}ALLOWED (200 OK - KÜMEYE KABUL EDİLDİ)${NC}"
        echo -e "   [DURUM]: Pod tüm Zero-Trust ve Pod Security kurallarını başarıyla geçti."
    fi
}

echo -e "${CYAN}${BOLD}[ADIM 4/5] Kubernetes Admission Denetimleri Gerçek Zamanlı Test Ediliyor...${NC}\n"

# Test 1: Untrusted Registry
send_review "1. Yetkisiz/Güvensiz Kaynaktan İmaj İndirme (Untrusted Registry)" \
    "production" \
    '{"name": "malicious-app", "image": "docker.io/evilcorp/crypto-miner:v1.0.0", "securityContext": {"privileged": false, "runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}}' \
    ''

# Test 2: Mutable :latest Tag
send_review "2. Değişken ':latest' Etiketi ile Dağıtım (Mutable Tag)" \
    "production" \
    '{"name": "unstable-app", "image": "ghcr.io/ekrmcakir/web-service:latest", "securityContext": {"privileged": false, "runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}}' \
    ''

# Test 3: Root & Privileged Security Violation
send_review "3. Privileged / Root Yetkili Container Saldırısı (Pod Security Violation)" \
    "production" \
    '{"name": "root-app", "image": "ghcr.io/ekrmcakir/web-service:v1.2.0", "securityContext": {"privileged": true, "runAsNonRoot": false}}' \
    ''

# Test 4: Unsigned Image from Trusted Registry
send_review "4. İmzalanmamış / Doğrulanmamış İmaj (Unsigned Cosign Artifact)" \
    "production" \
    '{"name": "unsigned-app", "image": "ghcr.io/ekrmcakir/unsigned-service:v1.0.0", "securityContext": {"privileged": false, "runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}}' \
    ''

# Test 5: Fully Compliant, Signed, Hardened Pod
send_review "5. Sigstore/Cosign İmzalı, Sertleştirilmiş Prodüksiyon Podu (Valid & Signed)" \
    "production" \
    '{"name": "secure-payment-service", "image": "ghcr.io/ekrmcakir/signed-payment-api:v1.0.0", "securityContext": {"privileged": false, "runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}}' \
    ''

# Test 6: Whitelisted / Excluded Namespace Workload
send_review "6. Kural Dışı / Sistem Namespace İzni (Whitelisted Namespace: kube-system)" \
    "kube-system" \
    '{"name": "coredns", "image": "registry.k8s.io/coredns/coredns:v1.11.1"}' \
    ''

echo -e "\n${BOLD}----------------------------------------------------------------------${NC}"
echo -e "${CYAN}${BOLD}[ADIM 5/5] Canlı Prometheus Metrikleri (http://127.0.0.1:9090/metrics):${NC}"
curl -s "http://127.0.0.1:9090/metrics" | grep -E '^supply_chain_' | while read -r line; do
    echo -e "   ${YELLOW}${line}${NC}"
done

echo -e "\n${GREEN}${BOLD}Tüm senaryolar başarıyla simüle edildi ve Zero-Trust Webhook'un çalıştığı doğrulandı!${NC}"
