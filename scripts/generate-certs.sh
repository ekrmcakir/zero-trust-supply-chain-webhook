#!/usr/bin/env bash
set -euo pipefail

# Generate TLS certificates for Kubernetes Admission Webhook
OUTPUT_DIR="${1:-certs}"
NAMESPACE="${2:-zero-trust-system}"
SERVICE_NAME="${3:-zero-trust-webhook}"

mkdir -p "${OUTPUT_DIR}"

echo "==> Generating CA Key and Certificate..."
openssl req -nodes -new -x509 -keyout "${OUTPUT_DIR}/ca.key" -out "${OUTPUT_DIR}/ca.crt" -days 365 -subj "/CN=ZeroTrustAdmissionWebhookCA"

echo "==> Generating Webhook Server Key..."
openssl req -nodes -newkey rsa:2048 -keyout "${OUTPUT_DIR}/tls.key" -out "${OUTPUT_DIR}/tls.csr" -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc"

cat <<EOF > "${OUTPUT_DIR}/csr.conf"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

echo "==> Signing Webhook Server Certificate with CA..."
openssl x509 -req -in "${OUTPUT_DIR}/tls.csr" -CA "${OUTPUT_DIR}/ca.crt" -CAkey "${OUTPUT_DIR}/ca.key" -CAcreateserial -out "${OUTPUT_DIR}/tls.crt" -days 365 -extfile "${OUTPUT_DIR}/csr.conf" -extensions v3_req

rm -f "${OUTPUT_DIR}/tls.csr" "${OUTPUT_DIR}/csr.conf"

echo "==> Webhook certificates generated successfully in '${OUTPUT_DIR}/':"
ls -lh "${OUTPUT_DIR}"
