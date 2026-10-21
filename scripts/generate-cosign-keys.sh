#!/usr/bin/env bash
set -euo pipefail

# Generate standard ECDSA P-256 keypair for Sigstore Cosign verification
OUTPUT_DIR="${1:-examples/cosign-test-keys}"
mkdir -p "${OUTPUT_DIR}"

echo "==> Generating ECDSA P-256 Cosign keypair in '${OUTPUT_DIR}'..."
openssl ecparam -name prime256v1 -genkey -noout -out "${OUTPUT_DIR}/cosign.key"
openssl ec -in "${OUTPUT_DIR}/cosign.key" -pubout -out "${OUTPUT_DIR}/cosign.pub"

echo "==> Cosign keypair created:"
ls -lh "${OUTPUT_DIR}"
cat "${OUTPUT_DIR}/cosign.pub"
