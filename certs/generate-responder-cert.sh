#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${SCRIPT_DIR}/responder.key" \
  -out "${SCRIPT_DIR}/responder.crt" \
  -sha256 \
  -days 365 \
  -subj "/CN=localhost"

echo "Generated ${SCRIPT_DIR}/responder.crt and ${SCRIPT_DIR}/responder.key"
