#!/bin/bash

set -e

OUTPUT_DIR="${1:-.}"

mkdir -p "$OUTPUT_DIR"

# Resolve absolute path safely
ABS_OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

PRIVATE_KEY="$ABS_OUTPUT_DIR/jwt-private.pem"
PUBLIC_KEY="$ABS_OUTPUT_DIR/jwt-public.pem"

openssl genpkey \
  -algorithm RSA \
  -out "$PRIVATE_KEY" \
  -pkeyopt rsa_keygen_bits:2048

openssl rsa \
  -pubout \
  -in "$PRIVATE_KEY" \
  -out "$PUBLIC_KEY"

echo "Wrote:"
echo "  Private Key: $PRIVATE_KEY"
echo "  Public Key : $PUBLIC_KEY"