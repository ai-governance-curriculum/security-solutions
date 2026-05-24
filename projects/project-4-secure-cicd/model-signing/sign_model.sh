#!/usr/bin/env bash
# Sign model artifacts after training. Verify at serving startup.
set -euo pipefail

MODEL_PATH=$1
SHA=$(sha256sum "$MODEL_PATH" | awk '{print $1}')
COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
  --output-signature "${MODEL_PATH}.sig" \
  --output-certificate "${MODEL_PATH}.cert" \
  "$MODEL_PATH"
echo "signed: $MODEL_PATH"
echo "  sha256: $SHA"
echo "  signature: ${MODEL_PATH}.sig"

# At serving startup, verify:
# COSIGN_EXPERIMENTAL=1 cosign verify-blob \
#   --signature ${MODEL_PATH}.sig \
#   --certificate ${MODEL_PATH}.cert \
#   --certificate-identity "https://github.com/me/training/.github/workflows/train.yml@main" \
#   --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
#   $MODEL_PATH
