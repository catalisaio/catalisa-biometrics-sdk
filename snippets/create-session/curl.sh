#!/usr/bin/env bash
# Creates a liveness session and prints the capture link.
BASE_URL="${CATALISA_BIOMETRICS_URL:-https://api.biometrics.catalisa.app/v1}"

curl -sS -X POST "$BASE_URL/sessions" \
  -H "X-API-Key: $CATALISA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "flow": "LIVENESS_ONLY",
    "purpose": "abertura de conta",
    "metadata": { "orderId": "123" }
  }'
# 201 → { "data": { "sessionId": "…", "status": "SESSION_OPEN",
#                   "handoff": { "captureUrl": "https://…/capture/…", "expiresAt": "…" } } }
