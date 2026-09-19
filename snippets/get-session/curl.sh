#!/usr/bin/env bash
# Reads the session envelope: status, decision, checks and evidence. Usage: SESSION_ID=… ./curl.sh
BASE_URL="${CATALISA_BIOMETRICS_URL:-https://api.biometrics.catalisa.app/v1}"

curl -sS "$BASE_URL/sessions/$SESSION_ID" -H "X-API-Key: $CATALISA_API_KEY"
# 200 → { "data": { "status": "APPROVED",
#                   "decision": { "outcome": "APPROVED", "reasons": [], "reviewRequired": false },
#                   "checks": [ { "kind": "liveness.passive", "status": "PASSED", "score": 0.97, "threshold": 0.8, … } ] } }
