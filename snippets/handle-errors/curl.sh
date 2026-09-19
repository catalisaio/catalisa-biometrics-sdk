#!/usr/bin/env bash
# Creates a session on behalf of a subaccount and handles 402 (quota) and 403 (suspended subaccount).
BASE_URL="${CATALISA_BIOMETRICS_URL:-https://api.biometrics.catalisa.app/v1}"

RESPONSE=$(curl -sS -w '\n%{http_code}' -X POST "$BASE_URL/sessions" \
  -H "X-API-Key: $CATALISA_API_KEY" \
  -H "X-Subaccount-Id: $CATALISA_SUBACCOUNT_ID" \
  -H "Content-Type: application/json" \
  -d '{"flow":"LIVENESS_ONLY","purpose":"abertura de conta"}')
STATUS=$(tail -n1 <<<"$RESPONSE"); BODY=$(sed '$d' <<<"$RESPONSE")
CODE=$(jq -r '.details.code // .error // empty' <<<"$BODY")

case "$STATUS:$CODE" in
  201:*)                    echo "ok: $(jq -r .data.handoff.captureUrl <<<"$BODY")" ;;
  402:QUOTA_EXCEEDED)       echo "blocked: QUOTA_EXCEEDED — monthly quota used ($(jq -r .details.used <<<"$BODY")/$(jq -r .details.monthlyQuota <<<"$BODY"))" ;;
  403:SUBACCOUNT_SUSPENDED) echo "blocked: SUBACCOUNT_SUSPENDED — subaccount suspended" ;;
  429:*)                    echo "rate limited; retry in $(jq -r '.retry_after // 1' <<<"$BODY") s" ;;
  *)                        echo "error $STATUS: $CODE" >&2; exit 1 ;;
esac
