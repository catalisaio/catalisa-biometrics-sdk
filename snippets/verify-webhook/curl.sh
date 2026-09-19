#!/usr/bin/env bash
# Verifies one webhook delivery with openssl (handy for debugging). The signature is RSA-SHA256
# over "x-webhook-id\nx-webhook-timestamp\nraw body", checked with the subscription's PUBLIC key.
#   ./curl.sh <body.json> <x-webhook-id> <x-webhook-timestamp> <x-webhook-signature> <public-key.pem>
set -euo pipefail
BODY="$1"; ID="$2"; TS="$3"; SIG="$4"; PEM="$5"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

[[ "$SIG" == v1=* ]] || { echo "unsupported signature version" >&2; exit 1; }
AGE=$(( $(date +%s) - $(date -d "$TS" +%s) )); [ "${AGE#-}" -le 300 ] || { echo "outside tolerance (${AGE}s)" >&2; exit 1; }

printf '%s\n%s\n' "$ID" "$TS" > "$TMP/msg" && cat "$BODY" >> "$TMP/msg"   # body byte for byte
printf '%s' "${SIG#v1=}" | base64 -d > "$TMP/sig"
openssl dgst -sha256 -verify "$PEM" -signature "$TMP/sig" "$TMP/msg"          # prints "Verified OK"
