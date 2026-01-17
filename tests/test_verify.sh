#!/bin/sh
set -e

echo "Running verify test..."
TMPDIR=$(mktemp -d)
KEY="$TMPDIR/key"
LOG="$TMPDIR/log"
PAYLOAD='{"pid":1234}'

# generate random key
head -c 32 /dev/urandom | base64 > "$KEY"
chmod 600 "$KEY"

# compute HMAC-SHA256 over payload (binary) and hex encode
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$(cat $KEY)" -binary | xxd -p -c 256)

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo test-id)

printf '{"ts":"%s","id":"%s","category":"test","type":"signed","pid":%d,"payload":%s,"hmac_sha256":"%s"}\n' "$TS" "$ID" 1234 "$PAYLOAD" "$SIG" > "$LOG"

# run verify subcommand (override keyfile via env)
export NULL_LOGS_KEYFILE="$KEY"
# debug: show key file for test
ls -l "$KEY" || true
xxd -l 64 "$KEY" || true
./null-logs verify "$LOG"

echo "verify test passed"
exit 0