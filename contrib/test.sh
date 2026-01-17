#!/bin/sh
# Simple smoke test (requires root)
set -euo pipefail

BIN=/usr/local/bin/null-logs
if [ ! -x "$BIN" ]; then
  echo "binary $BIN not found, build and install first" >&2
  exit 1
fi

KEY=/etc/null-logs/key
LOG=/var/log/null-logs/null-logs.log

if [ ! -f "$KEY" ]; then
  echo "Please install a key to $KEY (see contrib/key.sample)" >&2
  exit 1
fi

# Start in background
nohup "$BIN" start >/tmp/null-logs.out 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; exit' EXIT
sleep 1

# Generate events
touch /tmp/null-logs-test-file
ls /tmp/null-logs-test-file >/dev/null || true
/bin/sh -c 'echo hello' >/tmp/null-logs-test-file

sleep 1
kill $PID
sleep 1

if [ -f "$LOG" ]; then
  echo "Logs:"
  sudo tail -n 20 "$LOG" || true
else
  echo "Log file not present: $LOG" >&2
  exit 2
fi
