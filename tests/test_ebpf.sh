#!/bin/sh
set -e

echo "Running eBPF smoke test..."
# Skip if not running as root or libbpf not available
if [ "$(id -u)" -ne 0 ]; then
  echo "Skipping eBPF test: requires root (CI will run with sudo)"; exit 0
fi
if ! pkg-config --exists libbpf; then
  echo "Skipping eBPF test: libbpf not available"; exit 0
fi

# build with LIBBPF
make clean
make LIBBPF=1 -j2

# start in background
./null-logs foreground >/tmp/null-logs-ebpf.out 2>&1 &
PID=$!
sleep 1

# trigger syscalls
ls / >/dev/null
cat /etc/hosts >/dev/null
sleep 2

# stop daemon
kill $PID || true
wait $PID 2>/dev/null || true

# check log for syscall events
if grep -q '"category":"syscall"' /var/log/null-logs/null-logs.log 2>/dev/null; then
  echo "eBPF events found in log"
  exit 0
else
  echo "eBPF events NOT found in log" >&2
  exit 2
fi