# Null-Logs 🔧

**Null-Logs** is a modular, production-oriented Linux activity logging daemon and CLI. It collects deep-level system events (process lifecycle, filesystem activity, network capture integration optional) and writes cryptographically signed JSON logs for detection and forensics. It is designed for defenders (blue teams), red teams, and forensic engineers who want reliable, auditable event trails.

⚠️ Requires root (or appropriate capabilities) to capture kernel-level events (proc connector, fanotify, packet capture, eBPF hooks).

## Features

- Process events via Linux proc connector (fork/exec/exit)
- Filesystem events via fanotify (open/modify/delete)
- Pluggable network capture (hooks for libpcap/eBPF)
- JSONL output with categories, reasoning fields, and HMAC-SHA256 signatures for integrity
- Systemd service and CLI for controlling the daemon
- Modular codebase in C for low-level access and performance

## Quick start

Build and install:

```sh
make
sudo make install
```

Start the daemon:

```sh
sudo null-logs start
sudo systemctl enable --now null-logs.service
```

Query logs:

```sh
sudo null-logs query --file /var/log/null-logs/null-logs.log
```

## Security notes
- This tool requires root privileges for deep event capture; limit its access and rotate keys.
- The HMAC key is stored by default in `/etc/null-logs/key` (permissions 600). Replace with an HSM if available.

## Roadmap
- Add eBPF module for syscall tracing
- Add TLS remote forwarder and secure ingestion
- Build optional Rust/Go companion for advanced processing

---

See `docs/ARCHITECTURE.md` for details.