# Null-Logs Architecture

Null-Logs is built as a modular C daemon with small pluggable modules for various event sources.

Core modules:
- Process module: uses NETLINK_CONNECTOR (proc connector) to receive process lifecycle events (fork/exec/exit).
- Filesystem module: uses fanotify to monitor file open/modify/delete events across mounts.
- Network module: optional, integrates with libpcap or eBPF for packet-level capture.
- Storage: JSONL files written to `/var/log/null-logs`, each line is one JSON event with `hmac_sha256` for integrity.
- CLI: small user-facing tool to start/stop/query the daemon.

Security & Integrity:
- Events are HMAC-SHA256 signed with a key stored in `/etc/null-logs/key`.
- Recommend using an HSM or key manager for production.

Notes on privileges:
- The daemon requires root or capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN` for pcap, etc.) depending on modules enabled.

Roadmap:
- eBPF-based syscall tracing for deeper visibility.
- Remote TLS-based ingest with mutual auth.
- Pluggable backends (Kafka, Elasticsearch).
