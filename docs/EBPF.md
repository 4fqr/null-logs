# eBPF module (syscall tracing)

Null-Logs includes an optional eBPF module that captures sys_enter tracepoints and delivers events via ring buffer.

Building

- Install dependencies (Debian/Ubuntu):
  sudo apt-get install -y clang libbpf-dev libelf-dev llvm

- Build with eBPF enabled:
  make LIBBPF=1

Runtime

- eBPF component requires root to load programs. Start the daemon as root or via systemd with the `null-logs` service.
- You can run a smoke test (if you are root and libbpf is installed):
  sudo sh tests/test_ebpf.sh

Notes

- eBPF program is in `src/ebpf/syscalls.bpf.c` and is compiled to `src/ebpf/syscalls.bpf.o` by the `Makefile` when `LIBBPF=1`.
- The loader uses `libbpf` and ring buffer to receive events and emit `syscall` category logs containing syscall id and args.
- In production, review and limit the eBPF probing surface to avoid performance impact; consider filtering by cgroup or pid namespaces.
