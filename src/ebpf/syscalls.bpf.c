#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct syscall_event {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u64 id;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    __u64 tgid_pid = bpf_get_current_pid_tgid();
    e->tgid = (uint32_t)(tgid_pid >> 32);
    e->pid = (uint32_t)tgid_pid;
    e->id = ctx->id;
    // copy args (ctx->args is pointer to array)
    bpf_probe_read_kernel(&e->args, sizeof(e->args), ctx->args);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";