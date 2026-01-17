#ifdef USE_LIBBPF
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/ringbuf.h>
#include "ebpf_loader.h"
#include "logging.h"

struct syscall_event {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u64 id;
    __u64 args[6];
};

static struct ring_buffer *rb = NULL;
static struct bpf_object *obj = NULL;
static int prog_fd = -1;
static int events_map_fd = -1;
static volatile int worker_running = 0;
static pthread_t worker_thread;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct syscall_event)) return 0;
    struct syscall_event *e = data;
    // build JSON payload
    char payload[512];
    int n = snprintf(payload, sizeof(payload), "{\"pid\":%u,\"tgid\":%u,\"syscall\":%llu,\"args\":[%llu,%llu,%llu,%llu,%llu,%llu],\"ts_ns\":%llu}",
                     e->pid, e->tgid, (unsigned long long)e->id,
                     (unsigned long long)e->args[0], (unsigned long long)e->args[1], (unsigned long long)e->args[2], (unsigned long long)e->args[3], (unsigned long long)e->args[4], (unsigned long long)e->args[5],
                     (unsigned long long)e->ts);
    if (n > 0) log_event_json("syscall", "enter", payload);
    return 0;
}

static void *worker_fn(void *arg) {
    (void)arg;
    worker_running = 1;
    while (worker_running) {
        int r = ring_buffer__poll(rb, 100 /*ms*/);
        if (r < 0 && r != -EINTR) {
            // error
            break;
        }
    }
    return NULL;
}

int ebpf_init(const char *obj_path) {
    int err;
    struct bpf_object_open_attr open_attr = {0};
    open_attr.file = obj_path;
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "libbpf: failed to open %s\n", obj_path);
        return -1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "libbpf: failed to load BPF object\n");
        bpf_object__close(obj); obj = NULL; return -1;
    }

    // find map 'events'
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) { fprintf(stderr, "no map 'events' in object\n"); bpf_object__close(obj); obj=NULL; return -1; }
    events_map_fd = bpf_map__fd(map);
    if (events_map_fd < 0) { bpf_object__close(obj); obj = NULL; return -1; }

    rb = ring_buffer__new(events_map_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer setup failed\n"); bpf_object__close(obj); obj = NULL; return -1; }

    if (pthread_create(&worker_thread, NULL, worker_fn, NULL) != 0) {
        ring_buffer__free(rb); rb = NULL; bpf_object__close(obj); obj = NULL; return -1;
    }

    return 0;
}

void ebpf_shutdown(void) {
    if (worker_running) { worker_running = 0; pthread_join(worker_thread, NULL); }
    if (rb) { ring_buffer__free(rb); rb = NULL; }
    if (obj) { bpf_object__close(obj); obj = NULL; }
}

#else
#include "ebpf_loader.h"
int ebpf_init(const char *obj_path) { (void)obj_path; return -1; }
void ebpf_shutdown(void) { }
#endif
