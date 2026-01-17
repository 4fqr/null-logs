#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include "daemon.h"
#include "logging.h"
#include "utils.h"
#ifdef USE_LIBBPF
#include "ebpf_loader.h"
#endif

static int nl_sock = -1;
static int fan_fd = -1;

int setup_proc_connector() {
    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock < 0) return -1;
    struct sockaddr_nl sa_nl;
    memset(&sa_nl, 0, sizeof(sa_nl));
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();
    if (bind(nl_sock, (struct sockaddr*)&sa_nl, sizeof(sa_nl)) < 0) return -1;
    // subscribe
    struct {
        struct nlmsghdr nl;
        struct cn_msg cn;
        enum proc_cn_mcast_op op;
    } __attribute__((packed)) msg;
    memset(&msg, 0, sizeof(msg));
    msg.nl.nlmsg_len = sizeof(msg);
    msg.nl.nlmsg_type = NLMSG_DONE;
    msg.nl.nlmsg_flags = 0;
    msg.cn.id.idx = CN_IDX_PROC;
    msg.cn.id.val = CN_VAL_PROC;
    msg.cn.len = sizeof(enum proc_cn_mcast_op);
    msg.op = PROC_CN_MCAST_LISTEN;
    if (send(nl_sock, &msg, sizeof(msg), 0) < 0) return -1;
    return nl_sock;
}

int setup_fanotify() {
    fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (fan_fd < 0) return -1;
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE, AT_FDCWD, "/") < 0) return -1;
    return fan_fd;
}

#include <sys/types.h>
#include <pwd.h>
#include <signal.h>

static volatile sig_atomic_t running = 1;

static void sighandler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) running = 0;
    if (sig == SIGHUP) {
        // rotate log
        rotate_logfile("/var/log/null-logs/null-logs.log");
    }
}

void handle_proc_event(struct cn_msg *cn) {
    if (!cn) return;
    struct proc_event *ev = (struct proc_event *)cn->data;
    char payload[1024];
    switch (ev->what) {
        case PROC_EVENT_FORK: {
            snprintf(payload, sizeof(payload), "{\"pid\": %u, \"ppid\": %u}", ev->event_data.fork.child_pid, ev->event_data.fork.parent_pid);
            log_event_json("process", "fork", payload);
            break;
        }
        case PROC_EVENT_EXEC: {
            pid_t pid = ev->event_data.exec.process_pid;
            char cmd[512] = "";
            char exe[PATH_MAX] = "";
            char cmdpath[64];
            snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", pid);
            FILE *f = fopen(cmdpath, "r");
            if (f) {
                size_t r = fread(cmd, 1, sizeof(cmd)-1, f);
                for (size_t i=0;i<r;i++) if (cmd[i]=='\0') cmd[i]=' ';
                fclose(f);
            }
            char exepath[64]; snprintf(exepath, sizeof(exepath), "/proc/%d/exe", pid);
            ssize_t l = readlink(exepath, exe, sizeof(exe)-1);
            if (l > 0) exe[l]='\0'; else exe[0]='\0';
            snprintf(payload, sizeof(payload), "{\"pid\": %u, \"exe\": \"%s\", \"cmdline\": \"%s\"}", pid, exe, cmd);
            log_event_json("process", "exec", payload);
            break;
        }
        case PROC_EVENT_EXIT: {
            snprintf(payload, sizeof(payload), "{\"pid\": %u, \"exit_code\": %u}", ev->event_data.exit.process_pid, ev->event_data.exit.exit_code);
            log_event_json("process", "exit", payload);
            break;
        }
        default:
            break;
    }
}

void run_loop() {
    struct pollfd fds[2];
    fds[0].fd = nl_sock; fds[0].events = POLLIN;
    fds[1].fd = fan_fd; fds[1].events = POLLIN;
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGHUP, sighandler);

    while (running) {
        int r = poll(fds, 2, 1000);
        if (r < 0) { if (errno==EINTR) continue; break; }
        if (r == 0) continue; // timeout, check running
        if (fds[0].revents & POLLIN) {
            char buf[4096];
            int len = recv(nl_sock, buf, sizeof(buf), 0);
            if (len <= 0) continue;
            struct nlmsghdr *nlh = (struct nlmsghdr*)buf;
            for (; NLMSG_OK(nlh, (unsigned)len); nlh = NLMSG_NEXT(nlh, len)) {
                struct cn_msg *cn = (struct cn_msg*)NLMSG_DATA(nlh);
                handle_proc_event(cn);
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = 0;
            char buf[8192];
            len = read(fan_fd, buf, sizeof(buf));
            if (len <= 0) continue;
            ssize_t offset = 0;
            while (offset < len) {
                struct fanotify_event_metadata *md = (struct fanotify_event_metadata *)(buf + offset);
                if (md->vers != FANOTIFY_METADATA_VERSION) break;
                if (md->mask & FAN_Q_OVERFLOW) {
                    log_event_json("fs", "overflow", "{}");
                } else if (md->fd >= 0) {
                    char linkpath[64]; char path[PATH_MAX];
                    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", md->fd);
                    ssize_t l = readlink(linkpath, path, sizeof(path)-1);
                    if (l > 0) { path[l] = '\0'; }
                    else path[0] = '\0';

                    char payload[1024];
                    snprintf(payload, sizeof(payload), "{\"fd\":%d,\"pid\":%d,\"path\":\"%s\"}", md->fd, md->pid, path);
                    log_event_json("fs", "access", payload);
                    close(md->fd);
                }
                offset += md->event_len;
            }
        }
    }
    // cleanup
    if (nl_sock >= 0) close(nl_sock);
    if (fan_fd >= 0) close(fan_fd);
}

int daemon_start(const struct nl_config *cfg) {
    if (logging_init(cfg->log_path, cfg->key_file) != 0) {
        fprintf(stderr, "failed to init logging\n");
        return -1;
    }
#ifdef USE_LIBBPF
    if (cfg->enable_ebpf) {
        if (ebpf_init("src/ebpf/syscalls.bpf.o") == 0) {
            log_event_json("system", "ebpf", "{\"status\":\"started\"}");
        } else {
            log_event_json("system", "ebpf", "{\"status\":\"failed\"}");
        }
    }
#endif
    if (cfg->enable_proc) {
        if (setup_proc_connector() < 0) {
            fprintf(stderr, "failed to setup proc connector\n");
            return -1;
        }
    }
    if (cfg->enable_fanotify) {
        if (setup_fanotify() < 0) {
            fprintf(stderr, "failed to setup fanotify\n");
            return -1;
        }
    }
    log_event_json("system", "started", "{}");
    run_loop();
    log_event_json("system", "stopped", "{}");
#ifdef USE_LIBBPF
    ebpf_shutdown();
#endif
    logging_close();
    return 0;
}