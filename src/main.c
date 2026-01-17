#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include "daemon.h"
#include "config.h"
#include "logging.h"

#define PIDFILE "/run/null-logs/null-logs.pid"

static int write_pidfile(pid_t pid) {
    if (mkdir("/run/null-logs", 0750) != 0) {
        if (errno != EEXIST) return -1;
    }
    FILE *f = fopen(PIDFILE, "w");
    if (!f) return -1;
    fprintf(f, "%d\n", (int)pid);
    fclose(f);
    return 0;
}

static pid_t read_pidfile(void) {
    FILE *f = fopen(PIDFILE, "r");
    if (!f) return -1;
    int p = -1;
    if (fscanf(f, "%d", &p) != 1) p = -1;
    fclose(f);
    return (pid_t)p;
}

static int remove_pidfile(void) {
    return unlink(PIDFILE);
}

void usage(const char *p) {
    printf("Null-Logs CLI - production-grade Linux activity logger\n\n");
    printf("Usage: %s <command> [args]\n", p);
    printf("Commands:\n");
    printf("  start        Start daemon (background)\n");
    printf("  foreground   Run daemon in foreground (useful for debugging)\n");
    printf("  stop         Stop daemon (uses pidfile %s)\n", PIDFILE);
    printf("  status       Show if daemon is running\n");
    printf("  verify [file]  Verify HMAC signatures in log file (defaults to configured log)\n");
    printf("  query [file]   Print log file (defaults to configured log)\n");
    printf("  rotate       Rotate logfile (HUP semantics)\n");
    printf("  version      Show version info\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    struct nl_config cfg;
    config_load("/etc/null-logs/null-logs.conf", &cfg);
    /* Allow environment overrides for tests and runtime configuration */
    const char *env_key = getenv("NULL_LOGS_KEYFILE");
    if (env_key && env_key[0]) snprintf(cfg.key_file, sizeof(cfg.key_file), "%s", env_key);
    const char *env_log = getenv("NULL_LOGS_LOGPATH");
    if (env_log && env_log[0]) snprintf(cfg.log_path, sizeof(cfg.log_path), "%s", env_log);

    if (strcmp(argv[1], "start") == 0) {
        // daemonize
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid > 0) { // parent
            if (write_pidfile(pid) != 0) fprintf(stderr, "warning: failed to write pidfile\n");
            printf("Started (pid %d)\n", pid);
            return 0;
        }
        // child
        setsid();
        if (chdir("/") != 0) { perror("chdir"); _exit(1); }
        umask(027);
        // simple redirection
        fclose(stdin);
        fclose(stdout);
        fclose(stderr);
        // run
        return daemon_start(&cfg);
    } else if (strcmp(argv[1], "stop") == 0) {
        pid_t pid = read_pidfile();
        if (pid <= 0) { fprintf(stderr, "No pid or pidfile not found\n"); return 1; }
        if (kill(pid, SIGTERM) != 0) { perror("kill"); return 1; }
        remove_pidfile();
        printf("Stopped (pid %d)\n", (int)pid);
        return 0;
    } else if (strcmp(argv[1], "status") == 0) {
        pid_t pid = read_pidfile();
        if (pid <= 0) { printf("not running\n"); return 3; }
        if (kill(pid, 0) == 0) { printf("running (pid %d)\n", (int)pid); return 0; }
        else { printf("stale pidfile (pid %d)\n", (int)pid); return 4; }
    } else if (strcmp(argv[1], "foreground") == 0) {
        return daemon_start(&cfg);
    } else if (strcmp(argv[1], "verify") == 0) {
        const char *file = cfg.log_path;
        if (argc >= 3) file = argv[2];
        FILE *f = fopen(file, "r");
        if (!f) { perror("fopen"); return 1; }
        char *line = NULL; size_t sz = 0; int line_no = 0; int failures = 0;
        const char *use_key = getenv("NULL_LOGS_KEYFILE");
        if (!use_key || !use_key[0]) use_key = cfg.key_file;
        if (load_key(use_key) != 0) { fprintf(stderr, "failed to load key (%s)\n", use_key); return 1; }
        while (getline(&line, &sz, f) > 0) {
            line_no++;
            if (verify_log_line(line, use_key) != 0) {
                printf("Line %d: signature INVALID\n", line_no); failures++;
            }
        }
        free(line); fclose(f);
        if (failures==0) printf("All signatures valid\n");
        return failures==0 ? 0 : 2;
    } else if (strcmp(argv[1], "query") == 0) {
        const char *file = cfg.log_path;
        if (argc >= 3) file = argv[2];
        FILE *f = fopen(file, "r");
        if (!f) { perror("fopen"); return 1; }
        char *line = NULL; size_t sz = 0;
        while (getline(&line, &sz, f) > 0) {
            puts(line);
        }
        free(line);
        fclose(f);
        return 0;
    } else if (strcmp(argv[1], "rotate") == 0) {
        if (rotate_logfile(cfg.log_path) == 0) { printf("rotated\n"); return 0; }
        else { printf("rotate failed\n"); return 1; }
    } else if (strcmp(argv[1], "version") == 0) {
        printf("Null-Logs %s\n", VERSION);
        return 0;
    }
    usage(argv[0]);
    return 1;
}