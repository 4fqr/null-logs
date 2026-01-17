#define _GNU_SOURCE
#include "logging.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>

static int log_fd = -1;
static FILE *log_fp = NULL;
static unsigned char *hmac_key = NULL;
static size_t hmac_key_len = 0;

static char *read_random_uuid(void) {
    FILE *f = fopen("/proc/sys/kernel/random/uuid", "r");
    if (!f) return NULL;
    char *buf = malloc(40);
    if (!fgets(buf, 40, f)) { free(buf); buf = NULL; }
    fclose(f);
    if (buf) {
        size_t n = strlen(buf);
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) { buf[--n] = '\0'; }
    }
    return buf;
}

int load_key(const char *keyfile) {
    int fd = open(keyfile, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "load_key: open(%s) failed: %s\n", keyfile, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { fprintf(stderr, "load_key: fstat(%s) failed: %s\n", keyfile, strerror(errno)); close(fd); return -1; }
    if (st.st_size <= 0 || st.st_size > 1024) { fprintf(stderr, "load_key: unexpected size %lld for %s\n", (long long)st.st_size, keyfile); close(fd); return -1; }
    hmac_key = malloc(st.st_size + 1);
    if (!hmac_key) { fprintf(stderr, "load_key: malloc failed\n"); close(fd); return -1; }
    ssize_t total = 0;
    while (total < st.st_size) {
        ssize_t r = read(fd, hmac_key + total, st.st_size - total);
        if (r <= 0) break;
        total += r;
    }
    close(fd);
    if (total <= 0) { fprintf(stderr, "load_key: read returned %lld bytes for %s\n", (long long)total, keyfile); free(hmac_key); hmac_key = NULL; return -1; }
    hmac_key[total] = '\0';
    // trim
    while (total > 0 && (hmac_key[total-1] == '\n' || hmac_key[total-1] == '\r')) hmac_key[--total] = '\0';
    hmac_key_len = (size_t)total;
    return 0;
}

int logging_init(const char *path, const char *keyfile) {
    if (ensure_dir("/var/log/null-logs", 0700) != 0) return -1;
    if (load_key(keyfile) != 0) return -1;
    log_fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 0600);
    if (log_fd < 0) return -1;
    log_fp = fdopen(dup(log_fd), "a");
    if (!log_fp) { close(log_fd); log_fd = -1; return -1; }
    setvbuf(log_fp, NULL, _IOLBF, 0);
    return 0;
}

int rotate_logfile(const char *path) {
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
    if (log_fd >= 0) { close(log_fd); log_fd = -1; }
    log_fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 0600);
    if (log_fd < 0) return -1;
    log_fp = fdopen(dup(log_fd), "a");
    if (!log_fp) { close(log_fd); log_fd = -1; return -1; }
    setvbuf(log_fp, NULL, _IOLBF, 0);
    return 0;
}

void logging_close(void) {
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
    if (log_fd >= 0) { close(log_fd); log_fd = -1; }
    if (hmac_key) { explicit_bzero(hmac_key, hmac_key_len); free(hmac_key); hmac_key = NULL; }
}

static void hex_encode(const unsigned char *in, unsigned int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; ++i) { out[i*2] = hex[(in[i] >> 4) & 0xF]; out[i*2+1] = hex[in[i] & 0xF]; }
    out[len*2] = '\0';
}

int log_event_json(const char *category, const char *event_type, const char *json_payload) {
    if (log_fp == NULL) return -1;
    // timestamp and event id
    char *ts = iso8601_now();
    char *eid = read_random_uuid();

    unsigned int siglen = 0;
    unsigned char sig[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), hmac_key, (int)hmac_key_len, (unsigned char*)json_payload, strlen(json_payload), sig, &siglen);
    char sighex[EVP_MAX_MD_SIZE*2 + 1];
    hex_encode(sig, siglen, sighex);

    pid_t pid = getpid();
    char outbuf[4096];
    int n = snprintf(outbuf, sizeof(outbuf), "{\"ts\":\"%s\",\"id\":\"%s\",\"category\":\"%s\",\"type\":\"%s\",\"pid\":%d,\"payload\":%s,\"hmac_sha256\":\"%s\"}\n",
                     ts ? ts : "", eid ? eid : "", category, event_type, (int)pid, json_payload, sighex);
    if (n < 0 || n >= (int)sizeof(outbuf)) {
        free(ts); free(eid); return -1;
    }

    // atomic append with flock
    if (flock(log_fd, LOCK_EX) == 0) {
        ssize_t w = write(log_fd, outbuf, (size_t)n);
        flock(log_fd, LOCK_UN);
        if (w != n) { free(ts); free(eid); return -1; }
    } else {
        free(ts); free(eid); return -1;
    }

    free(ts); free(eid);
    return 0;
}

/* Verify a single JSON log line: return 0 if signature matches, -1 otherwise */
int verify_log_line(const char *line, const char *keyfile) {
    (void)keyfile; // key already loaded in memory
    if (!hmac_key) return -1;
    const char *h = strstr(line, "\"hmac_sha256\":\"");
    if (!h) return -1;
    h += strlen("\"hmac_sha256\":\"");
    const char *h_end = strchr(h, '\"');
    if (!h_end) return -1;
    size_t hlen = h_end - h;
    char *hexsig = strndup(h, hlen);
    // find payload
    const char *p = strstr(line, "\"payload\":");
    if (!p) { free(hexsig); return -1; }
    p = strchr(p, '{');
    if (!p) { free(hexsig); return -1; }
    // simple brace matching
    int depth = 0; const char *q = p;
    while (*q) {
        if (*q == '{') depth++;
        else if (*q == '}') { depth--; if (depth==0) { q++; break; } }
        q++;
    }
    if (depth != 0) { free(hexsig); return -1; }
    size_t payload_len = q - p; // include braces
    char *payload = malloc(payload_len + 1);
    memcpy(payload, p, payload_len);
    payload[payload_len] = '\0';

    unsigned char expected[EVP_MAX_MD_SIZE]; unsigned int expected_len = 0;
    HMAC(EVP_sha256(), hmac_key, (int)hmac_key_len, (unsigned char*)payload, payload_len, expected, &expected_len);
    char expected_hex[EVP_MAX_MD_SIZE*2 + 1]; hex_encode(expected, expected_len, expected_hex);

    int res = (strcmp(expected_hex, hexsig) == 0) ? 0 : -1;
    free(hexsig); free(payload);
    return res;
}