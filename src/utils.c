#define _GNU_SOURCE
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

char *iso8601_now(void) {
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    char *buf = malloc(30);
    strftime(buf, 30, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

int ensure_dir(const char *path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    return mkdir(path, mode);
}