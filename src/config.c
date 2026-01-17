#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int config_load(const char *path, struct nl_config *cfg) {
    // defaults
    snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", "/var/log/null-logs/null-logs.log");
    snprintf(cfg->key_file, sizeof(cfg->key_file), "%s", "/etc/null-logs/key");
    cfg->enable_fanotify = 1;
    cfg->enable_proc = 1;
    cfg->enable_ebpf = 1;

    FILE *f = fopen(path, "r");
    if (!f) return 0; // no config, use defaults
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p==' '||*p=='\t') p++;
        if (*p=='#' || *p=='\n' || *p=='\0') continue;
        char key[128], val[256];
        if (sscanf(p, "%127[^=]=%255s", key, val) == 2) {
            if (strcmp(key, "log_path") == 0) snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", val);
            else if (strcmp(key, "key_file") == 0) snprintf(cfg->key_file, sizeof(cfg->key_file), "%s", val);
            else if (strcmp(key, "enable_fanotify") == 0) cfg->enable_fanotify = atoi(val);
            else if (strcmp(key, "enable_proc") == 0) cfg->enable_proc = atoi(val);
        }
    }
    fclose(f);
    return 0;
}