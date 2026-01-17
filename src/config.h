#ifndef NULL_LOGS_CONFIG_H
#define NULL_LOGS_CONFIG_H

struct nl_config {
    char log_path[256];
    char key_file[256];
    int enable_fanotify;
    int enable_proc;
    int enable_ebpf;
};

int config_load(const char *path, struct nl_config *cfg);

#endif // NULL_LOGS_CONFIG_H