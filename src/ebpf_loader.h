#ifndef NULL_LOGS_EBPF_LOADER_H
#define NULL_LOGS_EBPF_LOADER_H

int ebpf_init(const char *obj_path);
void ebpf_shutdown(void);

#endif // NULL_LOGS_EBPF_LOADER_H