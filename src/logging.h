#ifndef NULL_LOGS_LOGGING_H
#define NULL_LOGS_LOGGING_H

#include <stdio.h>

int logging_init(const char *path, const char *keyfile);
void logging_close(void);
int log_event_json(const char *category, const char *event_type, const char *json_payload);

/* additional helpers */
int load_key(const char *keyfile);
int rotate_logfile(const char *path);
int verify_log_line(const char *line, const char *keyfile);

#endif // NULL_LOGS_LOGGING_H