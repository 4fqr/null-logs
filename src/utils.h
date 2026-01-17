#ifndef NULL_LOGS_UTILS_H
#define NULL_LOGS_UTILS_H

#include <time.h>
#include <sys/types.h>

char *iso8601_now(void);
int ensure_dir(const char *path, mode_t mode);

#endif // NULL_LOGS_UTILS_H