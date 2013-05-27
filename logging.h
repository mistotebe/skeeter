#ifndef _LOGGING_H
#define _LOGGING_H

/* for LOG_* level macros */
#include <syslog.h>
#include "module.h"

extern struct module logging_module;

int logging_setup(struct module *, config_setting_t *);
void skeeter_event_log(int, const char *);

#if SKEETER_DEBUG
#define debug(...) skeeter_log(__VA_ARGS__)
#else
#define debug(...) (void)0
#endif

void skeeter_log(int, const char *, ...)
        __attribute__ ((__format__ (__printf__, 2, 3)));

#endif /* _LOGGING_H */
