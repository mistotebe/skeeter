#ifndef _SKEETER_CONFIG_H
#define _SKEETER_CONFIG_H

#include "avl/avl.h"

#define conf_get_string(target, setting) \
    do { \
        const char *val = config_setting_get_string(setting); \
        if (val != NULL) { \
            asprintf(&(target), "%s", val); \
        } \
    } while (0)

struct config {
    int debug, shutdown;
    char *conffile;
    Avlnode *modules;
};

extern struct config config;

int parse_options(int, char **, struct config *);
int process_config_file(struct config *);

#endif /* _SKEETER_CONFIG_H */
