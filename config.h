#ifndef _SKEETER_CONFIG_H
#define _SKEETER_CONFIG_H

#include "avl/avl.h"

struct config {
    int debug, shutdown;
    char *conffile;
    Avlnode *modules;
};

extern struct config config;

int parse_options(int, char **, struct config *);
int process_config_file(struct config *);

#endif /* _SKEETER_CONFIG_H */
