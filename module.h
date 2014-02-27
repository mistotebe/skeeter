#ifndef _SKEETER_MODULE_H
#define _SKEETER_MODULE_H

#include <event2/event.h>
#include <libconfig.h>

struct module;

typedef int (*config_cb)(struct module *, config_setting_t *);
typedef int (*init_cb)(struct module *, struct event_base *);
typedef void (*shutdown_cb)(struct module *);
typedef void (*destroy_cb)(struct module *);

typedef enum {
    MODULE_READY = 0x1,
    MODULE_UNAVAILABLE = 0x2,
    MODULE_SHUTDOWN = 0x4,
    MODULE_ANY = 0xff,
    MODULE_PERSIST = 0x8000,
    MODULE_SPECIFIC = 0xffff0000
} module_event_flags;

typedef void (*module_event_cb)(module_event_flags, void *);
typedef int (*register_module_event)(struct module *, module_event_flags, module_event_cb, void *);

struct module {
    char *name;
    config_cb conf;
    init_cb init;
    register_module_event register_event;
    shutdown_cb shutdown;
    destroy_cb destroy;
    void *priv;
};

extern struct module *modules[];

int register_module(struct module *);
struct module *get_module(char *);

struct evdns_base *get_dnsbase();

#endif /* _SKEETER_MODULE_H */
