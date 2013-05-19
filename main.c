#include <event2/event.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "config.h"
#include "logging.h"
#include "imap.h"

static void signal_cb(evutil_socket_t, short, void *);

int main(int argc, char** argv)
{
    struct event_base *base;
    struct event *signal_event;
    struct module **p;

    if (parse_options(argc, argv, &config)) {
        return 1;
    }

    if (process_config_file(&config)) {
        return 1;
    }

    base = event_base_new();
    if (!base) {
        skeeter_log(LOG_CRIT, "Could not initialize libevent!");
        return 1;
    }

    for (p = modules; *p; p++) {
        struct module *module = *p;
        if (!module->init)
            continue;

        if (module->init(module, base)) {
            skeeter_log(LOG_CRIT, "Could not initialize module '%s'", module->name);
            return 1;
        }
    }

    signal_event = event_new(base, SIGINT, EV_SIGNAL, signal_cb, base);

    if (!signal_event || event_add(signal_event, NULL) < 0) {
        skeeter_log(LOG_CRIT, "Could not create/add a signal event!");
        return 1;
    }

    /* run */
    event_base_dispatch(base);

    event_free(signal_event);
    for (p = modules; *p; p++) {
        struct module *module = *p;
        if (module->destroy)
            module->destroy(module);
    }

    /* we've stopped, exit */
    event_base_free(base);

    return 0;
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
    struct event_base *base = user_data;
    struct timeval delay = { 2, 0 };
    struct module **p;

    skeeter_log(LOG_ERR, "Caught an interrupt signal; exiting cleanly in two seconds.");

    for (p = modules; *p; p++) {
        struct module *module = *p;
        if (module->shutdown)
            module->shutdown(module);
    }

    event_base_loopexit(base, &delay);
}
