#include <event2/event.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "config.h"
#include "logging.h"
#include "imap.h"

static int detach(struct event_base *base);
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

    if (initialize_modules(base))
        return 1;

    signal_event = event_new(base, SIGINT, EV_SIGNAL, signal_cb, base);

    if (!signal_event || event_add(signal_event, NULL) < 0) {
        skeeter_log(LOG_CRIT, "Could not create/add a signal event!");
        return 1;
    }

    if (!config.debug) {
        if (detach(base)) {
            skeeter_log(LOG_CRIT, "Failed to detach");
            return 1;
        }
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
    if (!config.debug)
        unlink(config.pidfile);

    return 0;
}

static int
detach(struct event_base *base)
{
    int fd, rc = 0;
    char *path;

    skeeter_log(LOG_NOTICE, "Detaching");

    fd = creat(config.pidfile, 0644);
    if (fd < 0) {
        rc = fd;
        goto done;
    }

    /* The pidfile location could have been a relative path, but we are
     * changing our dir to '/' and need an absolute one instead.
     * realpath() requires that the file exists, so it cannot be done any
     * sooner.
     */
    path = realpath(config.pidfile, NULL);
    if (!path) {
        rc = 1;
        goto done;
    }
    config.pidfile = path;

    rc = daemon(0, 0);
    if (rc) goto done;

    rc = event_reinit(base);
    if (rc) goto done;

    dprintf(fd, "%d", getpid());
    rc = close(fd);
    if (rc) goto done;

done:
    return rc;
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
