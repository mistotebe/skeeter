#include <event2/event.h>
#include <event2/listener.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "imap.h"

#define DEFAULT_SERVER "localhost"
#define DEFAULT_PORT 1143

static void signal_cb(evutil_socket_t, short, void *);

int main(int argc, char** argv)
{
    struct event_base *base;
    struct evconnlistener *listener;
    struct event *signal_event;
    struct imap_driver *driver;

    struct sockaddr_in6 sin;
    evutil_socket_t sock;
    int option = 0, port = 8080;

    char *rhost = DEFAULT_SERVER;
    int rport = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (!port) {
            fprintf(stderr, "Please specify a valid port number or do not provide any parameters for a default one!\n");
            return 1;
        }
    }

    if (argc > 3) {
        rhost = argv[2];
        rport = atoi(argv[3]);
        if (!rport) {
            fprintf(stderr, "Please specify a valid port number or do not provide any parameters for a default one!\n");
            return 1;
        }
    }

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Could not initialize libevent!\n");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_addr = in6addr_any;
    sin.sin6_port = htons(port);

    if ((sock = socket(AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
        perror("socket");
        return 1;
    }

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &option, sizeof(option))) {
        perror("setsockopt");
        return 1;
    }

    if (evutil_make_listen_socket_reuseable(sock)) {
        perror("reuseaddr");
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin))) {
        perror("bind");
        return 1;
    }

    driver = imap_driver_init(base, rhost, rport);

    listener = evconnlistener_new(base, listen_cb, (void*)driver,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, sock);

    /*
    listener = evconnlistener_new_bind(base, listen_cb, (void*)base,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
    */

    if (!listener) {
        fprintf(stderr, "Could not create a listener!\n");
        return 1;
    }

    signal_event = event_new(base, SIGINT, EV_SIGNAL, signal_cb, base);

    if (!signal_event || event_add(signal_event, NULL) < 0) {
        fprintf(stderr, "Could not create/add a signal event!\n");
        return 1;
    }

    /* run */
    event_base_dispatch(base);

    /* we've stopped, exit */
    evconnlistener_free(listener);
    event_base_free(base);
    //SSL_CTX_free(ctx);

    return 0;
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
    struct event_base *base = user_data;
    struct timeval delay = { 2, 0 };

    printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");

    event_base_loopexit(base, &delay);
}
