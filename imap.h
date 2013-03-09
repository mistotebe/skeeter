#ifndef _IMAP_H
#define _IMAP_H

#include "avl/avl.h"
#include "ssl.h"
#include <lber.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>

#define IMAP_OK 0
#define IMAP_TOCONTINUE 1
#define IMAP_NEED_MORE 2
#define IMAP_DONE 3
#define IMAP_SHUTDOWN 4

#define CRLF "\r\n"

struct imap_driver;
struct imap_context;
struct imap_request;

typedef int (*imap_request_handler)(struct imap_context *, struct imap_request *, void *);

typedef enum {
    imap_nonauth,
    imap_auth,
    imap_select
} imap_state;

struct imap_driver {
    struct event_base *base;
    struct evdns_base *dnsbase;
    struct evconnlistener *listener;

    char *remote_host;
    int remote_port;

    Avlnode *commands;
    SSL_CTX *ssl_ctx;
};

struct imap_context {
    struct imap_driver *driver;
    struct bufferevent *client_bev, *server_bev;

    imap_state state;
};

struct imap_handler {
    char *command;
    imap_request_handler handler;
    void *priv;
};

struct imap_request {
    BerValue tag;
    BerValue command;
    BerValue arguments;
    BerValue line;
};

int imap_handler_cmp(const void *, const void *);

struct imap_driver *imap_driver_init(struct event_base *, char *, int, int);
int imap_handle_request(struct imap_context *, struct imap_request *);

#endif /* _IMAP_H */
