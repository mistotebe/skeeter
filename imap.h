#ifndef _IMAP_H
#define _IMAP_H

#include "avl/avl.h"
#include "ssl.h"
#include "module.h"
#include <lber.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <libconfig.h>

#define IMAP_OK 0
#define IMAP_TOCONTINUE 1
#define IMAP_NEED_MORE 2
#define IMAP_DONE 3
#define IMAP_SHUTDOWN 4

#define CRLF "\r\n"

/*FIXME: these should match Cyrus messages */
#define AUTH_FAILED_MSG "NO Authentication failed"
#define AUTH_ABORTED_MSG "BAD Authentication aborted"

struct imap_driver;
struct imap_config;
struct imap_context;
struct imap_request;

extern struct module imap_module;

typedef int (*imap_request_handler)(struct imap_context *, struct imap_request *, void *);

typedef enum {
    ARG_ATOM,
    ARG_QUOTED,
    ARG_LITERAL,
    ARG_BINARY /* unimplemented */
} arg_type;

struct imap_arg {
    arg_type arg_type;
    struct berval value;
#define arg_len value.bv_len
#define arg_val value.bv_val

//    STAILQ_ENTRY(imap_arg) next;
};

typedef enum {
    /* only login params can contain literal */
    IMAP_MULTILINE = 0x1,
    IMAP_TLS = 0x2,
    IMAP_AUTHENTICATED = 0x4
} imap_flags;

struct imap_config {
    char *listen;
    char *default_host;
    int default_port;
    char *cert, *pkey;
};

struct imap_driver {
    struct event_base *base;
    struct evdns_base *dnsbase;
    struct evconnlistener *listener;

    struct imap_config *config;

    struct module *ldap;

    Avlnode *commands;
    SSL_CTX *ssl_ctx;
};

struct imap_context {
    struct imap_driver *driver;
    struct bufferevent *client_bev, *server_bev;

    imap_flags state;
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

int imap_driver_config(struct module *, config_setting_t *);
int imap_driver_init(struct module *, struct event_base *);
int imap_handle_request(struct imap_context *, struct imap_request *);

#endif /* _IMAP_H */
