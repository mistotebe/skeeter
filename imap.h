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

#define IMAP_HANDLER_OK 0
#define IMAP_HANDLER_SKIP 1
#define IMAP_HANDLER_ERROR -1

#define STRLENOF(x) (sizeof(x) - 1)
#define bv_const(name, string) struct berval name = { \
    .bv_val = string, \
    .bv_len = STRLENOF(string), \
}

#define CRLF "\r\n"

#define BAD_ARG_NO "BAD Invalid number of arguments"
#define BAD_INVALID "BAD Invalid request"
#define BAD_INVALID_LEN STRLENOF(BAD_INVALID)
#define LITERAL_RESPONSE "+ GO AHEAD"
#define LITERAL_RESPONSE_LEN STRLENOF(LITERAL_RESPONSE)
#define SERVER_ERROR "NO Internal server error"
#define SERVER_ERROR_LEN STRLENOF(SERVER_ERROR)
/*FIXME: these should match Cyrus messages */
#define AUTH_FAILED_MSG "NO Authentication failed"
#define AUTH_FAILED_MSG_LEN STRLENOF(AUTH_FAILED_MSG)
#define AUTH_ABORTED_MSG "BAD Authentication aborted"
#define AUTH_ABORTED_MSG_LEN STRLENOF(AUTH_ABORTED_MSG)

#define CAPABILITY_PREFIX "* CAPABILITY"
#define CAPABILITY_PREFIX_LEN STRLENOF(CAPABILITY_PREFIX)
#define STARTTLS_CAPABILITY "STARTTLS"
#define STARTTLS_CAPABILITY_LEN STRLENOF(STARTTLS_CAPABILITY)
#define SERVER_GREETING "* OK IMAP4rev1 service ready" CRLF
#define SERVER_GREETING_LEN STRLENOF(SERVER_GREETING)

struct imap_driver;
struct imap_config;
struct imap_context;
struct imap_handler;
struct imap_request;

extern struct module imap_module;

typedef int (*imap_handler_init)(struct imap_driver *, struct imap_handler *);
/**
 * Handles the request.
 * Return codes:
 * - IMAP_OK: processing can continue normally
 * - IMAP_DONE: handler wants to take control over the bufferevent,
 *              by doing so it needs to take care of freeing the imap_request
 *              pointer (most likely needs to take over the bufferevent's
 *              event_cb as well). To give control back to the request
 *              handling, call imap_resume()
 * - IMAP_SHUTDOWN: the connection should be closed
 * - everything else is considered an error and closes the connection as if
 *   IMAP_SHUTDOWN was returned
 */
typedef int (*imap_request_handler)(struct imap_context *, struct imap_request *, void *);

typedef enum {
    ARG_UNKNOWN,
    ARG_ATOM,
    ARG_QUOTED,
    ARG_LITERAL,
    ARG_BINARY, /* unimplemented */
    ARG_TYPES = 0xff,
#define ARG_TYPE(x) ((x) & ARG_TYPES)
    ARG_LAST = 0x100,
} arg_type;

struct imap_arg {
    arg_type arg_type;
    size_t arg_len;
    struct evbuffer *buffer;

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
    struct capability {
        char **common, **plain, **tls;
    } capability;
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
    void *priv;
};

struct imap_handler {
    char *command;
    imap_request_handler handler;
    imap_handler_init init;
    void *priv;
};

struct imap_request {
    BerValue tag;
    BerValue command;
    void *priv;
};

int imap_handler_cmp(const void *, const void *);

int imap_driver_config(struct module *, config_setting_t *);
int imap_driver_init(struct module *, struct event_base *);
int imap_handle_request(struct imap_context *, struct imap_request *);

/**
 * Reestablishes the IMAP request handling on the bufferevent. If last argument
 * is non-NULL, it will be freed.
 */
void imap_resume(struct bufferevent *, struct imap_context *, struct imap_request *);

#endif /* _IMAP_H */
