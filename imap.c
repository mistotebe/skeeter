#define _GNU_SOURCE
#include "imap.h"
#include "ldap.h"
#include "config.h"
#include "module.h"
#include "logging.h"
#include "chaining.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <ldap.h>

static int imap_driver_install(struct bufferevent *, struct imap_driver *);
static int imap_handler_tls_init(struct imap_driver *, struct imap_handler *);
static int imap_handler_capability_init(struct imap_driver *, struct imap_handler *);

static int parse_request(struct imap_request *, struct evbuffer *, ssize_t);
static void request_free(struct imap_request *);
static int imap_sp(struct chain *, struct bufferevent *, void *);
static int imap_astring(struct chain *, struct bufferevent *, void *);

static void trigger_listener(module_event_flags, void *);
static void listen_cb(struct evconnlistener *, evutil_socket_t, struct sockaddr *, int socklen, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb_with_req(struct bufferevent *, short, void *);
static void conn_eventcb(struct bufferevent *, short, void *);

static int imap_capability(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_starttls(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_login(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_noop(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_logout(struct imap_context *ctx, struct imap_request *req, void *priv);

static int imap_login_cleanup(struct chain *, struct bufferevent *, int, void *);
static int imap_credential_check(struct chain *, struct bufferevent *, void *);
static void search_cb(LDAP *, LDAPMessage *, void *);

static void proxy_cb(struct bufferevent *, void *);
static void server_event_cb(struct bufferevent *, short, void *);
static void proxy_error_cb(struct bufferevent *, short, void *);

static struct imap_handler handlers[] = {
    { "STARTTLS", imap_starttls, imap_handler_tls_init },
    { "CAPABILITY", imap_capability, imap_handler_capability_init },
    { "LOGIN", imap_login },
    { "NOOP", imap_noop },
    { "LOGOUT", imap_logout },
    /*
    { "AUTHENTICATE", imap_authenticate },
    */
    { NULL }
};

static char *capability_common_default[] = { "IMAP4rev1", NULL };
static char *capability_plain_default[] = { "LOGINDISABLED", NULL };
static char *capability_tls_default[] = { NULL };

bv_const(newline, CRLF);
bv_const(login, " LOGIN");

static struct imap_config config_default = {
    .listen = "127.0.0.1:1143",
    .default_host = "localhost",
    .default_port = 143,
    .capability = {
        .common = capability_common_default,
        .plain = capability_plain_default,
        .tls = capability_tls_default,
    },
};

struct module imap_module = {
    .name = "imap",
    .conf = imap_driver_config,
    .init = imap_driver_init,
};

int
imap_handler_cmp(const void *left, const void *right)
{
    const struct imap_handler *l = left;
    const struct imap_handler *r = right;
    return strcasecmp(l->command, r->command);
}

int
imap_driver_config(struct module *module, config_setting_t *conf)
{
    config_setting_t *setting, *value;
    struct imap_config *config;
    struct imap_driver *driver;
    int port;

    config = malloc(sizeof(struct imap_config));
    if (config == NULL)
        return 1;
    *config = config_default;

    setting = config_setting_get_member(conf, "listen");
    if (setting) {
        /* in the future there are going to be more listen addresses but not
         * right now */
        value = config_setting_get_elem(setting, 0);
        if (value == NULL) {
            skeeter_log(LOG_CRIT, "Invalid listen address");
            return 1;
        }

        conf_get_string(config->listen, value);
    }

    /*TODO: prime for a rewrite */
    setting = config_setting_get_member(conf, "defaults");
    if (setting) {

        value = config_setting_get_elem(setting, 0);
        if (value == NULL) {
            skeeter_log(LOG_CRIT, "Default remote host address missing");
            return 1;
        }

        conf_get_string(config->default_host, value);

        value = config_setting_get_elem(setting, 1);
        if (value == NULL) {
            skeeter_log(LOG_CRIT, "Default remote port missing");
            return 1;
        }

        port = config_setting_get_int(value);
        if ((port > 0) && (port <= 65535)) {
            config->default_port = port;
        } else {
            skeeter_log(LOG_CRIT, "Invalid remote port");
            return 1;
        }
    }

    setting = config_setting_get_member(conf, "tls");
    if (setting != NULL) {
        value = config_setting_get_elem(setting, 0);
        if (value == NULL) {
            skeeter_log(LOG_CRIT, "SSL server cert missing");
            return 1;
        }

        conf_get_string(config->cert, value);

        value = config_setting_get_elem(setting, 1);
        if (value == NULL) {
            skeeter_log(LOG_CRIT, "SSL server key missing");
            return 1;
        }

        conf_get_string(config->pkey, value);
    }

    setting = config_setting_get_member(conf, "capability");
    if (setting != NULL) {
        int i, len;

        value = config_setting_get_member(setting, "common");
        if (value) {
            if (!config_setting_is_aggregate(value)) {
                skeeter_log(LOG_CRIT, "Invalid capability configuration in section common");
                return 1;
            }

            len = config_setting_length(value);
            config->capability.common = calloc(len + 1, sizeof(char *));
            if (config->capability.common == NULL)
                return 1;

            for (i = 0; i < len; i++) {
                conf_get_string(config->capability.common[i],
                                config_setting_get_elem(value, i));
            }
        }

        value = config_setting_get_member(setting, "plain");
        if (value) {
            if (!config_setting_is_aggregate(value)) {
                skeeter_log(LOG_CRIT, "Invalid capability configuration in section plain");
                return 1;
            }

            len = config_setting_length(value);
            config->capability.plain = calloc(len + 1, sizeof(char *));
            if (config->capability.plain == NULL)
                return 1;

            for (i = 0; i < len; i++) {
                conf_get_string(config->capability.plain[i],
                                config_setting_get_elem(value, i));
            }
        }

        value = config_setting_get_member(setting, "tls");
        if (value) {
            if (!config_setting_is_aggregate(value)) {
                skeeter_log(LOG_CRIT, "Invalid capability configuration in section tls");
                return 1;
            }

            len = config_setting_length(value);
            config->capability.tls = calloc(len + 1, sizeof(char *));
            if (config->capability.tls == NULL)
                return 1;

            for (i = 0; i < len; i++) {
                conf_get_string(config->capability.tls[i],
                                config_setting_get_elem(value, i));
            }
        }
    }

    driver = calloc(1, sizeof(struct imap_driver));
    if (driver == NULL)
        return 1;

    driver->config = config;
    module->priv = driver;

    return 0;
}

int
imap_driver_init(struct module *module, struct event_base *base)
{
    struct imap_driver *driver = module->priv;
    struct imap_config *config;
    struct imap_handler *handler = handlers;
    struct module *ldap;
    struct sockaddr_in6 sin;
    int socklen = sizeof(sin);

    assert(driver && driver->config && base);
    config = driver->config;

    driver->base = base;
    driver->dnsbase = get_dnsbase();

    if (config->cert) {
        driver->ssl_ctx = new_ssl_ctx(config->cert, config->pkey);
        if (driver->ssl_ctx == NULL) {
            return 1;
        }
    }

    for (; handler->command; handler++) {
        int rc = IMAP_HANDLER_OK;

        if (handler->init)
            rc = handler->init(driver, handler);

        if (rc == IMAP_HANDLER_SKIP)
            continue;
        if (rc) {
            skeeter_log(LOG_CRIT, "Handler '%s' failed initialization: %d", handler->command, rc);
            return 1;
        }

        if (avl_insert(&driver->commands, handler, imap_handler_cmp, avl_dup_error)) {
            return 1;
        }
    }

    if (evutil_parse_sockaddr_port(config->listen, (struct sockaddr *)&sin, &socklen)) {
        return 1;
    }

    skeeter_log(LOG_NOTICE, "Binding to %s", config->listen);

    /* we start in disabled state until the LDAP interface is ready */
    driver->listener = evconnlistener_new_bind(base, listen_cb, (void*)driver,
            LEV_OPT_REUSEABLE|LEV_OPT_DISABLED|LEV_OPT_CLOSE_ON_FREE,
            -1, (struct sockaddr *)&sin, socklen);
    /* could also be wise to set an error callback, but what errors do we face
     * on accept()? */

    if (!driver->listener) {
        skeeter_log(LOG_CRIT, "Could not create a listener!");
        return 1;
    }

    ldap = get_module("ldap");
    if (!ldap || !ldap->register_event) {
        skeeter_log(LOG_CRIT, "LDAP module not available!");
        return 1;
    }

    if (ldap->register_event(ldap, MODULE_ANY | MODULE_PERSIST, trigger_listener, driver->listener)) {
        skeeter_log(LOG_CRIT, "Registration with LDAP module failed!");
        return 1;
    }

    driver->ldap = ldap;

    return 0;
}

static int
imap_handler_tls_init(struct imap_driver *driver, struct imap_handler *handler)
{
    return (driver->ssl_ctx) ? IMAP_HANDLER_OK : IMAP_HANDLER_SKIP;
}

static int
imap_handler_capability_init(struct imap_driver *driver, struct imap_handler *handler)
{
    BerValue *capability_strings;
    char **conf, *fragment;
    size_t len;

    capability_strings = calloc(3, sizeof(BerValue));
    if (!capability_strings)
        return IMAP_HANDLER_ERROR;

    /* "* CAPABILITY" + imap->capability->common */
    len = CAPABILITY_PREFIX_LEN;
    for (conf = driver->config->capability.common; *conf; conf++)
        len += 1 + strlen(*conf);

    fragment = malloc(len);
    if (fragment == NULL)
        return IMAP_HANDLER_ERROR;

    capability_strings[0].bv_val = fragment;
    capability_strings[0].bv_len = len;

    memcpy(fragment, CAPABILITY_PREFIX, CAPABILITY_PREFIX_LEN);
    fragment += CAPABILITY_PREFIX_LEN;

    for (conf = driver->config->capability.common; *conf; conf++) {
        *fragment = ' ';
        fragment++;
        memcpy(fragment, *conf, strlen(*conf));
        fragment += strlen(*conf);
    }

    /* capabilities sent over plaintext connection, imap->capability->plain and
     * "STARTTLS" if TLS is set up */
    len = 0;
    if (driver->ssl_ctx)
        len += 1 + STARTTLS_CAPABILITY_LEN;

    for (conf = driver->config->capability.plain; *conf; conf++)
        len += 1 + strlen(*conf);

    fragment = malloc(len);
    if (fragment == NULL)
        return IMAP_HANDLER_ERROR;

    capability_strings[1].bv_val = fragment;
    capability_strings[1].bv_len = len;

    if (driver->ssl_ctx) {
        *fragment = ' ';
        fragment++;
        memcpy(fragment, STARTTLS_CAPABILITY, STARTTLS_CAPABILITY_LEN);
        fragment += STARTTLS_CAPABILITY_LEN;
    }

    for (conf = driver->config->capability.plain; *conf; conf++) {
        *fragment = ' ';
        fragment++;
        memcpy(fragment, *conf, strlen(*conf));
        fragment += strlen(*conf);
    }

    /* capabilities sent over a TLS protected connection, imap->capability->tls */
    len = 0;
    for (conf = driver->config->capability.tls; *conf; conf++)
        len += 1 + strlen(*conf);

    fragment = malloc(len);
    if (fragment == NULL)
        return IMAP_HANDLER_ERROR;

    capability_strings[2].bv_val = fragment;
    capability_strings[2].bv_len = len;

    for (conf = driver->config->capability.tls; *conf; conf++) {
        *fragment = ' ';
        fragment++;
        memcpy(fragment, *conf, strlen(*conf));
        fragment += strlen(*conf);
    }

    handler->priv = capability_strings;

    return IMAP_HANDLER_OK;
}

static void
trigger_listener(module_event_flags flags, void *ctx)
{
    struct evconnlistener *listener = ctx;
    if (flags & MODULE_READY)
        evconnlistener_enable(listener);
    else
        evconnlistener_disable(listener);
}

static void
listen_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
    struct imap_driver *driver = user_data;
    struct event_base *base = driver->base;
    struct bufferevent* bev;

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        skeeter_log(LOG_CRIT, "Could not acquire bufferevent!");
        event_base_loopbreak(base);
        return;
    }

    bufferevent_write(bev, SERVER_GREETING, SERVER_GREETING_LEN);
    skeeter_log(LOG_INFO, "A new connection established");
    imap_driver_install(bev, driver);
}

static void
conn_eventcb_with_req(struct bufferevent *bev, short events, void *user_data)
{
    struct imap_context *ctx = user_data;
    if (ctx->priv) {
        struct imap_request *req = ctx->priv;

        if (req->priv) {
            struct imap_arg *args = req->priv;

            if (args[0].buffer) evbuffer_free(args[0].buffer);
            if (args[1].buffer) evbuffer_free(args[1].buffer);
            free(args);
        }
        request_free(req);
    }
    conn_eventcb(bev, events, user_data);
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    struct imap_context *ctx = user_data;
    assert(bev == ctx->client_bev);

    if (events & BEV_EVENT_EOF) {
        skeeter_log(LOG_INFO, "Connection closed.");
    } else if (events & BEV_EVENT_ERROR) {
        skeeter_log(LOG_WARNING, "Got an error on the connection: %s",
                strerror(errno));
        if (ctx->state & IMAP_TLS)
            skeeter_log(LOG_WARNING, "OpenSSL error is %lu", bufferevent_get_openssl_error(bev));
    } else if (events & BEV_EVENT_TIMEOUT) {
        skeeter_log(LOG_NOTICE, "Got a timeout on %s, closing connection.", (events & BEV_EVENT_READING) ? "reading" : "writing");
    } else if (events & BEV_EVENT_CONNECTED) {
        skeeter_log(LOG_NOTICE, "Looks like ssl handshake completed.");
        skeeter_log(LOG_DEBUG, "OpenSSL error %lu", bufferevent_get_openssl_error(bev));
        return;
    }

    skeeter_log(LOG_NOTICE, "Closing client connection");
    bufferevent_free(bev);
    ctx->client_bev = NULL;

    if (!ctx->server_bev)
        free(ctx);
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    struct imap_context *ctx = user_data;
    int rc = IMAP_OK;

    skeeter_log(LOG_INFO, "Ready to read");
    while (rc == IMAP_OK) {
        struct evbuffer_ptr pos;
        struct imap_request *req;

        pos = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
        if (pos.pos == -1)
            break;

        req = calloc(1, sizeof(struct imap_request));

        if (parse_request(req, input, pos.pos)) {
            skeeter_log(LOG_NOTICE, "invalid request");
            bufferevent_write(bev, "* " BAD_INVALID CRLF, 2 + BAD_INVALID_LEN + 2);
            evbuffer_drain(input, pos.pos + 2);
            goto cleanup;
        }

        rc = imap_handle_request(ctx, req);
        skeeter_log(LOG_INFO, "Request handled, result=%d", rc);

        if (rc == IMAP_DONE)
            return;

cleanup:
        request_free(req);
        if (rc != IMAP_OK) {
            skeeter_log(LOG_NOTICE, "Closing client connection");
            bufferevent_free(bev);
            free(ctx);
            return;
        }
    }
}

/**
 * Parse the outline of an IMAP request.
 *
 * All IMAP requests are of the form:
 * REQ := TAG SP COMMAND ( SP ARG )* CRLF
 *
 * We cut the TAG SP COMMAND part and populate the req struct with them.
 */
static int
parse_request(struct imap_request *req, struct evbuffer *input, ssize_t eol)
{
    const char *p, *end;
    ssize_t len, to_drain = 0;

    p = (const char *)evbuffer_pullup(input, eol);
    debug(LOG_DEBUG, "Parsing a new request: '%.*s'", eol, p);

    end = memchr(p, ' ', eol);
    if (!end)
        return 1;

    len = end - p;
    ber_str2bv(p, len, 1, &req->tag);

    p = end + 1;
    eol -= len + 1;
    to_drain += len + 1;

    end = memchr(p, ' ', eol);
    if (!end) {
        len = eol;
    } else {
        len = end - p;
    }

    if (!len)
        return 1;

    ber_str2bv(p, len, 1, &req->command);
    to_drain += len;

    evbuffer_drain(input, to_drain);
    return 0;
#if 0
    struct evbuffer_ptr pos;
    const char *p;
    ssize_t len;

    debug(LOG_DEBUG, "Parsing a new request: '%.*s'", eol, evbuffer_pullup(input, eol));

    pos = evbuffer_search(input, " ", 1, NULL);
    if (pos.pos == -1)
        return 1;
    len = pos.pos;

    /* We also read the SP and replace it with a NUL afterwards */
    req->tag.bv_val = p = ber_memalloc(len + 1);
    req->tag.bv_len = len;
    eol -= evbuffer_remove(input, p, len + 1);
    p[len] = '\0';

    pos = evbuffer_search(input, " ", 1, NULL);
    if (pos.pos == -1)
        len = eol;
    else
        len = pos.pos;

    req->command.bv_val = p = ber_memalloc(len + 1);
    req->command.bv_len = len;
    buffer_remove(input, p, len);
    p[len] = '\0';

    return 0;
#endif
}

static void
request_free(struct imap_request *req)
{
    ber_memfree(req->tag.bv_val);
    ber_memfree(req->command.bv_val);
    free(req);
}

void
imap_resume(struct bufferevent *bev, struct imap_context *ctx, struct imap_request *req)
{
    struct timeval tval = { .tv_sec = 60, .tv_usec = 0 };

    if (req)
        request_free(req);
    ctx->priv = NULL;

    bufferevent_setcb(bev, conn_readcb, NULL, conn_eventcb, ctx);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_set_timeouts(bev, &tval, &tval);
}

static int
unescape_arg(BerValue *out, struct evbuffer *in)
{
    size_t len = evbuffer_get_length(in);
    char *p, *q, *r;

    assert(len >= 2);
    out->bv_val = p = malloc(len);
    if (!p)
        return -1;

    out->bv_len = evbuffer_copyout(in, p, len);
    assert(out->bv_len == len);

    /* We do not copy the quotes */
    len -= 2;
    q = p + 1;
    while ((r = memchr(q, '\\', len))) {
        ssize_t offset = r - q;

        r++;

        memmove(p, q, offset);
        p += offset;
        *p = *r;
        p++; r++;
        len -= offset + 2;

        q = r;
    }
    memmove(p, q, len);

    return IMAP_OK;
}

/**
 * Locates the EOL and drains the evbuffer up to and including the EOL string
 *
 * Returns:
 * -1 iff no EOL was found
 *  0 iff there was no data preceding the EOL
 *  n iff there were n bytes pending before the EOL
 */
static int
drain_newline(struct bufferevent *bev, enum evbuffer_eol_style eol_style)
{
    struct evbuffer_ptr pos;
    struct evbuffer *input;
    size_t eol_size;

    input = bufferevent_get_input(bev);

    pos = evbuffer_search_eol(input, NULL, &eol_size, eol_style);
    if (pos.pos != -1)
        evbuffer_drain(input, pos.pos + eol_size);
    return pos.pos;
}

static int
imap_driver_install(struct bufferevent *bev, struct imap_driver *driver)
{
    struct imap_context *ctx = calloc(1, sizeof(struct imap_context));

    if (!ctx) {
        bufferevent_free(bev);
        skeeter_log(LOG_CRIT, "Could not allocate context!");
        return IMAP_SHUTDOWN;
    }

    ctx->driver = driver;
    ctx->client_bev = bev;

    imap_resume(bev, ctx, NULL);
    return IMAP_OK;
}

int
imap_handle_request(struct imap_context *ctx, struct imap_request *req)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);
    struct imap_handler h = { req->command.bv_val, NULL };
    struct imap_handler *handler = avl_find(ctx->driver->commands, &h, imap_handler_cmp);

    if (handler == NULL) {
        skeeter_log(LOG_NOTICE, "No handler defined for command '%s'", req->command.bv_val);
        evbuffer_add_printf(output, "%s BAD Command %.*s unrecognized" CRLF, req->tag.bv_val, (int)req->command.bv_len, req->command.bv_val);
        return IMAP_OK;
    }

    if (handler->handler != NULL) {
        return handler->handler(ctx, req, handler->priv);
    }

    return IMAP_OK;
}

static int
imap_capability(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);
    BerValue *caps = priv;

    if (drain_newline(bev, EVBUFFER_EOL_CRLF)) {
        evbuffer_add_printf(output, "%s " BAD_ARG_NO CRLF, req->tag.bv_val);
        return IMAP_OK;
    }

    bufferevent_write(bev, caps[0].bv_val, caps[0].bv_len);
    if (ctx->state & IMAP_TLS) {
        bufferevent_write(bev, caps[2].bv_val, caps[2].bv_len);
    } else {
        bufferevent_write(bev, caps[1].bv_val, caps[1].bv_len);
    }
    bufferevent_write(bev, CRLF, 2);

    evbuffer_add_printf(output, "%s OK CAPABILITY completed" CRLF, req->tag.bv_val);

    return IMAP_OK;
}

static int
imap_starttls(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);
    SSL *ssl_client_ctx = SSL_new(ctx->driver->ssl_ctx);

    if (drain_newline(bev, EVBUFFER_EOL_CRLF)) {
        evbuffer_add_printf(output, "%s " BAD_ARG_NO CRLF, req->tag.bv_val);
        return IMAP_OK;
    }

    if (ctx->state & IMAP_TLS) {
        evbuffer_add_printf(output, "%s BAD TLS layer already in place" CRLF, req->tag.bv_val);
        return IMAP_OK;
    }

    evbuffer_add_printf(output, "%s OK Begin TLS negotiation now" CRLF, req->tag.bv_val);

    bev = bufferevent_openssl_filter_new(ctx->driver->base,
                                         bev, ssl_client_ctx,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);

    if (!bev) {
        return IMAP_SHUTDOWN;
    }

    imap_resume(bev, ctx, NULL);
    ctx->client_bev = bev;
    ctx->state |= IMAP_TLS;

    return IMAP_OK;
}

static int
imap_noop(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);

    if (drain_newline(bev, EVBUFFER_EOL_CRLF)) {
        evbuffer_add_printf(output, "%s " BAD_ARG_NO CRLF, req->tag.bv_val);
        return IMAP_OK;
    }

    evbuffer_add_printf(output, "%s OK NOOP Completed" CRLF, req->tag.bv_val);

    return IMAP_OK;
}

static int
imap_logout(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);

    evbuffer_add_printf(output, "%s OK LOGOUT now" CRLF, req->tag.bv_val);

    return IMAP_SHUTDOWN;
}

static int
imap_login(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *client_bev = ctx->client_bev;
    struct chain *chain = NULL;
    struct imap_arg *arg;

    ctx->priv = req;
    arg = req->priv = calloc(2, sizeof(struct imap_arg));
    if (!arg)
        goto cleanup;

    chain = chain_new(imap_login_cleanup, ctx);
    if (!chain)
        goto cleanup;

    chain_add(chain, imap_sp, NULL, NULL);
    chain_add(chain, imap_astring, NULL, arg);

    arg++;
    arg->arg_type = ARG_LAST;
    chain_add(chain, imap_sp, NULL, NULL);
    chain_add(chain, imap_astring, NULL, arg);

    chain_add(chain, imap_credential_check, NULL, ctx);

    chain_activate(chain, ctx->client_bev, EV_READ);
    return IMAP_DONE;

cleanup:
    if (chain) {
        chain_destroy(chain, ctx->client_bev, CHAIN_ABORT);
    } else {
        free(req->priv);
    }
    bufferevent_write(client_bev, SERVER_ERROR CRLF, SERVER_ERROR_LEN + 2);
    return IMAP_SHUTDOWN;
}

static int
imap_login_cleanup(struct chain *chain, struct bufferevent *bev, int flags, void *priv)
{
    struct imap_context *ctx = priv;
    struct imap_request *req;
    struct imap_arg *args;

    /* This is the second call, cleanup. But all cleanup has already happened
     * when we were first called */
    if (flags == CHAIN_ABORT)
        return flags;

    if (flags == CHAIN_DONE) {
        /* imap_credential_check disables the bufferevent for reading, so we're
         * free to just set the eventcb */
        bufferevent_setcb(bev, NULL, NULL, conn_eventcb_with_req, ctx);
        return flags;
    }

    req = (struct imap_request *)ctx->priv;
    args = (struct imap_arg *)req->priv;

    /*FIXME If there's a true error on our side (like LDAP), need to admit it
     * and cause a shutdown instead */
    bufferevent_write(bev, req->tag.bv_val, req->tag.bv_len);
    bufferevent_write(bev, " " BAD_INVALID CRLF, 1 + BAD_INVALID_LEN + 2);

    if (args[0].buffer) evbuffer_free(args[0].buffer);
    if (args[1].buffer) evbuffer_free(args[1].buffer);
    free(args);

    imap_resume(bev, ctx, req);

    /* A libevent passed event, forward to the original handler */
    if (flags && !(flags & CHAIN_MASK)) {
        /*FIXME needs a rethought */
        conn_eventcb(bev, flags, priv);
        return flags;
    }

    return flags;
}

static int
imap_sp(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    const unsigned char *p;

    p = evbuffer_pullup(input, 1);
    if (!p) {
        return CHAIN_AGAIN;
    } else if (*p == ' ') {
        evbuffer_drain(input, 1);
        return CHAIN_DONE;
    }

    return CHAIN_ERROR;
}

static int
imap_astring(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer_ptr pos;
    struct imap_arg *dest = ctx;
    struct evbuffer *input = bufferevent_get_input(bev);
    int eol_pos, end_pos;
    const unsigned char *arg, *p;

    if (ARG_TYPE(dest->arg_type) == ARG_LITERAL) {
drain:;
        ssize_t need = dest->arg_len - evbuffer_get_length(dest->buffer);

        /* Add as much data as possible to the buffer */
        need -= evbuffer_remove_buffer(input, dest->buffer, need);
        assert(need >= 0);

        return need ? CHAIN_AGAIN : CHAIN_DONE;
    }

    pos = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
    eol_pos = pos.pos;

    if (dest->arg_type & ARG_LAST) {
        end_pos = eol_pos;
    } else {
        pos = evbuffer_search(input, " ", 1, NULL);
        end_pos = pos.pos;
    }

    if (end_pos == -1 && eol_pos == -1)
        return CHAIN_AGAIN;

    arg = evbuffer_pullup(input, 1);
    switch (*arg) {
        case '"':
            {
                /*FIXME: eol_pos might be -1 and then we want to use
                 * evbuffer_get_length(input) instead, plus the following code
                 * could probably be folded into a simpler do{}while() loop?
                 */
                const unsigned char *q, *quote = evbuffer_pullup(input, -1);

                q = memchr(quote+1, '"', eol_pos);
                if (!q) {
                    return (eol_pos == -1) ? CHAIN_AGAIN : CHAIN_ERROR;
                }

                p = memchr(quote+1, '\\', eol_pos);
                while (p && (p < q)) {
                    p++;
                    switch (*p++) {
                        case '"':
                            q = memchr(p, '"', eol_pos - (q - quote));
                            if (!q)
                                return (eol_pos == -1) ? CHAIN_AGAIN : CHAIN_ERROR;
                            break;
                        case '\\':
                            break;
                        default:
                            return CHAIN_ERROR;
                            break;
                    }
                    p = memchr(p, '\\', eol_pos - (p - quote));
                }

                dest->buffer = evbuffer_new();

                q++;
                dest->arg_len = q - quote;
                dest->arg_type |= ARG_QUOTED;
                evbuffer_remove_buffer(input, dest->buffer, dest->arg_len);

#if 0
                arg = quote;
                dest->arg_type |= ARG_QUOTED;
                do {
                    int escaped = 0;

                    quote = strchr(quote+1, '"');
                    if (!quote) {
                        if (eol_pos >= 0) {
                            /* invalid request */
                            return CHAIN_ERROR;
                        } else {
                            /* need more data */
                            return CHAIN_AGAIN;
                        }
                    }

                    /* find out whether it's escaped (= has an odd number of
                     * backslashes in front of it) */
                    p = quote;
                    while (*(--p) == '\\')
                        escaped = !escaped;
                } while (escaped);

                quote++;
                dest->arg_len = quote - arg;
                evbuffer_remove_buffer(input, dest->buffer, dest->arg_len);
#endif
            }
            break;
        case '{':
            if (eol_pos == -1)
                return CHAIN_AGAIN;

            dest->arg_type |= ARG_LITERAL;
            arg = evbuffer_pullup(input, eol_pos);

            /* find out how much data was advertised */
            p = arg + 1;
            if (!(*p > '0' && *p <= '9')) {
                /* invalid */
                return CHAIN_ERROR;
            }
            while (*p >= '0' && *p <= '9')
                p++; /* just skip over it */

            dest->arg_len = atol((const char *)(arg + 1));

            if (!(*p++ == '}') || !(*p++ == '\r') || !(*p++ == '\n'))
                return CHAIN_ERROR;

            dest->buffer = evbuffer_new();

            evbuffer_drain(input, p - arg);
            bufferevent_write(bev, LITERAL_RESPONSE CRLF, LITERAL_RESPONSE_LEN + 2);

            /*XXX can we return here? (= if there is still data on the bufferevent
             * and the client never sends anything more, will we be called
             * again or should we just jump to the beginning?) */
            /* we will not be called again -> jump */
            goto drain;
            break;
        default:
            dest->arg_type |= ARG_ATOM;
            if (end_pos == -1)
                return CHAIN_AGAIN;

            dest->buffer = evbuffer_new();

            dest->arg_len = end_pos;
            evbuffer_remove_buffer(input, dest->buffer, end_pos);
            break;
    }

    return CHAIN_DONE;
}

static int
imap_put_berval(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    BerValue *string = ctx;

    bufferevent_write(bev, string->bv_val, string->bv_len);
    return CHAIN_DONE;
}

static int
imap_put_literal_header(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct imap_arg *arg = ctx;
    struct evbuffer *output = bufferevent_get_output(bev);

    assert(ARG_TYPE(arg->arg_type) == ARG_LITERAL);
    evbuffer_add_printf(output, " {%zu}" CRLF, arg->arg_len);
    return CHAIN_DONE;
}

static int
imap_await_greeting(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer_ptr eol, pos;
    struct evbuffer *input = bufferevent_get_input(bev);
    unsigned char *p;
    size_t eol_size;

    eol = evbuffer_search_eol(input, NULL, &eol_size, EVBUFFER_EOL_CRLF);
    if (eol.pos == -1)
        return CHAIN_AGAIN;

    p = evbuffer_pullup(input, 5);
    if (!p || memcmp(p, "* OK ", 5) != 0)
        return CHAIN_ERROR;

    pos = evbuffer_search_range(input, "IMAP4rev1", 9, NULL, &eol);
    if (pos.pos == -1)
        return CHAIN_ERROR;

    evbuffer_drain(input, eol.pos + eol_size);

    return CHAIN_DONE;
}

static int
imap_await_goahead(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    const unsigned char *p;

    p = evbuffer_pullup(input, 3);
    if (!p) {
        return CHAIN_AGAIN;
    } else if (*p++ == '+' && *p == ' ') {
        int pos = drain_newline(bev, EVBUFFER_EOL_CRLF);
        if (pos == -1)
            return CHAIN_AGAIN;
        if (pos > 2)
            return CHAIN_DONE;
    }

    return CHAIN_ERROR;
}

static int
imap_put_astring(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct imap_arg *arg = ctx;

    if (ARG_TYPE(arg->arg_type) != ARG_LITERAL)
        bufferevent_write(bev, " ", 1);

    /* this is destructive, but we have used what we needed */
    if (bufferevent_write_buffer(bev, arg->buffer))
        return CHAIN_ERROR;

    return CHAIN_DONE;
}

static int
imap_await_tag(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer_ptr pos;
    struct evbuffer *input = bufferevent_get_input(bev);
    BerValue *tag = ctx;
    char *p = NULL;

    pos = evbuffer_search(input, " ", 1, NULL);
    if (pos.pos == -1) {
        if (evbuffer_get_length(input) > tag->bv_len)
            return CHAIN_ERROR;

        pos = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
        if (pos.pos != -1)
            return CHAIN_ERROR;

        return CHAIN_AGAIN;
    }

    if (pos.pos > tag->bv_len)
        return CHAIN_ERROR;

    if (pos.pos != tag->bv_len && pos.pos == 1) {
        /* Check for an unsolicited message before we reject it */
        p = (char *)evbuffer_pullup(input, 2);
        if (memcmp(p, "* ", 2)) {
            /* FIXME: a different code and handling routine, but for now,
             * unsolicited means error */
            return CHAIN_ERROR;
        }
    }

    if (pos.pos != tag->bv_len)
        return CHAIN_ERROR;

    p = (char *)evbuffer_pullup(input, pos.pos + 1);
    assert(p);

    if (memcmp(p, tag->bv_val, tag->bv_len) == 0) {
        evbuffer_drain(input, pos.pos + 1);
        return CHAIN_DONE;
    }

    return CHAIN_ERROR;
}

static int
imap_await_result(struct chain *chain, struct bufferevent *bev, void *ctx)
{
    struct evbuffer_ptr pos;
    struct evbuffer *input = bufferevent_get_input(bev);
    char *p;

    pos = evbuffer_search(input, " ", 1, NULL);
    if (pos.pos == -1) {
        pos = evbuffer_search_eol(input, NULL, NULL, EVBUFFER_EOL_CRLF);
        if (pos.pos == -1)
            return CHAIN_AGAIN;
    }

    p = (char *)evbuffer_pullup(input, pos.pos);
    assert(p);

    if (memcmp(p, "OK", 2) == 0)
        return CHAIN_DONE;

    return CHAIN_ERROR;
}

static int
imap_server_cleanup(struct chain *chain, struct bufferevent *bev, int flags, void *priv)
{
    struct imap_context *ctx;
    struct imap_request *req;
    struct imap_arg *args;

    /* This is the second call, cleanup. But all cleanup has already happened
     * when we were first called */
    if (flags == CHAIN_ABORT)
        return flags;

    ctx = (struct imap_context *)priv;
    req = (struct imap_request *)ctx->priv;
    args = (struct imap_arg *)req->priv;

    if (flags == CHAIN_DONE) {
        /* We have stripped the tag from the server response, add the
         * proper one and then send the rest of the response */
        /*TODO send our own response so that we don't leak information */
        bufferevent_write(ctx->client_bev, req->tag.bv_val, req->tag.bv_len);
        bufferevent_write(ctx->client_bev, " ", 1);
        proxy_cb(bev, ctx);

        bufferevent_setcb(bev, proxy_cb, NULL, proxy_error_cb, ctx);

        bufferevent_setcb(ctx->client_bev, proxy_cb, NULL, proxy_error_cb, ctx);
        bufferevent_enable(ctx->client_bev, EV_READ);
    }

    /* we need to do cleanup before server_event_cb is called as ctx could be
     * freed if the client connection has failed in the meantime */
    if (args[0].buffer) evbuffer_free(args[0].buffer);
    if (args[1].buffer) evbuffer_free(args[1].buffer);
    free(args);

    if (flags == CHAIN_DONE) {
        request_free(req);
    } else {
        imap_resume(ctx->client_bev, ctx, req);
    }

    /* We have an error, but non-fatal ones are handled by the chain_elem
     * specific handler, which means that the connection is shutting down */
    if (flags != CHAIN_DONE)
        server_event_cb(bev, (short)flags, priv);

    return flags;
}

static int
imap_credential_check(struct chain *chain, struct bufferevent *bev, void *priv)
{
    struct imap_context *ctx = priv;
    struct imap_request *req = ctx->priv;
    struct imap_arg *args = req->priv;
    struct evbuffer *output = bufferevent_get_output(bev);
    struct user_info user_info = {};
    char *attrs[2] = { "mailhost", NULL };
    char *p;
    ssize_t len, len_domain = 0;
    int rc = CHAIN_ERROR;
    int freeit = 0;

    if (drain_newline(bev, EVBUFFER_EOL_CRLF))
        return rc;

    if (ARG_TYPE(args->arg_type) == ARG_QUOTED) {
        unescape_arg(&user_info.username, args->buffer);
        freeit = 1;
    } else {
        p = (char *)evbuffer_pullup(args->buffer, -1);
        ber_str2bv(p, args->arg_len, 0, &user_info.username);
    }

    len = user_info.username.bv_len; // length of whole "username@domain"
    p = user_info.username.bv_val;

    p = memchr(p, '@', len);
    if (p) {
        len = p - user_info.username.bv_val;
        len_domain = user_info.username.bv_len - len - 1;
        p++;
    } else {
        // use a default domain
        p = ctx->driver->config->default_host;
    }
    user_info.username.bv_len = len;
    ber_str2bv(p, len_domain, 0, &(user_info.domain));

    user_info.attrs = attrs;
    if (get_user_info(ctx->driver->ldap, &user_info, search_cb, ctx)) {
        /*FIXME */
        evbuffer_add_printf(output, "%s " SERVER_ERROR CRLF, req->tag.bv_val);
    } else {
        /* now stop reading on the connection until we're connected to server */
        bufferevent_disable(bev, EV_READ);
        rc = CHAIN_DONE;
    }

    if (freeit)
        free(user_info.username.bv_val);
    return rc;
}

static void
search_cb(LDAP *ld, LDAPMessage *msg, void *priv)
{
    struct imap_context *ctx = priv;
    struct imap_request *req = ctx->priv;
    struct bufferevent *server_bev;
    struct evbuffer *out;
    BerValue **servername = NULL;
    char *p;
    int port = 0;

    out = bufferevent_get_output(ctx->client_bev);
    if (msg) {
        servername = ldap_get_values_len(ld, msg, "mailhost");
    }

    // user not provisioned
    if (!servername || !*servername) {
        struct imap_arg *args = req->priv;

        if (servername)
            ldap_value_free_len(servername);

        bufferevent_write(ctx->client_bev, req->tag.bv_val, req->tag.bv_len);
        bufferevent_write(ctx->client_bev, " " AUTH_FAILED_MSG CRLF, 1 + AUTH_FAILED_MSG_LEN + 2);

        if (args[0].buffer) evbuffer_free(args[0].buffer);
        if (args[1].buffer) evbuffer_free(args[1].buffer);
        free(args);

        imap_resume(ctx->client_bev, ctx, req);
        return;
    }

    p = memchr(servername[0]->bv_val, ':', servername[0]->bv_len);
    if (p && (p < (servername[0]->bv_val + servername[0]->bv_len))) {
        //FIXME: do a proper checking, using atoi on a buffer is just asking for an overflow
        *p = '\0';
        port = atoi(p+1);
    }
    if (!port)
        port = ctx->driver->config->default_port;

    server_bev = bufferevent_socket_new(ctx->driver->base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(server_bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(server_bev, ctx->driver->dnsbase, AF_UNSPEC, servername[0]->bv_val, port);
    bufferevent_setcb(server_bev, NULL, NULL, server_event_cb, ctx);

    ctx->server_bev = server_bev;

    ldap_value_free_len(servername);
}

static void
server_event_cb(struct bufferevent *bev, short events, void *priv)
{
    struct imap_context *ctx = priv;
    assert(bev == ctx->server_bev);

    if (events & BEV_EVENT_EOF) {
        skeeter_log(LOG_NOTICE, "Connection closed.");
    } else if (events & BEV_EVENT_ERROR) {
        skeeter_log(LOG_WARNING, "Got an error on the connection: %s",
                strerror(errno));
    } else if (events & BEV_EVENT_TIMEOUT) {
        skeeter_log(LOG_NOTICE, "Got a timeout on %s, closing connection.", (events & BEV_EVENT_READING) ? "reading" : "writing");
    } else if (events & BEV_EVENT_CONNECTED) {
        struct imap_request *req = ctx->priv;
        struct imap_arg *args = req->priv;
        struct chain *chain = NULL;

        skeeter_log(LOG_NOTICE, "Looks like we are connected, initiating server handshake...");
        chain = chain_new(imap_server_cleanup, ctx);
        if (!chain)
            goto cleanup;

        chain_add(chain, imap_await_greeting, NULL, NULL);
        /* TODO: insert a STARTTLS attempt here, IIUC it should not interfere
         * with chaining as it is designed, but needs a side channel to
         * communicate a "NO" properly.
         *
         * chain_add(chain, imap_put_berval, NULL, tag);
         * chain_add(chain, imap_put_berval, NULL, &starttls);
         * chain_add(chain, imap_await_tag, NULL, tag);
         * chain_add(chain, imap_await_result, handle_no, &tls_approved_by_server);
         * chain_add(chain, imap_tls_layer, imap_tls_done, &tls_approved_by_server);
         */
        chain_add(chain, imap_put_berval, NULL, &req->tag);
        chain_add(chain, imap_put_berval, NULL, &login);

        /* username */
        if (ARG_TYPE(args->arg_type) == ARG_LITERAL) {
            chain_add(chain, imap_put_literal_header, NULL, args);
            chain_add(chain, imap_await_goahead, NULL, NULL);
        }
        chain_add(chain, imap_put_astring, NULL, args);

        args++;
        /* password */
        if (ARG_TYPE(args->arg_type) == ARG_LITERAL) {
            chain_add(chain, imap_put_literal_header, NULL, args);
            chain_add(chain, imap_await_goahead, NULL, NULL);
        }
        chain_add(chain, imap_put_astring, NULL, args);

        chain_add(chain, imap_put_berval, NULL, &newline);

        chain_add(chain, imap_await_tag, NULL, &req->tag);
        chain_add(chain, imap_await_result, NULL, NULL);

        chain_activate(chain, bev, EV_READ|EV_WRITE);
        return;
    }
cleanup:
    skeeter_log(LOG_INFO, "Closing server connection");
    bufferevent_free(ctx->server_bev);
    ctx->server_bev = NULL;

    if (ctx->client_bev) {
        struct imap_request *req = ctx->priv;
        struct imap_arg *args = req->priv;

        bufferevent_write(ctx->client_bev, req->tag.bv_val, req->tag.bv_len);
        bufferevent_write(ctx->client_bev, " " AUTH_FAILED_MSG CRLF, 1 + AUTH_FAILED_MSG_LEN + 2);

        if (args[0].buffer) evbuffer_free(args[0].buffer);
        if (args[1].buffer) evbuffer_free(args[1].buffer);
        free(args);

        imap_resume(ctx->client_bev, ctx, req);
    } else {
        free(ctx);
    }
}

static void
proxy_error_cb(struct bufferevent *bev, short events, void *priv)
{
    struct imap_context *ctx = priv;

    if (events & BEV_EVENT_EOF) {
        skeeter_log(LOG_NOTICE, "Connection closed.");
    } else if (events & BEV_EVENT_ERROR) {
        skeeter_log(LOG_WARNING, "Got an error on the connection: %s",
                strerror(errno));
    } else if (events & BEV_EVENT_TIMEOUT) {
        skeeter_log(LOG_NOTICE, "Got a timeout on %s, closing connection.", (events & BEV_EVENT_READING) ? "reading" : "writing");
    }
    skeeter_log(LOG_INFO, "Freeing connection data");
    bufferevent_free(ctx->server_bev);
    bufferevent_free(ctx->client_bev);
    free(ctx);
}

static void
proxy_cb(struct bufferevent *source, void *priv)
{
    struct imap_context *ctx = priv;
    struct evbuffer *input = bufferevent_get_input(source);
    /* pick the right direction, if reading from client_bev, dump to server_bev
     * and vice versa */
    struct bufferevent *target = (source == ctx->client_bev) ?
                                ctx->server_bev : ctx->client_bev;

    skeeter_log(LOG_INFO, "Proxying %zu bytes from %s.", evbuffer_get_length(input),
            (source == ctx->client_bev) ? "client" : "server");
    debug(LOG_DEBUG, "%.*s", evbuffer_get_length(input), evbuffer_pullup(input, -1));
    bufferevent_write_buffer(target, input);
    /* TODO: choke the reading bufferevent if we start buffering too much on
     * the target and set a write watermark+callback to have it reopened when
     * enough has been drained */
}
