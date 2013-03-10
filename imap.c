#define _GNU_SOURCE
#include "imap.h"
#include "config.h"
#include "module.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

static int imap_driver_install(struct bufferevent *, struct imap_driver *);

static void listen_cb(struct evconnlistener *, evutil_socket_t, struct sockaddr *, int socklen, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);

static int imap_capability(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_starttls(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_login(struct imap_context *ctx, struct imap_request *req, void *priv);

static void proxy_cb(struct bufferevent *, void *);
static void server_connect_cb(struct bufferevent *, short, void *);

static struct imap_handler handlers[] = {
    { "CAPABILITY", imap_capability },
    { "STARTTLS", imap_starttls },
    { "LOGIN", imap_login },
    /*
    { "NOOP", imap_noop },
    { "LOGOUT", imap_logout },
    { "AUTHENTICATE", imap_authenticate },
    */
    { NULL }
};

static struct imap_config config_default = {
    .listen = "127.0.0.1:1143",
    .default_host = "localhost",
    .default_port = 143
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

    if (conf == NULL)
        return 1;

    config = malloc(sizeof(struct imap_config));
    if (config == NULL)
        return 1;
    *config = config_default;

    setting = config_setting_get_member(conf, "listen");
    if (setting) {
        /* in the future there are going to be more listen addresses but not
         * right now */
        value = config_setting_get_elem(setting, 0);
        if (value == NULL)
            return 1;

        conf_get_string(config->listen, value);
    }

    /*TODO: prime for a rewrite */
    setting = config_setting_get_member(conf, "defaults");
    if (setting) {

        value = config_setting_get_elem(setting, 0);
        if (value == NULL)
            return 1;

        conf_get_string(config->default_host, value);

        value = config_setting_get_elem(setting, 1);
        if (value == NULL)
            return 1;

        port = config_setting_get_int(value);
        if ((port > 0) && (port <= 65535)) {
            config->default_port = port;
        } else {
            return 1;
        }
    }

    setting = config_setting_get_member(conf, "tls");
    if (setting != NULL) {
        value = config_setting_get_elem(setting, 0);
        if (value == NULL)
            return 1;

        conf_get_string(config->cert, value);

        value = config_setting_get_elem(setting, 1);
        if (value == NULL)
            return 1;

        conf_get_string(config->pkey, value);
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
    struct sockaddr_in6 sin;
    int socklen = sizeof(sin);

    assert(driver && driver->config && base);
    config = driver->config;

    driver->base = base;
    driver->dnsbase = get_dnsbase();

    for (handler = handlers; handler->command; handler++) {
        /* handle the private handler storage */
        if (avl_insert(&driver->commands, handler, imap_handler_cmp, avl_dup_error)) {
            return 1;
        }
    }

    driver->ssl_ctx = new_ssl_ctx(config->cert, config->pkey);
    if (driver->ssl_ctx == NULL) {
        return 1;
    }

    if (evutil_parse_sockaddr_port(config->listen, (struct sockaddr *)&sin, &socklen)) {
        return 1;
    }

    /* after startup dependency notifications are available, create it in
     * disabled state setting LEV_OPT_DISABLED and enable after ldap tells us
     * it's ready */
    driver->listener = evconnlistener_new_bind(base, listen_cb, (void*)driver,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr *)&sin, socklen);
    /* could also be wise to set an error callback, but what errors do we face
     * on accept()? */

    if (!driver->listener) {
        fprintf(stderr, "Could not create a listener!\n");
        return 1;
    }

    return 0;
}

static void
listen_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
    struct imap_driver *driver = user_data;
    struct event_base *base = driver->base;
    struct bufferevent* bev;

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stderr, "Could not acquire bufferevent!\n");
        event_base_loopbreak(base);
        return;
    }

    printf("A connection\n");
    imap_driver_install(bev, driver);
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    if (events & BEV_EVENT_EOF) {
        printf("Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        printf("Got an error on the connection: %s\n",
                strerror(errno));
        printf("OpenSSL error %lu\n", bufferevent_get_openssl_error(bev));
    } else if (events & BEV_EVENT_TIMEOUT) {
        printf("Got a timeout on %s, closing connection.\n", (events & BEV_EVENT_READING) ? "reading" : "writing");
    } else if (events & BEV_EVENT_CONNECTED) {
        printf("Looks like ssl handshake completed.\n");
        printf("OpenSSL error %lu\n", bufferevent_get_openssl_error(bev));
        return;
    }
    printf("Freeing connection data\n");
    bufferevent_free(bev);
    free(user_data);
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    struct imap_context *driver_ctx = user_data;
    char *line;
    size_t bytes_read;
    int rc = IMAP_OK;

    printf("Ready to read\n");
    while (rc == IMAP_OK && (line = evbuffer_readln(input, &bytes_read, EVBUFFER_EOL_CRLF))) {
        struct imap_request *req = calloc(1, sizeof(struct imap_request));
        char *p, *end;
        ssize_t len;

        printf("Client said: '%s'\n", line);

        /* parse the request properly instead of this one-off code */
        p = line;
        end = strchrnul(p, ' ');
        len = end - p;

        req->tag.bv_val = malloc(len + 1);
        req->tag.bv_len = len;
        memcpy(req->tag.bv_val, p, len);
        req->tag.bv_val[len] = '\0';

        if (*end != ' ') {
            printf("invalid request\n");
            goto cleanup;
        }
        p = end + 1;

        end = strchrnul(p, ' ');
        len = end - p;

        req->command.bv_val = malloc(len + 1);
        req->command.bv_len = len;
        memcpy(req->command.bv_val, p, len);
        req->command.bv_val[len] = '\0';

        if (*end == ' ') {
            p = end + 1;

            // luckily the potentially longest part of the line needs no copying
            req->arguments.bv_val = p;
            req->arguments.bv_len = strlen(p);
        } else if (*end != '\0') {
            printf("invalid request\n");
            goto cleanup;
        }

        req->line.bv_val = line;
        req->line.bv_len = strlen(line);

        rc = imap_handle_request(driver_ctx, req);
        printf("Request handled, result=%d\n", rc);
cleanup:
        // all pointers are valid or NULL, and NULL is ok for free()
        free(req->command.bv_val);
        free(req->tag.bv_val);
        free(line);
    }
}

static int
imap_driver_install(struct bufferevent *bev, struct imap_driver *driver)
{
    struct imap_context *ctx;
    struct timeval tval;

    ctx = (struct imap_context *)calloc(1, sizeof(struct imap_context));
    ctx->driver = driver;
    ctx->client_bev = bev;

    tval.tv_sec = 10;
    tval.tv_usec = 0;

    bufferevent_setcb(bev, conn_readcb, NULL, conn_eventcb, ctx);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_set_timeouts(bev, &tval, &tval);
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
        printf("No handler defined for command '%s'\n", req->command.bv_val);
        evbuffer_add_printf(output, "%s BAD Command %s unrecognized" CRLF, req->tag.bv_val, req->command.bv_val);
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

    evbuffer_add_printf(output, "%s CAPABILITY STARTTLS AUTH=PLAIN LOGINDISABLED IMAP4rev1" CRLF, req->tag.bv_val);
    return IMAP_OK;
}

static int
imap_starttls(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);
    SSL *ssl_client_ctx = SSL_new(ctx->driver->ssl_ctx);
    bufferevent_data_cb readcb, writecb;
    bufferevent_event_cb eventcb;
    void *orig_ctx;

    /* retrieve the callbacks to apply them again on the filtering bev */
    bufferevent_getcb(bev, &readcb, &writecb, &eventcb, &orig_ctx);

    evbuffer_add_printf(output, "%s OK Begin TLS negotiation now" CRLF, req->tag.bv_val);

    bev = bufferevent_openssl_filter_new(ctx->driver->base,
                                         bev, ssl_client_ctx,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);

    if (!bev) {
        return IMAP_SHUTDOWN;
    }

    bufferevent_setcb(bev, readcb, writecb, eventcb, orig_ctx);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    ctx->client_bev = bev;

    return IMAP_OK;
}

static int
imap_login(struct imap_context *ctx, struct imap_request *req, void *priv)
{
    struct bufferevent *server_bev, *client_bev = ctx->client_bev;
    char *p, *end, *servername;
    ssize_t len;

    p = memchr(req->arguments.bv_val, '@', req->arguments.bv_len);
    if (p) {
        // skip the @ sign
        p++;
    } else {
        // use a default domain
        p = ctx->driver->config->default_host;
    }

    end = strchrnul(p, ' ');
    len = end - p;

    servername = malloc(len + 1);
    memcpy(servername, p, len);
    servername[len] = '\0';

    server_bev = bufferevent_socket_new(ctx->driver->base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(server_bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(server_bev, ctx->driver->dnsbase, AF_UNSPEC, servername, ctx->driver->config->default_port);
    bufferevent_setcb(server_bev, NULL, NULL, server_connect_cb, ctx);

    // copy over client data, CRLF in request has been skipped, so append that
    bufferevent_write(server_bev, req->line.bv_val, req->line.bv_len);
    bufferevent_write(server_bev, CRLF, 2);

    ctx->server_bev = server_bev;

    /* stop reading on the connection until we're connected to server */
    bufferevent_disable(client_bev, EV_READ);

    free(servername);

    return IMAP_DONE;
}

static void
server_connect_cb(struct bufferevent *bev, short events, void *priv)
{
    struct imap_context *ctx = priv;
    // temporarily disable, until error_cb is ready
    //assert(bev == ctx->server_bev);

    if (events & BEV_EVENT_EOF) {
        printf("Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        printf("Got an error on the connection: %s\n",
                strerror(errno));
    } else if (events & BEV_EVENT_TIMEOUT) {
        printf("Got a timeout on %s, closing connection.\n", (events & BEV_EVENT_READING) ? "reading" : "writing");
    } else if (events & BEV_EVENT_CONNECTED) {
        printf("Looks like we are connected, proxying...\n");
        bufferevent_setcb(ctx->server_bev, proxy_cb, NULL, server_connect_cb, ctx);
        bufferevent_setcb(ctx->client_bev, proxy_cb, NULL, server_connect_cb, ctx);
        bufferevent_enable(ctx->client_bev, EV_READ);
        return;
    }
    printf("Freeing connection data\n");
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

    printf("Proxying %zu bytes from %s.\n", evbuffer_get_length(input),
            (source == ctx->client_bev) ? "client" : "server");
    printf("%.*s", evbuffer_get_length(input), evbuffer_pullup(input, -1));
    bufferevent_write_buffer(target, input);
}
