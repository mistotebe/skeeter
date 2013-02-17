#define _GNU_SOURCE
#include "imap.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

static int imap_capability(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_starttls(struct imap_context *ctx, struct imap_request *req, void *priv);
static int imap_login(struct imap_context *ctx, struct imap_request *req, void *priv);

static struct imap_handler handlers[] = {
    { "CAPABILITY", imap_capability },
    { "STARTTLS", imap_starttls },
    { "LOGIN", imap_login },
    /*
    */
    { NULL }
};

int
imap_handler_cmp(const void *left, const void *right)
{
    const struct imap_handler *l = left;
    const struct imap_handler *r = right;
    return strcasecmp(l->command, r->command);
}

int
imap_handle_request(struct imap_context *ctx, struct imap_request *req)
{
    struct bufferevent *bev = ctx->client_bev;
    struct evbuffer *output = bufferevent_get_output(bev);
    struct imap_handler h = { req->command.bv_val, NULL };
    struct imap_handler *handler = avl_find(ctx->driver->commands, &h, imap_handler_cmp);

    if (handler == NULL) {
        printf( "No handler defined for command '%s'\n", req->command.bv_val );
        evbuffer_add_printf(output, "%s BAD Command %s unrecognized" CRLF, req->tag.bv_val, req->command.bv_val);
        return IMAP_OK;
    }

    if (handler->handler != NULL) {
        return handler->handler(ctx, req, handler->priv);
    }

    return IMAP_OK;
}

struct imap_driver *
imap_driver_init(struct event_base *base, char *host, int port)
{
    struct imap_driver *driver;
    struct imap_handler *handler;

    driver = calloc(1, sizeof(struct imap_driver));
    if (driver == NULL) {
        return NULL;
    }
    driver->base = base;

    driver->remote_host = host;
    driver->remote_port = port;

    for (handler = handlers; handler->command; handler++) {
        /* handle the private handler storage */
        if (avl_insert(&driver->commands, handler, imap_handler_cmp, avl_dup_error)) {
            return NULL;
        }
    }

    driver->ssl_ctx = new_server_ctx("cert", "pkey");
    if (driver->ssl_ctx == NULL) {
        free(driver);
        return NULL;
    }

    return driver;
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
    bufferevent_getcb( bev, &readcb, &writecb, &eventcb, &orig_ctx );

    evbuffer_add_printf(output, "%s OK Begin TLS negotiation now" CRLF, req->tag.bv_val);

    bev = bufferevent_openssl_filter_new(ctx->driver->base,
                                         bev, ssl_client_ctx,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);

    if (!bev) {
        return IMAP_SHUTDOWN;
    }

    bufferevent_setcb(bev, readcb, writecb, eventcb, orig_ctx );
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_enable(bev, EV_READ);
    ctx->client_bev = bev;

    return IMAP_OK;
}

static void
proxy_cb(struct bufferevent *source, void *priv)
{
    struct imap_context *ctx = priv;
    struct evbuffer *input = bufferevent_get_input(source);
    // pick the right direction, if reading from client_bev, dump to server_bev
    // and vice versa
    struct bufferevent *target = (source == ctx->client_bev) ?
                                ctx->server_bev : ctx->client_bev;

    printf("Proxying %zu bytes from %s.\n", evbuffer_get_length(input),
            (source == ctx->client_bev) ? "client" : "server");
    printf("%.*s", evbuffer_get_length(input), evbuffer_pullup(input, -1));
    bufferevent_write_buffer(target, input);
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
        printf("Got a timeout on %s, closing connection.\n", (events & BEV_EVENT_READING) ? "reading" : "writing" );
    } else if (events & BEV_EVENT_CONNECTED) {
        printf("Looks like we are connected, proxying...\n");
        bufferevent_setcb(ctx->server_bev, proxy_cb, NULL, server_connect_cb, ctx);
        bufferevent_setcb(ctx->client_bev, proxy_cb, NULL, server_connect_cb, ctx);
        return;
    }
    printf("Freeing connections\n");
    bufferevent_free(ctx->server_bev);
    bufferevent_free(ctx->client_bev);
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
        p = ctx->driver->remote_host;
    }
    
    end = strchrnul(p, ' ');
    len = end - p;

    servername = malloc(len + 1);
    memcpy(servername, p, len);
    servername[len] = '\0';

    server_bev = bufferevent_socket_new(ctx->driver->base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(server_bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(server_bev, ctx->driver->dnsbase, AF_UNSPEC, servername, ctx->driver->remote_port);
    bufferevent_setcb(server_bev, NULL, NULL, server_connect_cb, ctx);

    // copy over client data, CRLF in request has been skipped, so append that
    bufferevent_write(server_bev, req->line.bv_val, req->line.bv_len);
    bufferevent_write(server_bev, CRLF, 2);

    ctx->server_bev = server_bev;

    //bufferevent_disable(client_bev, EV_READ|EV_WRITE);

    free(servername);

    return IMAP_DONE;
}
