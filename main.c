#define _GNU_SOURCE
/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For fcntl */
#include <fcntl.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <lber.h>
#include "imap.h"

#define MESSAGE "Hello "

#define DEFAULT_SERVER "localhost"
#define DEFAULT_PORT 1143

static void listen_cb(struct evconnlistener *, evutil_socket_t, struct sockaddr *, int socklen, void *);
//static void conn_writecb(struct bufferevent *, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
static void signal_cb(evutil_socket_t, short, void *);

static int imap_driver_install(struct bufferevent *, struct imap_driver *);

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

	if (!signal_event || event_add(signal_event, NULL)<0) {
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
listen_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
    struct imap_driver *driver = user_data;
    struct event_base *base = driver->base;
    struct bufferevent* bev;
    char buf[BUFSIZ];
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stderr, "Could not acquire bufferevent!\n");
        event_base_loopbreak(base);
        return;
    }

    printf("A connection\n");
    imap_driver_install(bev, driver);

	//bufferevent_write(bev, MESSAGE, strlen(MESSAGE));
    
    if (getnameinfo(sa, socklen, buf, BUFSIZ, NULL, 0, 0) == 0) {
        bufferevent_write(bev, buf, strlen(buf));
    } else {
        bufferevent_write(bev, "unknown", strlen("unknown"));
    }
    bufferevent_write(bev, "\n", 1);
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
//	struct evbuffer *output = bufferevent_get_output(bev);
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

        if ( *end == ' ' ) {
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

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	if (events & BEV_EVENT_EOF) {
		printf("Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		printf("Got an error on the connection: %s\n",
		    strerror(errno));
        printf("OpenSSL error %lu\n", bufferevent_get_openssl_error(bev) );
	} else if (events & BEV_EVENT_TIMEOUT) {
		printf("Got a timeout on %s, closing connection.\n", (events & BEV_EVENT_READING) ? "reading" : "writing" );
    } else if (events & BEV_EVENT_CONNECTED) {
        printf("Looks like ssl handshake completed.\n");
        printf("OpenSSL error %lu\n", bufferevent_get_openssl_error(bev) );
        return;
	}
    printf("Freeing connection\n");
	bufferevent_free(bev);
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct event_base *base = user_data;
	struct timeval delay = { 2, 0 };

	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");

	event_base_loopexit(base, &delay);
}

static int imap_driver_install(struct bufferevent *bev, struct imap_driver *driver)
{
    struct imap_context *ctx;
    struct timeval tval;

    ctx = (struct imap_context *)calloc(1, sizeof(struct imap_context));
    ctx->driver = driver;
    ctx->client_bev = bev;

    tval.tv_sec = 10;
    tval.tv_usec = 0;

    bufferevent_setcb(bev, conn_readcb, NULL, conn_eventcb, ctx);
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_enable(bev, EV_READ);
    bufferevent_set_timeouts(bev, &tval, &tval);
    return IMAP_OK;
}
