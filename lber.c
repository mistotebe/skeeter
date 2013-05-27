#include "io_handler.h"
#include <errno.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/buffer.h>
// need at least libevent 2.1.1 for bufferevent_getcb
#include <event2/bufferevent.h>

#include <unistd.h>

static int
sb_libevent_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
    sbiod->sbiod_pvt = arg;
    return 0;
}

void
sb_libevent_all_sent(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *buffer = bufferevent_get_output(bev);

    assert( evbuffer_get_length(buffer) == 0 );

    bufferevent_free(bev);
}

static int
sb_libevent_remove(Sockbuf_IO_Desc *sbiod)
{
    return 0;
}

static int
sb_libevent_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
    switch (opt) {
        case LBER_SB_OPT_DATA_READY:
            {
                // libldap cannot trust the fd read status because at that time
                // it's already drained, it asks us to tell it if we're ready
                struct bufferevent *bev = sbiod->sbiod_pvt;
                struct evbuffer *buffer = bufferevent_get_input(bev);

                return (evbuffer_get_length(buffer) != 0);
                break;
            }
        default:
            break;
    }
    // we process no other controls
    return 0;
}

static ber_slen_t
sb_libevent_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    struct bufferevent *bev = sbiod->sbiod_pvt;
    ber_slen_t read;

    read = bufferevent_read(bev, buf, len);
    /* Were we to return a zero length read without setting errno, liblber
     * would think the socket is closed and give up on it */
    if (!read)
        errno = EWOULDBLOCK;
    return read;
}

static ber_slen_t
sb_libevent_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    struct bufferevent *bev = sbiod->sbiod_pvt;
    int rc;

    // bufferevent_write returns 0 when OK, -1 otherwise
    rc = bufferevent_write(bev, buf, len);
    return (rc == 0) ? len : 0;
}

static int
sb_libevent_close(Sockbuf_IO_Desc *sbiod)
{
    struct bufferevent *bev = sbiod->sbiod_pvt;
    bufferevent_data_cb readcb, writecb;
    bufferevent_event_cb eventcb;
    void *ctx;

    /* set up a write callback to dispose of the bufferevent after everything
     * is sent */
    bufferevent_getcb( bev, &readcb, &writecb, &eventcb, &ctx );

    /* we are often called several times */
    if (writecb != sb_libevent_all_sent)
        bufferevent_setcb( bev, readcb, sb_libevent_all_sent, eventcb, ctx );

    return 0;
}

Sockbuf_IO ber_sockbuf_io_libevent = {
    sb_libevent_setup,  /* sbi_setup */
    sb_libevent_remove, /* sbi_remove */
    sb_libevent_ctrl,   /* sbi_ctrl */
    sb_libevent_read,   /* sbi_read */
    sb_libevent_write,  /* sbi_write */
    sb_libevent_close   /* sbi_close */
};

int
init_ldap_connection(struct event_base *base, char *url)
{
    return 0;
}
