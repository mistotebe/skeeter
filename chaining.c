#include "chaining.h"
#include <stdlib.h>
#include <sys/queue.h>
#include <assert.h>
#include <event2/event.h>

/*
 * Implementation considerations (aka features not advertised to chain users):
 * - do not cede control between an error being raised and before it will be
 *   handled by current+chain-wide except callback. If we did, we risk being
 *   called again with the chain being in a half torn-down state.
 */

struct chain_elem {
    chain_process process;
    chain_except event;
    void *ctx;
    STAILQ_ENTRY(chain_elem) next;
};

struct chain {
    STAILQ_HEAD(chain_q, chain_elem) elems;
    struct chain_elem *current;

    chain_except event;
    void *ctx;
};

static void chain_run(struct bufferevent *, void *);

static void chain_event(struct bufferevent *, short, void *);
static int chain_event_int(struct bufferevent *, int, void *);

int
chain_add(struct chain *chain, chain_process process, chain_except event, void *ctx)
{
    struct chain_elem *elem;

    assert(chain);

    elem = calloc(1, sizeof(struct chain_elem));
    if (!elem)
        return CHAIN_ERROR;

    elem->process = process;
    elem->event = event;
    elem->ctx = ctx;

    STAILQ_INSERT_TAIL(&chain->elems, elem, next);

    return CHAIN_DONE;
}

struct chain *
chain_new(chain_except event, void *ctx)
{
    struct chain *chain;

    assert(event);

    chain = calloc(1, sizeof(struct chain));
    if (!chain)
        return NULL;

    STAILQ_INIT(&chain->elems);
    chain->event = event;
    chain->ctx = ctx;

    return chain;
}

int
chain_activate(struct chain *chain, struct bufferevent *bev, short iotype)
{
    bufferevent_data_cb read_cb;
    bufferevent_data_cb write_cb;

    assert(chain && bev);

    read_cb = (iotype & EV_READ) ? chain_run : NULL;
    write_cb = (iotype & EV_WRITE) ? chain_run : NULL;

    chain->current = STAILQ_FIRST(&chain->elems);
    bufferevent_setcb(bev, read_cb, write_cb, chain_event, chain);

    /* we'd be stuck indefinitely until there was a new event on bev, so run
     * now */
    bufferevent_trigger(bev, iotype, BEV_TRIG_DEFER_CALLBACKS);

    return CHAIN_DONE;
}

static void
chain_run(struct bufferevent *bev, void *ctx)
{
    struct chain *chain = ctx;
    struct chain_elem *cur;
    int rc = CHAIN_DONE;

    assert(chain);
    while (rc == CHAIN_DONE) {
        for (cur = chain->current;
                rc == CHAIN_DONE && cur;
                cur = STAILQ_NEXT(cur, next)) {
            chain->current = cur;
            if (cur->process)
                rc = cur->process(chain, bev, cur->ctx);
        };

        if (rc == CHAIN_AGAIN) {
            /* We need more data */
            return;
        }
        if (rc == CHAIN_DONE) {
            chain_destroy(chain, bev, CHAIN_DONE);
            return;
        }

        /* Error */
        rc = chain_event_int(bev, rc, ctx);
        /* If we recovered with CHAIN_DONE now, continue */
    }
}

static void
chain_event(struct bufferevent *bev, short events, void *ctx)
{
    (void)chain_event_int(bev, events, ctx);
}

static int
chain_event_int(struct bufferevent *bev, int events, void *ctx)
{
    struct chain *chain = ctx;
    int rc;

    assert(chain && chain->current);

    if (chain->current->event) {
        rc = chain->current->event(chain, bev, events, chain->current->ctx);
        if (rc == CHAIN_AGAIN || rc == CHAIN_DONE) {
            if (rc == CHAIN_DONE)
                chain->current = STAILQ_NEXT(chain->current, next);
            /* Recovered */
            return rc;
        }
    }

    if (chain->event) {
        rc = chain->event(chain, bev, events, chain->ctx);
        if (rc == CHAIN_AGAIN) {
            /* Recovered */
            return rc;
        }
    }

    chain_destroy(chain, bev, CHAIN_ABORT);
    return CHAIN_ABORT;
}

void
chain_destroy(struct chain *chain, struct bufferevent *bev, int events)
{
    struct chain_elem *elem;

    assert(chain);

    while (!STAILQ_EMPTY(&chain->elems)) {
        elem = STAILQ_FIRST(&chain->elems);
        if (elem->event)
            elem->event(chain, bev, events, elem->ctx);

        STAILQ_REMOVE_HEAD(&chain->elems, next);
        free(elem);
    }

    if (chain->event)
        chain->event(chain, bev, events, chain->ctx);
    free(chain);
}
