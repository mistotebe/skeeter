#include "chaining.h"
#include <stdlib.h>
#include <sys/queue.h>
#include <assert.h>
#include <event2/event.h>

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

void chain_event(struct bufferevent *, short, void *);

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
chain_activate(struct chain *chain, struct bufferevent *bev, short flags)
{
    bufferevent_data_cb read_cb;
    bufferevent_data_cb write_cb;

    assert(chain && bev);

    read_cb = (flags & EV_READ) ? chain_run : NULL;
    write_cb = (flags & EV_WRITE) ? chain_run : NULL;

    chain->current = STAILQ_FIRST(&chain->elems);
    bufferevent_setcb(bev, read_cb, write_cb, chain_event, chain);

    return CHAIN_DONE;
}

void
chain_run(struct bufferevent *bev, void *ctx)
{
    struct chain *chain = ctx;
    struct chain_elem *cur;
    int rc = CHAIN_DONE;

    assert(chain);

    for (cur = chain->current;
            rc == CHAIN_DONE && cur;
            cur = STAILQ_NEXT(cur, next)) {
        chain->current = cur;
        rc = cur->process(chain, bev, cur->ctx);
    };

    if (rc == CHAIN_AGAIN) {
        /* We need more data */
        return;
    }

    /* Error */
    chain_event(bev, rc, ctx);
}

void
chain_event(struct bufferevent *bev, short events, void *ctx)
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
            return;
        }
    }

    if (chain->event) {
        rc = chain->event(chain, bev, events, chain->ctx);
        if (rc == CHAIN_AGAIN) {
            /* Recovered */
            return;
        }
    }

    chain_abort(chain, bev);
}

void
chain_abort(struct chain *chain, struct bufferevent *bev)
{
    struct chain_elem *elem;

    assert(chain);

    while (!STAILQ_EMPTY(&chain->elems)) {
        elem = STAILQ_FIRST(&chain->elems);
        if (elem->event)
            elem->event(chain, bev, CHAIN_ABORT, elem->ctx);

        STAILQ_REMOVE_HEAD(&chain->elems, next);
        free(elem);
    }

    if (chain->event)
        chain->event(chain, bev, CHAIN_ABORT, chain->ctx);
    free(chain);
}
