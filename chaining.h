#ifndef _CHAINING_H
#define _CHAINING_H

#include <limits.h>
#include <event2/bufferevent.h>

#if INT_MAX <= SHRT_MAX
#error "need arch where short is shorter than int"
#endif

typedef enum {
    CHAIN_EVENT_MASK = (unsigned short)~0,
    CHAIN_DONE,
    CHAIN_ERROR,
    CHAIN_ABORT,
    CHAIN_AGAIN,
    CHAIN_MASK = 0xff * CHAIN_DONE,
} chain_result;

struct chain;

/**
 * Called when I/O happens on the chained bufferevent (provided as the second
 * argument).
 *
 * As long as it returns CHAIN_AGAIN, it will be called again when new I/O
 * happens. When CHAIN_DONE is returned, the next entry added with chain_add is
 * called and so on. For any other return code, see chain_except.
 */
typedef int (*chain_process)(struct chain *, struct bufferevent *, void *);

/** Called in the following cases:
 * - when event happens on the bufferevent (only bits in CHAIN_EVENT_MASK will
 *   be set)
 * - when chain_process returns anything else than CHAIN_AGAIN or CHAIN_DONE
 * - when the chain is being destroyed:
 *   - with the value provided to chain_destroy()
 *   - with CHAIN_DONE when all chain elements have finished successfully
 *   - with CHAIN_ABORT when no chain_except callback could recover (see below)
 *
 * In cases 1 and 2 the callback on the current chain element is run,
 * CHAIN_AGAIN and CHAIN_DONE are treated as if they were returned by the
 * respective chain_process. If a chain_except callback is not registered or
 * returns anything else, the chain-wide chain_except callback is run next,
 * with any return value except CHAIN_AGAIN leading to the chain being
 * chain_destroy()-ed with CHAIN_ABORT.
 *
 * It is guaranteed that each registered chain_except callback will be called
 * when the chain's life is ending. This is the case 3 above. The
 * callbacks will be called in the order they were chain_add()-ed and the
 * chain_except callback registered with chain_new() is called last.
 */
typedef int (*chain_except)(struct chain *, struct bufferevent *, int, void *);

/**
 * Allocates a new chain. Will get freed when the chain finishes or when
 * chain_destroy() is called.
 */
struct chain *chain_new(chain_except, void *);

/**
 * Adds a new element at the end of the chain.
 */
int chain_add(struct chain *, chain_process, chain_except, void *);

/**
 * Activates the chain on this bufferevent. This replaces all data/event
 * callbacks on the bufferevent.
 *
 * The chain then watches the bufferevent for the specified activity, EV_READ,
 * EV_WRITE or both.
 */
int chain_activate(struct chain *, struct bufferevent *, short);

/**
 * Runs all registered chain_except callbacks from chain_add in the order they
 * were added, then the callback from chain_new, then frees the chain and all
 * its elements.
 */
void chain_destroy(struct chain *, struct bufferevent *, int);

#endif /* _CHAINING_H */
