#ifndef _CHAINING_H
#define _CHAINING_H

#include <event2/bufferevent.h>

typedef enum {
    CHAIN_DONE,
    CHAIN_ERROR,
    CHAIN_ABORT,
    CHAIN_AGAIN,
} chain_result;

struct chain;

typedef int (*chain_process)(struct chain *, struct bufferevent *, void *);
typedef short (*chain_except)(struct chain *, struct bufferevent *, short, void *);

int chain_add(struct chain *, chain_process, chain_except, void *);
struct chain *chain_new(chain_except, void *);
int chain_activate(struct chain *, struct bufferevent *, short);
void chain_run(struct bufferevent *, void *);
void chain_abort(struct chain *, struct bufferevent *);

#endif /* _CHAINING_H */
