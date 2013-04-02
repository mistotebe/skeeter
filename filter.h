#ifndef _FILTER_H
#define _FILTER_H

#include <sys/queue.h>
#include <lber.h>
#include "ldap.h"

// leave this item always at the end - necessary for creating occurence count list
enum filter_token {
    USER = 0,
    DOMAIN,
    ADDR,
    LITERAL
};

struct filter_part {
    enum filter_token token_type;
    struct berval *text;
    STAILQ_ENTRY(filter_part) next;
};

struct filter {
    STAILQ_HEAD(filterhead, filter_part) body;
    int total_len;
    int occurrence[LITERAL];
};

int filter_create(struct filter *, const char *);
char *filter_get(struct filter *, struct user_info *);
void filter_free(struct filter *);

#endif
