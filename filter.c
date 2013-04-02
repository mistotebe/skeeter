#define _GNU_SOURCE
#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ldap.h>

#define COPY_TEXT_BER(dst,src) \
    memcpy((dst), (src)->bv_val, (src)->bv_len); \
    (dst) += (src)->bv_len;

int
filter_create(struct filter *filter, const char *pattern)
{
    struct filter_part *entry;
    struct filterhead *head = &filter->body;
    const char *ptr, *prev, *end;
    BerElement *ber;
    int len = strlen(pattern);

    STAILQ_INIT(head);

    filter->total_len = len;
    end = pattern + len;

    /* test input filter validity */
    ber = ber_alloc_t(0);
    if (!ber)
        return 1;
    if (ldap_put_vrFilter(ber, pattern)) {
        ber_free(ber, 1);
        return 1;
    }
    ber_free(ber, 1);

    prev = pattern;
    while ( *(ptr=strchrnul(prev, '%')) != '\0' )
    {
        filter->total_len -= 2;
        if (prev != ptr) {
            entry = malloc(sizeof(struct filter_part));
            if (entry == NULL) return 1;

            /* the original string comes from config and will be freed -> we
             * need to dup it */
            entry->text = ber_str2bv(prev, ptr - prev, 1, NULL);
            entry->token_type = LITERAL;

            STAILQ_INSERT_TAIL(head, entry, next);
        }

        ptr++; // we are interested in the following symbol

        // '%' character is not allowed at the last position
        if (ptr >= end)
            return 1;

        entry = malloc(sizeof(struct filter_part));
        if (entry == NULL) return 1;

        switch (*ptr) {
            case '%':
                filter->total_len++;
                entry->text = ber_str2bv(ptr, 1, 1, NULL);
                entry->token_type = LITERAL;
                break;
            case 'u':
                entry->token_type = USER;
                break;
            case 'd':
                entry->token_type = DOMAIN;
                break;
            case 'U':
                entry->token_type = ADDR;
                break;
            default:
                fprintf(stderr, "Unsupported token %c\n", *ptr);
                free(entry);
                return 1;
        }
        STAILQ_INSERT_TAIL(head, entry, next);
        if (entry->token_type != LITERAL)
            filter->occurrence[entry->token_type] += 1;

        ptr++;
        prev = ptr;
    }

    if (prev < ptr) {
        entry = malloc(sizeof(struct filter_part));
        if (entry == NULL) return 1;

        entry->text = ber_str2bv(prev, ptr - prev, 1, NULL);
        entry->token_type = LITERAL;

        STAILQ_INSERT_TAIL(head, entry, next);
    }

    return 0;
}

char *
filter_get(struct filter *filter, struct user_info *info)
{
    char *result, *ptr;
    struct filter_part *item;
    struct berval esc_username, esc_domainname;
    int addr_len, total;

    if (ldap_bv2escaped_filter_value(&info->username, &esc_username))
        goto filter_get_done;
    if (ldap_bv2escaped_filter_value(&info->domain, &esc_domainname))
        goto filter_get_done;

    addr_len = esc_username.bv_len + 1 + esc_domainname.bv_len;

    total = filter->total_len;
    total += esc_username.bv_len * filter->occurrence[USER];
    total += esc_domainname.bv_len * filter->occurrence[DOMAIN];
    total += addr_len * filter->occurrence[ADDR];
    total++; // remember trailing '\0'

    result = calloc(total, sizeof(char));
    if (!result)
        goto filter_get_done;

    ptr = result;
    STAILQ_FOREACH(item, &filter->body, next) {
        switch(item->token_type) {
            case USER:
                COPY_TEXT_BER(ptr, &esc_username);
                break;
            case DOMAIN:
                COPY_TEXT_BER(ptr, &esc_domainname);
                break;
            case ADDR:
                COPY_TEXT_BER(ptr, &esc_username);
                *ptr = '@'; ptr++;
                COPY_TEXT_BER(ptr, &esc_domainname);
                break;
            case LITERAL:
                COPY_TEXT_BER(ptr, item->text);
                break;
            default:
                // this should never happen
                assert(0);
        }
    }

filter_get_done:
    if (esc_username.bv_len) ber_memfree(esc_username.bv_val);
    if (esc_domainname.bv_len) ber_memfree(esc_domainname.bv_val);
    return result;
}

void
filter_free(struct filter *filter)
{
    struct filterhead *head = &filter->body;
    struct filter_part *to_remove;
    while (!STAILQ_EMPTY(head)) {
        to_remove = STAILQ_FIRST(head);
        STAILQ_REMOVE_HEAD(head, next);
        // REMOVE_HEAD only unlinked the element
        if (to_remove->token_type == LITERAL)
            ber_bvfree(to_remove->text);
        free(to_remove);
    }
}
