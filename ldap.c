#include <event2/bufferevent.h>

#include "avl/avl.h"
#include "ldap.h"

struct ldap_driver {
    struct bufferevent *bev;
    LDAP *ld;

    Avlnode *pending_requests;
};

struct request {
    int msgid;
    ldap_cb cb;
    void *ctx;
};

static int request_cmp(void *left, void *right)
{
    struct request *l = left;
    struct request *r = right;
    return l->msgid - r->msgid;
}

void ldap_error_cb(struct bufferevent *bev, short events, void *ctx)
{
    /* have we lost the connection? Disable the module temporarily and try to
     * create another, possibly after some time has passed */
}

void ldap_read_cb(struct bufferevent *bev, void *ctx) {
    /* try ldap_result and iterate over the results */

    /* for each entry, update the pending_requests */
    /* if search res done is received, invoke the callback and remove the
     * corrensponding pending request */
}

int ldap_driver_init(void)
{
    /* open connection to the LDAP server and do an ldap_simple_bind_s
     * store the ld to driver */
}

int ldap_driver_config(config_setting_t *)
{
    /* update the config with the appropriate values and register as "ldap" so
     * that "imap" can retrieve the driver */
}

int get_user_info(struct user_info *info, ldap_cb cb, void *ctx)
{
    /* construct the search filter */

    /* send the search */
}

