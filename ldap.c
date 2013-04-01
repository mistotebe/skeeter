#define _GNU_SOURCE
#include <event2/bufferevent.h>

#include "avl/avl.h"
#include "ldap.h"
#include "io_handler.h"
#include "filter.h"
#include <sys/queue.h>
#include <lber.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#define config_entry(obj, name) { #name, &(obj) }

int ldap_init_fd(ber_socket_t fd, int proto, LDAP_CONST char *url, LDAP **ldp );

#define LDAP_PROTO_EXT 4

#define DEFAULT_URI "ldap://ldap.example.com:389/o=example.com?mailHost?sub"

static struct timeval ldap_no_timeout = {
    .tv_sec = 0,
    .tv_usec = 0,
};

struct request {
    int msgid;
    ldap_cb cb;
    void *ctx;
    LDAP *ld;
    LDAPMessage *msg;
};

struct ldap_config {
    LDAPURLDesc *data;
    char *uri;
    char *bind_dn;
    struct berval password;
    struct filter filter;
    struct timeval reconnect_timeout;
};

static struct ldap_config config_default = {
    .bind_dn = "cn=Directory Manager,o=example.com",
    .password = { 4L, "abcd"},
    .uri = DEFAULT_URI,
    .reconnect_timeout = { 5, 0 },
};

struct ldap_q_entry {
    int flag;
    module_event_cb cb;
    void *ctx;
    TAILQ_ENTRY(ldap_q_entry) next;
};

struct ldap_driver {
    struct event_base *base;
    struct bufferevent *bev;
    LDAP *ld;
    struct ldap_config *config;
    struct event *reconnect_event;

    TAILQ_HEAD(ldap_q_tailhead, ldap_q_entry) ldap_q;

    Avlnode *pending_requests;
};

struct module ldap_module = {
    .name = "ldap",
    .conf = ldap_driver_config,
    .init = ldap_driver_init,
};

static int request_cmp(const void *left, const void *right)
{
    const struct request *l = left;
    const struct request *r = right;
    return l->msgid - r->msgid;
}

static void request_free(void *req)
{
    struct request *r = req;
    if (r->msg != NULL)
        ldap_msgfree(r->msg);
    free(req);
}

static void request_fail_free(void *req)
{
    struct request *r = req;
    // login failed, inform the client
    r->cb(r->ld,NULL,r->ctx);
    request_free(r);
}

static void handlers_free(struct ldap_driver *driver)
{
    struct ldap_q_entry *ent;
    while (!TAILQ_EMPTY(&driver->ldap_q)) {
        ent = TAILQ_FIRST(&driver->ldap_q);
        TAILQ_REMOVE(&driver->ldap_q, driver->ldap_q.tqh_first, next);
        free(ent);
    }
}

int get_ldap_errcode(LDAP *, LDAPMessage *);
void ldap_close_connection(struct ldap_driver *);
void ldap_reset_connection(struct ldap_driver *);
void ldap_error_cb(struct bufferevent *, short, void *);
void ldap_read_cb(struct bufferevent *, void *);
void ldap_bind_cb(struct bufferevent *, void *);
void ldap_connect_cb(struct bufferevent *, short, void *);
void ldap_driver_connect_cb(evutil_socket_t, short, void *);
int ldap_register_event(struct module *, int, module_event_cb, void *);
void ldap_call_handlers(struct ldap_driver *, int);
void ldap_shutdown(struct module *);

int
ldap_driver_init(struct module *module, struct event_base *base)
{
    /* open connection to the LDAP server and do an ldap_simple_bind_s
     * store the ld to driver */
    struct ldap_driver *driver = module->priv;
    driver->base = base;

    driver->reconnect_event = event_new(base, -1, EV_TIMEOUT, ldap_driver_connect_cb,
                                driver);
    if (driver->reconnect_event == NULL) {
        fprintf(stderr, "Failed to create LDAP handling event\n");
        return 1;
    }

    // activate the event immediately after starting
    event_active(driver->reconnect_event, EV_TIMEOUT, 1);

    return 0;
}

int
ldap_driver_config(struct module *module, config_setting_t *conf)
{
    /* update the config with the appropriate values and register as "ldap" so
     * that "imap" can retrieve the driver */
    config_setting_t *setting;
    struct ldap_config *config;
    struct ldap_driver *driver;
    char *password;
    int tout;

    if (conf == NULL)
        return 1;

    config = malloc(sizeof(struct ldap_config));
    if (config == NULL)
        return 1;
    *config = config_default;

    // entries that should contain only one string
    struct {
        char *name;
        char **addr;
    } *ptr, simple_entries[] =
        {
            config_entry(config->bind_dn, bind_dn),
            config_entry(password, password),
//            config_entry(config->data->lud_dn, search_base),
            { NULL }
        };
    ptr = simple_entries;

    // first parse the uri - it should allocate the LDAPURLDesc structure
    setting = config_setting_get_member(conf, "uri");
    if (setting != NULL)
        conf_get_string(config->uri, setting);

    if (ldap_is_ldap_url(config->uri)) {
        if (ldap_url_parse(config->uri,&(config->data))) {
            fprintf(stderr, "Can not parse LDAP URI\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Wrong format of ldap URI\n");
        return 1;
    }

    // we can not use conf_get_string macro because it is wrongly handling
    // the pointer to the target variable
    for (; ptr->name; ptr++) {
        setting = config_setting_get_member(conf, ptr->name);
        if (setting == NULL)
            continue;
        const char *val = config_setting_get_string(setting);
    // TODO: it fails for some config that is stored in the ldap structure (lud_dn for example)
        if (val != NULL)
            asprintf(ptr->addr, "%s", val);
    }

    ber_str2bv(password, 0, 0, &config->password);

    // filter is mandatory
    setting = config_setting_get_member(conf, "filter");
    if (setting == NULL)
        return 1;
    const char *val = config_setting_get_string(setting);
    if (val) {
        if (filter_create(&config->filter, val))
            return 1;
    } else {
        return 1;
    }

    setting = config_setting_get_member(conf, "reconnect_timeout");
    if (setting != NULL) {
        tout = config_setting_get_int(setting);
        if (tout >= 0) config->reconnect_timeout.tv_sec = tout;
    }

    driver = calloc(1, sizeof(struct ldap_driver));
    if (driver == NULL)
        return 1;

    driver->config = config;
    module->priv = driver;
    module->register_event = ldap_register_event;
    module->shutdown = ldap_shutdown;
    TAILQ_INIT(&driver->ldap_q);

    return 0;
}

int
get_ldap_errcode(LDAP* ld, LDAPMessage *msg)
{
/*
 * Simple getter of ldap error code to avoid using original function with
 * many unused arguments
 */
    int result;
    if ( ldap_parse_result(ld, msg, &result, NULL, NULL, NULL, NULL, 0) != LDAP_SUCCESS ) {
        fprintf(stderr, "Unable to parse ldap result\n");
        return -1;
    }
    return result;
}

void
ldap_close_connection(struct ldap_driver *driver)
{
    if (driver->ld != NULL) {
        ldap_unbind_ext(driver->ld, NULL, NULL);
        driver->ld = NULL;

        /* driver->bev is freed by the sockbuf automatically after all pending
         * data has been sent */
    } else if (driver->bev) {
        /* the connection failed, no sockbuf owns this bufferevent yet */
        bufferevent_free(driver->bev);
    }
    driver->bev = NULL;
}

void
ldap_reset_connection(struct ldap_driver *driver)
{
    ldap_close_connection(driver);
    // wait for some time and try reconnect
    event_add(driver->reconnect_event, &(driver->config->reconnect_timeout));
}

void
ldap_call_handlers(struct ldap_driver *driver, int flag)
{
    struct ldap_q_entry *ent, *next;
    for (ent = TAILQ_FIRST(&driver->ldap_q); ent; ent = next) {
        /* We might be freeing ent */
        next = TAILQ_NEXT(ent, next);

        if (!(flag & ent->flag))
            continue;

        ent->cb(flag, ent->ctx);

        if (!(flag & MODULE_PERSIST)) {
            TAILQ_REMOVE(&driver->ldap_q, ent, next);
            free(ent);
        }
    }
}

void
ldap_error_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct ldap_driver *driver = ctx;
    /* have we lost the connection? Disable the module temporarily and try to
     * create another, possibly after some time has passed */
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        // call the error handlers
        ldap_call_handlers(driver, MODULE_UNAVAILABLE);
        // flush the pending requests
        avl_free(driver->pending_requests, request_fail_free);
        ldap_reset_connection(driver);
    }
}

void
ldap_read_cb(struct bufferevent *bev, void *ctx)
{
    /* try ldap_result and iterate over the results */

    /* for each entry, update the pending_requests */
    /* if search res done is received, invoke the callback and remove the
     * corrensponding pending request */

    struct ldap_driver *driver = ctx;
    LDAPMessage *res;
    int msgtype, errcode;
    struct request *found;

    while ( (msgtype = ldap_result( driver->ld, LDAP_RES_ANY, 0, &ldap_no_timeout, &res )) > 0 ) {
        struct request needle = { .msgid = ldap_msgid(res) };

        // handle unsolicited message
        if (needle.msgid == 0) {
            fprintf(stderr,"LDAP server shutting down\n");
            ldap_error_cb(bev, BEV_EVENT_EOF, ctx);
            ldap_msgfree(res);
            break;
        }

        found = avl_find(driver->pending_requests, &needle, request_cmp);
        // it is probably too early or too late to get the result
        if (found == NULL) {
            fprintf(stderr, "Got response for non-existent request\n");
            ldap_msgfree(res);
            continue;
        }

        switch (msgtype) {
            case LDAP_RES_SEARCH_ENTRY:
                found->msg = res;
                // continue otherwise the message will be freed
                continue;
            case LDAP_RES_SEARCH_RESULT:
                errcode = get_ldap_errcode(driver->ld, res);

                if (errcode != LDAP_SUCCESS) {
                    fprintf(stderr, "Error during reading results: %s\n", ldap_err2string(errcode));
                    found->cb(driver->ld, NULL, found->ctx);
                } else {
                    found->cb(driver->ld, found->msg, found->ctx);
                }

                avl_delete(&driver->pending_requests, found, request_cmp);
                request_free(found);
                break;
            default:
                break;
        }
        ldap_msgfree(res);
    }
}

void
ldap_bind_cb(struct bufferevent *bev, void *ctx)
{
    /* try ldap_result and iterate over the results */
    struct ldap_driver *driver = ctx;
    LDAPMessage *res;
    int msgtype, errcode;

    while ( (msgtype = ldap_result( driver->ld, LDAP_RES_ANY, 0, &ldap_no_timeout, &res )) > 0 ) {
        errcode = get_ldap_errcode(driver->ld, res);
        // we need only msgtype and errcode, msg body is useless
        ldap_msgfree(res);

        if ( msgtype == LDAP_RES_BIND ) {
            if ( errcode == LDAP_SUCCESS ) {
                fprintf(stderr,"We are binded\n");
                bufferevent_setcb(bev, ldap_read_cb, NULL, ldap_error_cb, ctx);
                ldap_call_handlers(driver, MODULE_READY);
            } else {
                fprintf(stderr, "Bind failed: %s\n", ldap_err2string(errcode));
                ldap_reset_connection(driver);
            }
            break;
        } // ignore other than bind_result responses
    }
}

void
ldap_connect_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct ldap_driver *driver = ctx;
    int rc, msgid;
    Sockbuf *sb;

    if (events & BEV_EVENT_CONNECTED) {
        int ldap_version = LDAP_VERSION3;

        if (ldap_init_fd(bufferevent_getfd(bev), LDAP_PROTO_EXT, driver->config->uri, &(driver->ld)))
            goto ldap_connect_cleanup;
        ldap_set_option(driver->ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

        ldap_get_option(driver->ld, LDAP_OPT_SOCKBUF, &sb);
        if (sb == NULL) {
            fprintf(stderr, "Could not retrieve sockbuf\n");
            goto ldap_connect_cleanup;
        }

        if (ber_sockbuf_add_io(sb, &ber_sockbuf_io_libevent, LBER_SBIOD_LEVEL_PROVIDER, bev)) {
            fprintf(stderr, "Could not install sockbuf handler\n");
            goto ldap_connect_cleanup;
        }
        errno = 0;

        bufferevent_setcb(bev, ldap_bind_cb, NULL, ldap_error_cb, driver);
        rc = ldap_sasl_bind(driver->ld, driver->config->bind_dn,
                            LDAP_SASL_SIMPLE, &driver->config->password,
                            NULL, NULL, &msgid);
        if (rc != LDAP_SUCCESS) {
            fprintf(stderr, "error during bind: %s\n", ldap_err2string(rc));
            goto ldap_connect_cleanup;
        }

        return;
    }

    // otherwise cleanup and reconnect
ldap_connect_cleanup:
    ldap_reset_connection(driver);
}

// bufferevent creation and callback setting might be used more times
// therefore it deserves own function
void
ldap_driver_connect_cb(evutil_socket_t fd, short what, void *ctx)
{
    struct evdns_base *dnsbase = get_dnsbase();
    struct ldap_driver *driver = ctx;
    struct ldap_config *conf = driver->config;

    /* we must have disowned it in ldap_close_connection */
    assert(driver->bev == NULL);

    driver->bev = bufferevent_socket_new(driver->base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(driver->bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(driver->bev, dnsbase, AF_UNSPEC,
                                        conf->data->lud_host, conf->data->lud_port);
    bufferevent_setcb(driver->bev, NULL, NULL, ldap_connect_cb, driver);
    //TODO: timeout when can not connect to the hostname
}

int
ldap_register_event(struct module *module, int flag, module_event_cb cb, void *ctx)
{
    struct ldap_q_entry *entry;
    struct ldap_driver *driver = module->priv;
    entry = calloc(1,sizeof(struct ldap_q_entry));
    if (entry == NULL)
        return 1;
    entry->flag = flag;
    entry->cb = cb;
    entry->ctx = ctx;
    TAILQ_INSERT_TAIL(&driver->ldap_q, entry, next);
    return 0;
}

int
get_user_info(struct module *module, struct user_info *info, ldap_cb cb, void *ctx)
{
    int rc;
    struct ldap_driver *driver = module->priv;
    struct ldap_config *config = driver->config;

    struct request *req = calloc(1, sizeof (struct request));
    if (req == NULL)
        return 1;

    /* construct the search filter */
    char *filter = filter_get(&config->filter, info);
    if (filter == NULL) {
        fprintf(stderr, "Failed to construct filter\n");
        rc = 1;
        goto get_user_info_fail;
    }

    /* send the search */
    rc = ldap_search_ext(driver->ld, config->data->lud_dn,
                         config->data->lud_scope, filter,
                         info->attrs, 0,
                         NULL, NULL,
                         NULL, /* timeout here affects just the timelimit part of the search */
                         1, /* we want only one result */
                         &req->msgid);

    if (rc != LDAP_SUCCESS) {
        fprintf(stderr,"ldap_search failed for filter '%s' with error '%s'\n",filter,ldap_err2string(rc));
        goto get_user_info_fail;
    }

    req->cb = cb;
    req->ctx = ctx;
    req->ld = driver->ld;

    rc = avl_insert(&driver->pending_requests, req, request_cmp, avl_dup_error);

get_user_info_fail:
    if (rc) free(req);
    free(filter);
    return rc;
}

void
ldap_shutdown(struct module *module)
{
    struct ldap_driver *driver = module->priv;
//    ldap_call_handlers(driver, MODULE_SHUTDOWN);
    ldap_close_connection(driver);
    /*
     *  Use simple request_free with no notifications being sent to client,
     *  because the IMAP module might be already terminated and thus no message
     *  could be sent
     */
    avl_free(driver->pending_requests, request_free);
    // clear all ldap handlers
    handlers_free(driver);
}
