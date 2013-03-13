#define _GNU_SOURCE
#include <event2/bufferevent.h>

#include "avl/avl.h"
#include "ldap.h"
#include "io_handler.h"
#include <lber.h>
#include <errno.h>
#include <stdlib.h>

#define config_entry(obj, name) { #name, &(obj) }
int ldap_init_fd(ber_socket_t fd, int proto, LDAP_CONST char *url, LDAP **ldp );
#define LDAP_PROTO_EXT 4

#define DEFAULT_URI "ldap://ldap.example.com:389/o=example.com?mailHost?sub?(uid=%u)"

struct request {
    int msgid;
    ldap_cb cb;
    void *ctx;
    LDAPMessage *msg;
};

struct ldap_config {
    LDAPURLDesc *data;
    char *bind_dn;
    char *password;
    char *uri;
    struct timeval reconnect_tout;
};

static struct ldap_config ldap_config = {
    .bind_dn = "cn=Directory Manager,o=example.com",
    .password = "abcd",
    .uri = DEFAULT_URI,
    .reconnect_tout = { 5, 0 },
};

struct ldap_driver {
    struct event_base *base;
    struct bufferevent *bev;
    LDAP *ld;
    struct ldap_config *config;
    struct event *reconnect_event;

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

void ldap_connect_cb(struct bufferevent *, short, void *);

int get_ldap_errcode(LDAP* ld, LDAPMessage *msg)
{
/*
 * Simple getter of ldap error code to avoid using original function with
 * many unused arguments
 */
    int result;
    if ( ldap_parse_result(ld, msg, &result, NULL, NULL, NULL, NULL, 1) != LDAP_SUCCESS ) {
        fprintf(stderr, "Unable to parse ldap result\n");
        return -1;
    }
    return result;
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

    struct ldap_driver *driver = ctx;
    LDAPMessage *res;
    int msgtype, errcode;
    static struct timeval poll_time = {0, 0};
    struct request *found;

    while ( (msgtype = ldap_result( driver->ld, LDAP_RES_ANY, 0, &poll_time, &res )) > 0 ) {
        // we are interested in search responses only
        if (msgtype == LDAP_RES_SEARCH_ENTRY || msgtype == LDAP_RES_SEARCH_RESULT) {
            struct request needle = { .msgid = ldap_msgid(res) };
            errcode = get_ldap_errcode(driver->ld, res);
            found = avl_find(driver->pending_requests, &needle, request_cmp);
            // it is probably too early or too lateto get the result
            if(found == NULL) {
                fprintf(stderr, "storing requests into avl tooks long time\n");
                continue;
            }

            if ( msgtype == LDAP_RES_SEARCH_ENTRY ) {
                // read the result and store it into avl
                found->msg = res;
            } else {
                if (errcode == LDAP_SUCCESS) {
                    found->cb(found->msg,found->ctx);
                } else {
                    fprintf(stderr, "Error during reading results: %s\n", ldap_err2string(errcode));
                    found->cb(NULL,found->ctx);
                }
                if(found->msg != NULL) free(found->msg);
                avl_delete(&driver->pending_requests, &needle, request_cmp);
            }
        }
    }
}

void ldap_bind_cb(struct bufferevent *bev, void *ctx) {
    /* try ldap_result and iterate over the results */
    struct ldap_driver *driver = ctx;
    LDAPMessage *res;
    int msgtype, errcode;
    static struct timeval poll_time = {0, 0};

    while ( (msgtype = ldap_result( driver->ld, LDAP_RES_ANY, 0, &poll_time, &res )) > 0 ) {
        if ( msgtype == LDAP_RES_BIND ) {
            errcode = get_ldap_errcode(driver->ld, res);
            if ( errcode == LDAP_SUCCESS ) {
                bufferevent_setcb(bev, ldap_read_cb, NULL, ldap_error_cb, ctx);
                return;
            } else {
                fprintf(stderr, "Bind failed: %s\n", ldap_err2string(errcode));
                // try binding again after some time
                event_add(driver->reconnect_event, &(driver->config->reconnect_tout));
                return;
            }
        } // ignore other than bind_result responses
    } //otherwise restart bind
}

void ldap_connect_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct ldap_driver *driver = ctx;
    struct berval password = {0, NULL};
    int rc, msgid;
    Sockbuf *sb;

    if (events & BEV_EVENT_CONNECTED) {
        if (ldap_init_fd(bufferevent_getfd(bev), LDAP_PROTO_EXT, driver->config->uri, &(driver->ld)))
            goto ldap_connect_cleanup;
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
        password.bv_val = ber_strdup(driver->config->password);
        password.bv_len = strlen(password.bv_val);
        rc = ldap_sasl_bind(driver->ld, driver->config->bind_dn, LDAP_SASL_SIMPLE, &password, NULL, NULL, &msgid);
        if (rc != LDAP_SUCCESS) {
            fprintf(stderr, "error during bind: %s\n", ldap_err2string(rc));
            // restart connection after timeout
        }

        return;
    }

    // otherwise cleanup and restart
    ldap_connect_cleanup:
        bufferevent_free(bev); bev = NULL;
        // wait for some time and try reconnect
        event_add(driver->reconnect_event, &(driver->config->reconnect_tout));
}

// bufferevent creation and callback setting might be used more times
// therefore it deserves own function
void ldap_driver_connect_cb(evutil_socket_t fd, short what, void *ctx)
{
    struct evdns_base *dnsbase = get_dnsbase();
    struct ldap_driver *driver = ctx;
    struct ldap_config *conf = driver->config;

    if (driver->bev != NULL) {
        bufferevent_free(driver->bev); driver->bev = NULL;
    }

    driver->bev = bufferevent_socket_new(driver->base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(driver->bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(driver->bev, dnsbase, AF_UNSPEC,
                                        conf->data->lud_host, conf->data->lud_port);
    bufferevent_setcb(driver->bev, NULL, NULL, ldap_connect_cb, driver);
}

int ldap_driver_init(struct module *module, struct event_base *base)
{
    /* open connection to the LDAP server and do an ldap_simple_bind_s
     * store the ld to driver */
    struct ldap_driver *driver = module->priv;
    driver->base = base;
    // no waiting on init
    struct timeval initial_timeout = { 0, 0 };

    driver->reconnect_event = event_new(base, -1, EV_TIMEOUT, ldap_driver_connect_cb,
                                driver);
    if (driver->reconnect_event == NULL) {
        fprintf(stderr, "Failed to create LDAP handling event\n");
        return 1;
    }

    event_add(driver->reconnect_event, &initial_timeout);

    return 0;
}

int ldap_driver_config(struct module *module, config_setting_t *conf)
{
    /* update the config with the appropriate values and register as "ldap" so
     * that "imap" can retrieve the driver */
    config_setting_t *setting, *value;
    struct ldap_driver *driver;
    int i,tout;

    if (conf == NULL)
        return 1;

    // first parse the uri - it should allocate the LDAPURLDesc structure
    setting = config_setting_get_member(conf, "uri");
    if (setting != NULL)
        conf_get_string(ldap_config.uri, setting);

    if (ldap_is_ldap_url(ldap_config.uri)) {
        if (ldap_url_parse(ldap_config.uri,&(ldap_config.data))) {
            fprintf(stderr, "Can not parse LDAP URI\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Wrong format of ldap URI\n");
        return 1;
    }

    // entries that should contain only one string
    struct {
        char *name;
        char **addr;
    } simple_entries[] =
        {
            config_entry(ldap_config.bind_dn, bind_dn),
            config_entry(ldap_config.password, password),
            config_entry(ldap_config.data->lud_dn, search_base),
            config_entry(ldap_config.data->lud_filter, filter),
        };

    // we can not use conf_get_string macro because it is wrongly hanling
    // the pointer to the target variable
    for (i=0; i < sizeof(simple_entries)/sizeof(*simple_entries); i++) {
        setting = config_setting_get_member(conf, simple_entries[i].name);
        if (setting == NULL)
            continue;
        const char *val = config_setting_get_string(setting);
        if (val != NULL)
            asprintf(simple_entries[i].addr, "%s", val);
    }

    setting = config_setting_get_member(conf, "search_attribute");
    if (setting != NULL) {
        if (ldap_config.data->lud_attrs != NULL) {
            for(i=0; i < sizeof(ldap_config.data->lud_attrs)/sizeof(*ldap_config.data->lud_attrs); i++){
                free(ldap_config.data->lud_attrs[i]);
            }
            free(ldap_config.data->lud_attrs);
        }
        i = config_setting_length(setting);
        ldap_config.data->lud_attrs = calloc(i+1,sizeof(char *));
        if(ldap_config.data->lud_attrs == NULL)
            return 1;
        i=0;
        while((value=config_setting_get_elem(setting,i)) != NULL)
        {
            conf_get_string(ldap_config.data->lud_attrs[i],value);
            i++;
        }
        ldap_config.data->lud_attrs[i] = NULL;
    }

    setting = config_setting_get_member(conf, "reconnect_timeout");
    if (setting != NULL) {
        tout = config_setting_get_int(setting);
        if (tout >= 0) ldap_config.reconnect_tout.tv_sec = tout;
    }

    driver = calloc(1, sizeof(struct ldap_driver));
    if(driver == NULL)
        return 1;

    driver->config = &ldap_config;
    module->priv = driver;

    return 0;
}

char * expand_tokens(char *pattern, char *username, char *domain)
{
 /*
  * Expand user specified search string into usable ldap filter
  * %% = %
  * %u = username
  * %U = username@domain
  * %d = domain
  * TODO: escape some characters "* ( ) \ \0"
  */
    char *buffer, *buf_ptr, *orig, *orig_end, *token;
    int username_len, domain_len, total;

    total = strlen(pattern);
    username_len = strlen(username);
    domain_len = strlen(domain);

    orig = pattern;
    orig_end = pattern + total;

    for(; *orig; orig++) {
        if( *orig == '%' ) {
            switch(*(orig+1)) {
                // two '%' reduces into one
                case '%':
                    total--;
                    break;
                case 'u':
                    total += username_len - 2;
                    break;
                case 'U':
                    // full address should contain additionaly an '@'
                    total += username_len + domain_len - 1;
                    break;
                case 'd':
                    total += domain_len - 2;
                    break;
                default:
                    fprintf(stderr,"Unsupported token\n");
                    break;
            }
        }
    }

    buffer = malloc( (total + 1) * sizeof(char));
    if (buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        goto expand_tokens_cleanup;
    }
    memset(buffer,'\0', total+1);
    buf_ptr = buffer;
    orig = pattern;

    while ( (token=strchr(orig,'%')) != NULL ) {
        if (token > orig) {
            memcpy(buf_ptr, orig, token-orig);
            buf_ptr += token-orig;
        }

        if (token+1 > orig_end) {
            fprintf(stderr,"Boundary broken\n");
            goto expand_tokens_cleanup;
        }

        switch( *(token+1) ){
            case '%':
                *buf_ptr = *token;
                break;
            case 'u':
                memcpy(buf_ptr, username, username_len); buf_ptr += username_len;
                break;
            case 'U':
                memcpy(buf_ptr, username, username_len); buf_ptr += username_len;
                *buf_ptr++ = '@';
                memcpy(buf_ptr, domain, domain_len); buf_ptr += domain_len;
                break;
            case 'd':
                memcpy(buf_ptr, domain, domain_len); buf_ptr += domain_len;
                break;
            default:
                fprintf(stderr,"Malformed filter\n");
                goto expand_tokens_cleanup;
        }

        orig = token + 2;
    }

    if (orig < orig_end)
        memcpy(buf_ptr,orig,orig_end-orig);

    return buffer;

    expand_tokens_cleanup:
        free(buffer);
        return NULL;
}

int get_user_info(struct module *module, struct user_info *info, ldap_cb cb, void *ctx)
{
    int msgid, rc;
    struct ldap_driver *driver = module->priv;
    struct ldap_config *config = driver->config;

    struct request *req = malloc(sizeof (struct request));
    if (req == NULL)
        goto get_user_info_fail;

    /* construct the search filter */
    char *filter = expand_tokens(config->data->lud_filter, info->username, "");
    if(filter == NULL) {
        fprintf(stderr, "Failed to construct filter\n");
        goto get_user_info_fail;
    }

    /* send the search */
    rc = ldap_search_ext(driver->ld,config->data->lud_dn,
                         LDAP_SCOPE_SUBTREE, filter,
                         ldap_config.data->lud_attrs, 0,
                         NULL, NULL,
                         NULL, 1, // no timeout set and we want only one result
                         &msgid);

   if(rc != LDAP_SUCCESS) {
        fprintf(stderr,"ldap_search failed for filter '%s' with error '%s'\n",filter,ldap_err2string(rc));
        goto get_user_info_fail;
    }

    req->msgid = msgid;
    req->cb = cb;
    req->ctx = ctx;
    req->msg = NULL;

    if(avl_insert(&driver->pending_requests, req, request_cmp, avl_dup_error))
        goto get_user_info_fail;

    return 0;

get_user_info_fail:
    // respond to client immediately
    cb(NULL,ctx);
    if(req != NULL) free(req);
    if(filter != NULL) free(filter);
    return 1;
}

