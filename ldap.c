#include <event2/bufferevent.h>

#include "avl/avl.h"
#include "ldap.h"
#include "io_handler.h"
#include <errno.h>
#include <stdlib.h>

#define config_entry(obj, name) { #name, &((obj).name) }
#define LDAP_PROTO_EXT 4

struct request {
    int msgid;
    ldap_cb cb;
    void *ctx;
};

struct ldap_config {
    char *host;
    int port;
    char *bind_dn;
    char *password;
    char *search_base;
    char *filter;
    char *attribute;
};

static struct ldap_config ldap_config = {
    .host = "ldap://ldap.example.com",
    .port = 389,
    .bind_dn = "cn=Directory Manager,o=example.com",
    .password = "abcd",
    .search_base = "o=example.com",
    .filter = "(mail=%u)",
    .attribute = "mailHost"
};

struct ldap_driver {
    struct event_base *base;
    struct bufferevent *bev;
    LDAP *ld;
    struct ldap_config *config;

    Avlnode *pending_requests;
};

struct module ldap_module = {
    .name = "ldap",
    .conf = ldap_driver_config,
    .init = ldap_driver_init,
};

static int request_cmp(void *left, void *right)
{
    struct request *l = left;
    struct request *r = right;
    return l->msgid - r->msgid;
}

void ldap_connect_cb(struct bufferevent *, short, void *);

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

// bufferevent creation and callback setting might be used more times
// therefore it deserves own function
void
ldap_driver_connect(struct ldap_driver* driver)
{
    struct evdns_base *dnsbase = get_dnsbase(); // not working yes

    if (driver->bev != NULL)
        bufferevent_free(driver->bev);

    driver->bev = bufferevent_socket_new(driver->base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(driver->bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(driver->bev, dnsbase, AF_UNSPEC,
                                        driver->config->host, driver->config->port);

    bufferevent_setcb(driver->bev, NULL, NULL, ldap_connect_cb, driver);
}

void ldap_connect_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct ldap_driver *driver = ctx;
    int rc;
    Sockbuf *sb;
    char *ldap_uri;

    asprintf(ldap_uri,"%s:%d",driver->config->host,driver->config->port);

    if (events & BEV_EVENT_CONNECTED) {
        if (ldap_init_fd(bufferevent_getfd(bev), LDAP_PROTO_EXT, ldap_uri, driver->ld))
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
        rc = ldap_simple_bind_s(driver->ld, driver->config->bind_dn, driver->config->password);
        if (rc != LDAP_SUCCESS) {
            fprintf(stderr, "error during bind: %s\n", ldap_err2string(rc));
        }

        bufferevent_setcb(bev, ldap_read_cb, NULL, ldap_error_cb, driver);
        free(ldap_uri);
        return;
    }

    // otherwise cleanup and restart
    ldap_connect_cleanup:
        bufferevent_free(bev);
        // wait for some time and try reconnect
        // sleep(5);
        ldap_driver_connect(driver);
}

int ldap_driver_init(struct module *module, struct event_base *base)
{
    /* open connection to the LDAP server and do an ldap_simple_bind_s
     * store the ld to driver */
    struct ldap_driver *driver = module->priv;
    driver->base = base;

    ldap_driver_connect(driver);

    return 0;
}

int ldap_driver_config(struct module *module, config_setting_t *conf)
{
    /* update the config with the appropriate values and register as "ldap" so
     * that "imap" can retrieve the driver */
    config_setting_t *setting, *value;
    struct ldap_driver *driver;
    const char *name;
    int port, i;

    if (conf == NULL)
        return 1;

    // entries that should contain only one string
    struct {
        char *name;
        char **addr;
    } simple_entries[] =
        {
            config_entry(ldap_config, bind_dn),
            config_entry(ldap_config, password),
            config_entry(ldap_config, search_base),
            config_entry(ldap_config, filter),
            config_entry(ldap_config, attribute)
        };
 
    setting = config_setting_get_member(conf, "host");
    if (setting != NULL) {
        value = config_setting_get_elem(setting, 0);
        name = config_setting_get_string(value);
        if (name != NULL) {
            /* lazy, lazy */
            asprintf(&ldap_config.host, "%s", name);
        }

        value = config_setting_get_elem(setting, 1);
        port = config_setting_get_int(value);
        if ((port > 0) && (port <= 65535)) {
            ldap_config.port = port;
        } else {
            return 1;
        }
    }

    for (i=0; i < sizeof(simple_entries)/sizeof(*simple_entries); i++) {
        setting = config_setting_get_member(conf, simple_entries[i].name);
        if (setting == NULL)
            continue;

        name = config_setting_get_string(setting);
        if (name != NULL) {
            /* lazy, lazy */
            asprintf(simple_entries[i].addr,"%s",name);
        }
    }

    driver->config = &ldap_config;
    module->priv = driver;

    return 0;
}

int get_user_info(struct user_info *info, ldap_cb cb, void *ctx)
{
    /* construct the search filter */

    /* send the search */
}

