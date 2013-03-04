#include <event2/bufferevent.h>

#include "avl/avl.h"
#include "ldap.h"

#define config_entry(obj, name) { #name, &((obj).name) }

struct ldap_driver {
    struct bufferevent *bev;
    LDAP *ld;
    struct ldap_config *config;

    Avlnode *pending_requests;
};

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

int ldap_driver_init(struct module *module, struct event_base *base)
{
    /* open connection to the LDAP server and do an ldap_simple_bind_s
     * store the ld to driver */
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

