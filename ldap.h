#ifndef _SKEETER_LDAP_H
#define _SKEETER_LDAP_H

#include <ldap.h>
#include <lber.h>
#include "config.h"
#include "module.h"

typedef void (*ldap_cb)(LDAP *, LDAPMessage *, void *);

extern struct module ldap_module;

struct user_info {
    struct berval username, domain;
    char **attrs;
};

int ldap_driver_init(struct module *, struct event_base *);
int ldap_driver_config(struct module *, config_setting_t *);

int get_user_info(struct module *, struct user_info *, ldap_cb, /* int *, */ void *);
//void abandon_search(int);

#endif /* _SKEETER_LDAP_H */
