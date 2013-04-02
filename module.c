#include "module.h"
#include "config.h"
#include "imap.h"
#include "ldap.h"

struct module *modules[] = {
    &imap_module,
    &ldap_module,
    NULL
};

static int
module_cmp(const void *left, const void *right)
{
    const struct module *l = left;
    const struct module *r = right;
    return strcmp(l->name, r->name);
}

int
register_module(struct module *module)
{
    return avl_insert(&config.modules, module, module_cmp, avl_dup_error);
}

struct module *
get_module(char *name)
{
    struct module needle = { .name = name };
    struct module *module = avl_find(config.modules, &needle, module_cmp);

    return module;
}

struct evdns_base *
get_dnsbase()
{
    /*TODO: figure out where to allocate and store it first,
     * maybe a dns module? */
    return NULL;
}
