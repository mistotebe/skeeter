#include "module.h"
#include "config.h"
#include "logging.h"
#include "imap.h"
#include "ldap.h"

struct module *modules[] = {
    &logging_module,
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

static int
module_init(void *mod, void *arg)
{
    struct module *module = mod;
    struct event_base *base = arg;
    int rc = 0;

    if (!module->init)
        return rc;

    if (module->init(module, base))
        rc = 1;

    return rc;
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

int
initialize_modules(struct event_base *base)
{
    return avl_apply(config.modules, module_init, base, 1, 1) != AVL_NOMORE;
}

struct evdns_base *
get_dnsbase()
{
    /*TODO: figure out where to allocate and store it first,
     * maybe a dns module? */
    return NULL;
}
