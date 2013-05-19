#include "config.h"
#include "module.h"
#include "logging.h"
#include "avl/avl.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libconfig.h>

static const char *shortopts = "f:d:v";
static struct option options[] = {
    { NULL }
};

struct config config = {
    .conffile = "/etc/skeeter.conf",
    .loglevel = LOG_ERR,
};

int
parse_options(int argc, char **argv, struct config *config)
{
    int opt, option_index;

    while ((opt = getopt_long(argc, argv, shortopts,
                options, &option_index)) != -1)
    {
        switch (opt)
        {
            case 0:
                /* a separate long option */
                break;
            case 'd':
                /* do not detach - we are in debug mode */
                config->debug++;
                break;
            case 'f':
                /* we have a config */
                config->conffile = optarg;
                break;
            case 'v':
                /* print version and end */
                printf("Skeeter\n");
                exit(0);
                break;
            default:
                /* garbage in, bail */
                return 1;
        }
    }

    if (optind < argc) {
        /* there is something unexpected on the command line, bail too */
        return 1;
    }

    return 0;
}

int
process_config_file(struct config *config)
{
    int rc = 0;
    config_t cfg;
    config_setting_t *root;
    struct module **p;

    config_init(&cfg);

    if (config_read_file(&cfg, config->conffile) == CONFIG_FALSE) {
        /* failure */
        skeeter_log(LOG_ERR, "Failure reading configuration file '%s' at line %d: %s",
                config_error_file(&cfg), config_error_line(&cfg),
                config_error_text(&cfg));
        return 1;
    }
    root = config_root_setting(&cfg);

    for (p = modules; *p; p++) {
        struct module *module = *p;
        rc = register_module(module);
        if (rc)
            break;

        if (module->conf) {
            rc = module->conf(module, config_setting_get_member(root, module->name));
            if (rc)
                break;
        }
    }

    config_destroy(&cfg);
    return rc;
}
