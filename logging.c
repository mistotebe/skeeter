#include "logging.h"

#include <stdarg.h>
#include <strings.h>
#include <event2/event.h>
#include "config.h"

struct module logging_module = {
    .name = "logging",
    .conf = logging_setup,
};

#define table_entry(name) { #name, LOG_##name }
struct level {
    char *name;
    int level;
} level_table[] = {
    table_entry(EMERG),
    table_entry(ALERT),
    table_entry(CRIT),
    table_entry(ERR),
    table_entry(WARNING),
    table_entry(NOTICE),
    table_entry(INFO),
    table_entry(DEBUG),
    /* extra mappings */
    { "CRITICAL", LOG_CRIT },
    { "ERROR", LOG_ERR },
    { NULL }
};

struct facility {
    char *name;
    int facility;
} facility_table[] = {
    table_entry(AUTH),
    table_entry(AUTHPRIV),
    table_entry(CRON),
    table_entry(DAEMON),
    table_entry(FTP),
    table_entry(KERN),
    table_entry(LOCAL0),
    table_entry(LOCAL1),
    table_entry(LOCAL2),
    table_entry(LOCAL3),
    table_entry(LOCAL4),
    table_entry(LOCAL5),
    table_entry(LOCAL6),
    table_entry(LOCAL7),
    table_entry(LPR),
    table_entry(MAIL),
    table_entry(NEWS),
    table_entry(SYSLOG),
    table_entry(USER),
    table_entry(UUCP),
    { NULL }
};

typedef void (logger)(int, const char *, va_list);

static logger *skeeter_vlog;
logger skeeter_syslog, skeeter_stderr;

int logging_setup(struct module *module, config_setting_t *conf)
{
    config_setting_t *setting;
    const char *val;
    int num;

    if (config.debug < 2)
        skeeter_vlog = &skeeter_syslog;

    num = LOG_ERR;
    setting = config_setting_get_member(conf, "level");
    if (setting) {
        struct level *level;

        val = config_setting_get_string(setting);
        for (level = level_table; level->name; level++) {
            if (!strcasecmp(val, level->name))
                break;
        }
        if (!level->name) {
            skeeter_log(LOG_ERR, "Could not parse loglevel value '%s'", val);
            return 1;
        }
        num = level->level;
    }
    config.loglevel = num;

    num = LOG_MAIL;
    setting = config_setting_get_member(conf, "facility");
    if (setting) {
        struct facility *facility;

        val = config_setting_get_string(setting);
        for (facility = facility_table; facility->name; facility++) {
            if (!strcasecmp(val, facility->name))
                break;
        }
        if (!facility->name) {
            skeeter_log(LOG_ERR, "Could not parse log facility value '%s'", val);
            return 1;
        }
        num = facility->facility;
    }
    config.facility = num;

    openlog("skeeter", LOG_PID, config.facility);
    event_set_log_callback(skeeter_event_log);

    return 0;
}

void
skeeter_log(int level, const char *format, ...)
{
    va_list args;

    if (level > config.loglevel)
        return;

    va_start(args, format);
    skeeter_vlog(level, format, args);
    va_end(args);
}

void
skeeter_syslog(int level, const char *format, va_list args)
{
    vsyslog(level, format, args);
}

void
skeeter_stderr(int level, const char *format, va_list args)
{
    fprintf(stderr, "%s:\t", level_table[level].name);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

static logger *skeeter_vlog = skeeter_stderr;

void skeeter_event_log(int severity, const char *msg)
{
    /* make sure we never interpret msg as a format string */
    skeeter_log(severity, "%s", msg);
}
