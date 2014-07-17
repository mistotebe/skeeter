#include "../logging.c"
#include "test.h"

static int logger_calls = 0;
static const char message[] = "At least 1 critical error has occured if this does not get logged";

static void
logger_ignore(int level, const char *format, va_list args)
{
    return;
}

void
setup_logging(void)
{
    /* We do not want to spam the system logs/stderr */
    skeeter_vlog = logger_ignore;
}

static void
testing_vlog(int level, const char *format, va_list args)
{
    char buf[BUFSIZ];
    int len;

    logger_calls++;
    ck_assert_int_eq(level, LOG_CRIT);

    len = vsnprintf(buf, BUFSIZ, format, args);
    ck_assert_int_lt(len, BUFSIZ);

    ck_assert_str_eq(buf, message);
}

START_TEST(test_logging_config)
{
}
END_TEST

START_TEST(test_logging_log)
{
    skeeter_vlog = testing_vlog;

    config.loglevel = LOG_ERR;

    ck_assert_int_eq(logger_calls, 0);

    skeeter_log(LOG_CRIT, "At least %d critical error has occured if this does%s get logged", 1, " not");
    ck_assert_int_eq(logger_calls, 1);

    skeeter_log(LOG_WARNING, "This message is ignored");
    ck_assert_int_eq(logger_calls, 1);
}
END_TEST

TCase *
testcase_logging()
{
    TCase *testcase;

    testcase = tcase_create("logging");

    tcase_add_test(testcase, test_logging_config);
    tcase_add_test(testcase, test_logging_log);

    return testcase;
}
