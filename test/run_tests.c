#include <unistd.h>
#include <stdlib.h>

#include "test.h"

typedef TCase * (*test_func)(void);

test_func tests[] = {
    &testcase_logging,
    &testcase_module,
    &testcase_filter,
    NULL
};

void setup(void)
{
    setup_logging();
}

void teardown(void)
{
}

int main()
{
    Suite *test_suite = suite_create("skeeter");
    SRunner *test_runner;
    test_func *func;
    int failed;

    for (func = tests; *func; func++) {
        TCase *testcase = (*func)();

        tcase_add_unchecked_fixture(testcase, setup, teardown);
        suite_add_tcase(test_suite, testcase);
    }

    test_runner = srunner_create(test_suite);

    srunner_run_all(test_runner, CK_NORMAL);
    failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return failed != 0;
}

