#include "../module.c"
#include "test.h"

static struct module test_modules[] = {
    { .name = "one" },
    { .name = "two" },
    { .name = "three" },
    {}
};

static struct module duplicate = {
    .name = "one"
};

START_TEST(test_module_register)
{
    struct module *module;

    for (module = test_modules; module->name; module++) {
        ck_assert_int_eq(register_module(module), 0);
        ck_assert_ptr_eq(get_module(module->name), module);
    }

    /* Adding a module with the same name should fail */
    ck_assert_int_ne(register_module(&duplicate), 0);
    ck_assert_ptr_eq(get_module(duplicate.name), test_modules);
}
END_TEST

TCase *
testcase_module()
{
    TCase *testcase;

    testcase = tcase_create("module");

    tcase_add_test(testcase, test_module_register);

    return testcase;
}
