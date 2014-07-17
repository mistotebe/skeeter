#include "../filter.c"
#include "test.h"

#define NUM_ELEMS(x) (sizeof(x)/(sizeof(*(x))))

struct filter_create_data {
    int rc;
    char *input;
    struct filter output;
} filter_create_data[] = {
    {
        .input = "",
        .rc = 0,
        .output = {
            .total_len = 0,
        },
    },
    {
        .input = "a=%%",
        .rc = 0,
        .output = {
            .total_len = 3,
        },
    },
    {
        .input = "()",
        .rc = 1,
    },
    {
        .input = "a=%",
        .rc = 1,
    },
    {
        .input = "a=%a",
        .rc = 1,
    },
    {
        .input = "(|(a=%u)(&(!(b=%u*%%*%d))(c=%u%d%U)))",
        .rc = 0,
        .output = {
            .total_len = 24,
            .occurrence = { 3, 2, 1 },
        },
    },
};

START_TEST(test_filter_create)
{
    struct filter filter = {};
    int occurrence[LITERAL] = {};
    struct filter_create_data *t = &filter_create_data[_i];
    struct filter_part *item;
    int type;

    ck_assert_int_eq(filter_create(&filter, t->input), t->rc);
    if (t->rc)
        return;

    ck_assert_int_eq(filter.total_len, t->output.total_len);

    STAILQ_FOREACH(item, &filter.body, next) {
        if (item->token_type == LITERAL) {
            /* text is only valid for literal parts */
            ck_assert_ptr_ne(item->text, NULL);
        } else {
            occurrence[item->token_type]++;
        }
    }

    for (type = 0; type < LITERAL; type++) {
        ck_assert_int_eq(filter.occurrence[type], occurrence[type]);
        ck_assert_int_eq(filter.occurrence[type], t->output.occurrence[type]);
    }

    filter_free(&filter);
}
END_TEST

struct filter_get_data {
    char *input, *output;
    struct user_info info;
} filter_get_data[] = {
    {
        .input = "a=b",
        .output = "a=b",
    },
    {
        .input = "(&(a=%u@%d)(b=%U))",
        .output = "(&(a=user@domain)(b=user@domain))",
        .info = {
            .username = { .bv_val = "user", .bv_len = 4 },
            .domain = { .bv_val = "domain", .bv_len = 6 },
        },
    },
    {
        .input = "(&(a=%u@%d)(b=%U))",
        .output = "(&(a=\\2A\\00@\\28)(b=\\2A\\00@\\28))",
        .info = {
            .username = { .bv_val = "*", .bv_len = 2 },
            .domain = { .bv_val = "()+", .bv_len = 1 },
        },
    },
};

START_TEST(test_filter_get)
{
    struct filter filter = {};
    struct filter_get_data *t = &filter_get_data[_i];

    ck_assert(!filter_create(&filter, t->input));
    ck_assert_str_eq(filter_get(&filter, &t->info), t->output);
}
END_TEST

TCase *
testcase_filter()
{
    TCase *testcase;

    testcase = tcase_create("filter");

    tcase_add_loop_test(testcase, test_filter_create, 0, NUM_ELEMS(filter_create_data));
    tcase_add_loop_test(testcase, test_filter_get, 0, NUM_ELEMS(filter_get_data));

    return testcase;
}
