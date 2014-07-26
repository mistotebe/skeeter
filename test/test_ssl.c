#include "../ssl.c"
#include "test.h"

void
setup_ssl(void)
{
    ck_assert_int_eq(init_ssl(), 0);
}

START_TEST(test_ssl_init)
{
    ck_assert_int_eq(ssl_initialized, 0);
    setup_ssl();
    ck_assert_int_eq(ssl_initialized, 1);
}
END_TEST

START_TEST(test_ssl_new_ctx)
{
    SSL_CTX *ctx;

    setup_ssl();

    ctx = new_ssl_ctx("test/data/cert", "test/data/pkey");
    ck_assert_ptr_ne(ctx, NULL);

    SSL_CTX_free(ctx);
}
END_TEST

TCase *
testcase_ssl()
{
    TCase *testcase;

    testcase = tcase_create("ssl");

    tcase_add_test(testcase, test_ssl_init);
    tcase_add_test(testcase, test_ssl_new_ctx);

    return testcase;
}
