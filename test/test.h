#ifndef TEST_H
#define TEST_H

#include <check.h>

void setup_logging(void);
void setup_ssl(void);

TCase *testcase_logging(void);
TCase *testcase_module(void);
TCase *testcase_filter(void);
TCase *testcase_ssl(void);

#endif /* TEST_H */
