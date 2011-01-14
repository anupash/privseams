/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include <check.h>

#include "firewall/line_parser.h"
#include "firewall/line_parser.c"

// four lines, each 50 characters long (including \n)
char data[] = "I'm not knocking your want to carry that home    \n\
Took it with you when you moved and got it broke \n\
Found the pieces we counted them all alone       \n\
Didn't add up forgot to carry a zero             ";
// four pointers to the beginning of the lines
char *const lines[4] = {
    data,
    data + 50,
    data + 100,
    data + 150
};
// the memory area describing data
const struct hip_mem_area ma = { data, data + sizeof(data) };

// these tests do not clean up after themselves because they assume that
// check runs them in dedicated processes so the OS does the cleanup
START_TEST(test_hip_lp_create_valid)
{
    struct hip_line_parser lp;

    fail_unless(hip_lp_create(&lp, &ma) == 0, NULL);
}
END_TEST

START_TEST(test_hip_lp_create_null_lp)
{
    fail_unless(hip_lp_create(NULL, &ma) == -1, NULL);
}
END_TEST

START_TEST(test_hip_lp_create_null_ma)
{
    struct hip_line_parser lp;

    fail_unless(hip_lp_create(&lp, NULL) == -1, NULL);
}
END_TEST

START_TEST(test_hip_lp_delete_valid)
{
    struct hip_line_parser lp;
    int                    err = 0;

    err = hip_lp_create(&lp, &ma);
    assert(0 == err);
    hip_lp_delete(&lp);
}
END_TEST

START_TEST(test_hip_lp_delete_null_lp)
{
    hip_lp_delete(NULL);
}
END_TEST

START_TEST(test_hip_lp_first_valid)
{
    struct hip_line_parser lp;
    int                    err = 0;

    err = hip_lp_create(&lp, &ma);
    assert(0 == err);
    fail_unless(hip_lp_first(&lp) == lines[0], NULL);
}
END_TEST

START_TEST(test_hip_lp_first_null_lp)
{
    fail_unless(hip_lp_first(NULL) == NULL, NULL);
}
END_TEST

START_TEST(test_hip_lp_next_valid)
{
    struct hip_line_parser lp;
    int                    err   = 0;
    char                  *first = NULL;

    err = hip_lp_create(&lp, &ma);
    assert(0 == err);
    first = hip_lp_first(&lp);
    assert(first == lines[0]);

    fail_unless(hip_lp_next(&lp) == lines[1], NULL);
    fail_unless(hip_lp_next(&lp) == lines[2], NULL);
    fail_unless(hip_lp_next(&lp) == lines[3], NULL);
    fail_unless(hip_lp_next(&lp) == NULL, NULL);
}
END_TEST

START_TEST(test_hip_lp_next_null_lp)
{
    fail_unless(hip_lp_next(NULL) == NULL, NULL);
}
END_TEST

// For unknown reasons, this file does not compile without the following,
// seemingly useless forward declaration
Suite *firewall_line_parser(void);

Suite *firewall_line_parser(void)
{
    Suite *s = suite_create("firewall/line_parser");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_lp_create_valid);
    tcase_add_test(tc_core, test_hip_lp_create_null_lp);
    tcase_add_test(tc_core, test_hip_lp_create_null_ma);
    tcase_add_test(tc_core, test_hip_lp_delete_valid);
    tcase_add_test(tc_core, test_hip_lp_delete_null_lp);
    tcase_add_test(tc_core, test_hip_lp_first_valid);
    tcase_add_test(tc_core, test_hip_lp_first_null_lp);
    tcase_add_test(tc_core, test_hip_lp_next_valid);
    tcase_add_test(tc_core, test_hip_lp_next_null_lp);
    suite_add_tcase(s, tc_core);

    return s;
}
