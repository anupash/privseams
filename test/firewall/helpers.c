/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University.
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

#define _BSD_SOURCE

#include <check.h>
#include <stdlib.h>

#include "lib/core/common.h"
#include "firewall/helpers.h"
#include "test/mocks.h"
#include "test_suites.h"


START_TEST(test_system_printf)
{
    mock_system = true;

    char str[MAX_COMMAND_LINE + 1];
    memset(str, '.', sizeof(str));
    str[MAX_COMMAND_LINE] = '\0';

    fail_unless(system_printf("_%s",  str) == -1, "Truncated command line executed");
    fail_unless(system_printf("%s", str)   ==  0, "Fitting command line not executed");
}
END_TEST

Suite *firewall_helpers(void)
{
    Suite *s = suite_create("firewall/helpers");

    TCase *tc_helpers = tcase_create("helpers");
    tcase_add_test(tc_helpers, test_system_printf);
    suite_add_tcase(s, tc_helpers);

    return s;
}
