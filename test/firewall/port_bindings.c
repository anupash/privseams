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
#include <check.h>
#include "firewall/port_bindings.h"
#include "firewall/port_bindings.c"

// these tests do not clean up after themselves because they assume that
// check runs them in dedicated processes so the OS does the cleanup
START_TEST(test_hip_port_bindings_init_with_cache)
{
    fail_unless(hip_port_bindings_init(true) == 0, NULL);
}
END_TEST

START_TEST(test_hip_port_bindings_init_without_cache)
{
    fail_unless(hip_port_bindings_init(false) == 0, NULL);
}
END_TEST

// For unknown reasons, this file does not compile with the following,
// seemingly useless forward declaration
Suite *firewall_port_bindings(void);

Suite *firewall_port_bindings(void)
{
    Suite *s = suite_create("firewall/port_bindings");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_port_bindings_init_with_cache);
    tcase_add_test(tc_core, test_hip_port_bindings_init_without_cache);
    suite_add_tcase(s, tc_core);

    return s;
}
