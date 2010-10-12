/**
 * @file
 *
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
 *
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lib/core/hit.h"

START_TEST (test_hip_convert_hit_to_str_valid)
{
    char buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", buf) == 0, NULL);
}
END_TEST

START_TEST (test_hip_convert_hit_to_str_null_buf)
{
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", NULL) == 1, NULL);
}
END_TEST

START_TEST (test_hip_convert_hit_to_str_null_prefix)
{
    char buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, NULL, buf) == 0, NULL);
}
END_TEST

START_TEST (test_hip_convert_hit_to_str_bounds)
{
    const char *prefix = "PREFIX";
    const unsigned long BEFORE_LEN = 30;
    const unsigned long PREFIX_LEN = sizeof(*prefix);
    const unsigned long HIT_LEN = 40; // 16 bytes -> 32 hex chars + 7 ':'s + \0
    const unsigned long AFTER_LEN = 30;
    char buf[BEFORE_LEN + PREFIX_LEN + HIT_LEN + AFTER_LEN];
    char ones[BEFORE_LEN + PREFIX_LEN + HIT_LEN + AFTER_LEN];
    hip_hit_t hit;
    memset(buf, -1, sizeof(buf));
    memset(ones, -1, sizeof(ones));
    memset(&hit.s6_addr, 0x22222222, sizeof(hit.s6_addr));

    // write the HIT string into the middle of the buffer
    fail_unless(hip_convert_hit_to_str(&hit, prefix, buf + BEFORE_LEN) == 0, NULL);
    // is the buffer before the HIT untouched?
    fail_unless(memcmp(buf, ones, BEFORE_LEN) == 0, NULL);
    // is the prefix correct?
    fail_unless(memcmp(buf + BEFORE_LEN, prefix, PREFIX_LEN) == 0, NULL);
    // is the first part of the HIT correct?
    fail_unless(*(buf + BEFORE_LEN + PREFIX_LEN) == '2', NULL);
    // is the last part of the HIT correct?
    fail_unless(*(buf + BEFORE_LEN + PREFIX_LEN + HIT_LEN - 2) == '2', NULL);
    // is the HIT 0-terminated?
    fail_unless(*(buf + BEFORE_LEN + PREFIX_LEN + HIT_LEN - 1) == '\0', NULL);
    // is the buffer after the HIT untouched?
    fail_unless(memcmp(buf + BEFORE_LEN + PREFIX_LEN + HIT_LEN, ones, AFTER_LEN) == 0, NULL);
}
END_TEST

Suite *lib_core_hit(void);

Suite *lib_core_hit(void)
{
    Suite *s = suite_create("lib/core/hit");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_valid);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_buf);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_prefix);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

