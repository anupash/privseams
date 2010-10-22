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

/**
 * @file
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lib/core/hit.h"

START_TEST(test_hip_convert_hit_to_str_valid)
{
    char buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", buf) == 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_hit)
{
    char buf[64];
    hip_convert_hit_to_str(NULL, "", buf);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_buf)
{
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", NULL) == 1, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_prefix)
{
    char buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, NULL, buf) == 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_bounds)
{
    const char suffix[] = "SFX";
    const unsigned int BEFORE_LEN = 30;
    const unsigned int HIT_LEN = 39; // 16 bytes -> 32 hex chars + 7 ':'s
    const unsigned int SUFFIX_LEN = sizeof(suffix); // includes null char
    const unsigned int AFTER_LEN = 30;
    char buf[BEFORE_LEN + HIT_LEN + SUFFIX_LEN + AFTER_LEN] = { 1 };
    char ones[BEFORE_LEN + HIT_LEN + SUFFIX_LEN + AFTER_LEN] = { 1 };
    hip_hit_t hit;
    memset(&hit.s6_addr, 0x22, sizeof(hit.s6_addr));

    // write the HIT string into the middle of the buffer
    fail_unless(hip_convert_hit_to_str(&hit, suffix, buf + BEFORE_LEN) == 0, NULL);
    // is the buffer before the HIT untouched?
    fail_unless(memcmp(buf, ones, BEFORE_LEN) == 0, NULL);
    // is the first part of the HIT correct?
    fail_unless(*(buf + BEFORE_LEN) == '2', NULL);
    // is the last part of the HIT correct?
    fail_unless(*(buf + BEFORE_LEN + HIT_LEN - 1) == '2', NULL);
    // is the suffix correct including the terminating null character?
    fail_unless(memcmp(buf + BEFORE_LEN + HIT_LEN, suffix, SUFFIX_LEN) == 0, NULL);
    // is the buffer after the suffix untouched?
    fail_unless(memcmp(buf + BEFORE_LEN + HIT_LEN + SUFFIX_LEN, ones, AFTER_LEN) == 0, NULL);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_bigger)
{
    const hip_hit_t bigger = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t smaller = IN6ADDR_ANY_INIT;
    fail_unless(hip_hit_is_bigger(&bigger, &smaller) == 1, NULL);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_equal_smaller)
{
    const hip_hit_t bigger = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t smaller = IN6ADDR_ANY_INIT;
    fail_unless(hip_hit_is_bigger(&smaller, &bigger) == 0, NULL);
    fail_unless(hip_hit_is_bigger(&bigger, &bigger) == 0, NULL);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_first_null)
{
    hip_hit_t hit;
    hip_hit_is_bigger(NULL, &hit);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_second_null)
{
    hip_hit_t hit;
    hip_hit_is_bigger(&hit, NULL);
}
END_TEST

START_TEST(test_hip_hit_are_equal_equality)
{
    const hip_hit_t hit1 = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t hit2 = IN6ADDR_LOOPBACK_INIT;
    fail_unless(hip_hit_are_equal(&hit1, &hit2) == 1, NULL);
}
END_TEST

START_TEST(test_hip_hit_are_equal_inequality)
{
    const hip_hit_t bigger = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t smaller = IN6ADDR_ANY_INIT;
    fail_unless(hip_hit_are_equal(&bigger, &smaller) == 1, NULL);
}
END_TEST

START_TEST(test_hip_hit_are_equal_first_null)
{
    hip_hit_t hit;
    hip_hit_are_equal(NULL, &hit);
}
END_TEST

START_TEST(test_hip_hit_are_equal_second_null)
{
    hip_hit_t hit;
    hip_hit_are_equal(&hit, NULL);
}
END_TEST

START_TEST(test_hip_hash_hit_valid)
{
    const hip_hit_t hit = IN6ADDR_ANY_INIT;
    hip_hash_hit(&hit);
}
END_TEST

START_TEST(test_hip_hash_hit_null)
{
    hip_hash_hit(NULL);
}
END_TEST

// For unknown reasons, this file does not compile with the following,
// seemingly useless forward declaration
Suite *lib_core_hit(void);

Suite *lib_core_hit(void)
{
    Suite *s = suite_create("lib/core/hit");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_valid);
    tcase_add_exit_test(tc_core, test_hip_convert_hit_to_str_null_hit, 1);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_buf);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_prefix);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_bounds);
    tcase_add_test(tc_core, test_hip_hit_is_bigger_bigger);
    tcase_add_test(tc_core, test_hip_hit_is_bigger_equal_smaller);
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_first_null, 1);
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_second_null, 1);
    tcase_add_test(tc_core, test_hip_hit_are_equal_equality);
    tcase_add_test(tc_core, test_hip_hit_are_equal_inequality);
    tcase_add_exit_test(tc_core, test_hip_hit_are_equal_first_null, 1);
    tcase_add_exit_test(tc_core, test_hip_hit_are_equal_second_null, 1);
    tcase_add_test(tc_core, test_hip_hash_hit_valid);
    tcase_add_exit_test(tc_core, test_hip_hash_hit_null, 1);
    suite_add_tcase(s, tc_core);

    return s;
}
