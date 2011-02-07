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
    char      buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", buf) == 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_hit)
{
    char buf[64];
    fail_unless(hip_convert_hit_to_str(NULL, "", buf) < 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_buf)
{
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, "", NULL) < 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_null_suffix)
{
    char      buf[64];
    hip_hit_t hit;
    fail_unless(hip_convert_hit_to_str(&hit, NULL, buf) == 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_hit_to_str_bounds)
{
    const char         suffix[]   = "SFX";
    const unsigned int BEFORE_LEN = 30;
    const unsigned int HIT_LEN    = 39; // 16 bytes -> 32 hex chars + 7 ':'s
    const unsigned int SUFFIX_LEN = sizeof(suffix); // includes null char
    const unsigned int AFTER_LEN  = 30;
    struct {
        char before[BEFORE_LEN];
        char hit[HIT_LEN];
        char suffix[SUFFIX_LEN];
        char after[AFTER_LEN];
    } buf;
    char      ones[sizeof(buf)];
    hip_hit_t hit;

    memset(&buf, 1, sizeof(buf));
    memset(ones, 1, sizeof(ones));
    memset(&hit.s6_addr, 0x22, sizeof(hit.s6_addr));

    // write the HIT string into the middle of the buffer
    fail_unless(hip_convert_hit_to_str(&hit, suffix, buf.hit) == 0, NULL);
    // is the buffer before the HIT untouched?
    fail_unless(memcmp(&buf.before, ones, BEFORE_LEN) == 0, NULL);
    // is the first part of the HIT correct?
    fail_unless(buf.hit[0] == '2', NULL);
    // is the last part of the HIT correct?
    fail_unless(buf.hit[HIT_LEN - 1] == '2', NULL);
    // is the suffix correct including the terminating null character?
    fail_unless(memcmp(&buf.suffix, suffix, SUFFIX_LEN) == 0, NULL);
    // is the buffer after the suffix untouched?
    fail_unless(memcmp(&buf.after, ones, AFTER_LEN) == 0, NULL);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_bigger)
{
    const hip_hit_t bigger  = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t smaller = IN6ADDR_ANY_INIT;
    fail_unless(hip_hit_is_bigger(&bigger, &smaller) == 1, NULL);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_equal_smaller)
{
    const hip_hit_t bigger  = IN6ADDR_LOOPBACK_INIT;
    const hip_hit_t smaller = IN6ADDR_ANY_INIT;
    fail_unless(hip_hit_is_bigger(&smaller, &bigger) == 0, NULL);
    fail_unless(hip_hit_is_bigger(&bigger, &bigger) == 0, NULL);
}
END_TEST

// the tcase_add_exit_test macro is only available in check 0.9.8 or later but
// scratchbox uses an older version of checkc so we try to avoid this macro
#if CHECK_MAJOR_VERSION > 0 || \
    (CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION > 9) || \
    (CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION >= 8)
START_TEST(test_hip_hit_is_bigger_null_first)
{
    const hip_hit_t hit = IN6ADDR_LOOPBACK_INIT;
    hip_hit_is_bigger(NULL, &hit);
}
END_TEST

START_TEST(test_hip_hit_is_bigger_null_second)
{
    const hip_hit_t hit = IN6ADDR_LOOPBACK_INIT;
    hip_hit_is_bigger(&hit, NULL);
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
#endif

// For unknown reasons, this file does not compile with the following,
// seemingly useless forward declaration
Suite *lib_core_hit(void);

Suite *lib_core_hit(void)
{
    Suite *s = suite_create("lib/core/hit");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_valid);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_hit);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_buf);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_null_suffix);
    tcase_add_test(tc_core, test_hip_convert_hit_to_str_bounds);
    tcase_add_test(tc_core, test_hip_hit_is_bigger_bigger);
    tcase_add_test(tc_core, test_hip_hit_is_bigger_equal_smaller);
    // the tcase_add_exit_test macro is only available in check 0.9.8 or later but
    // scratchbox uses an older version of checkc so we try to avoid this macro
#if CHECK_MAJOR_VERSION > 0 || \
    (CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION > 9) || \
    (CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION >= 8)
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_null_first, 1);
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_null_second, 1);
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_first_null, 1);
    tcase_add_exit_test(tc_core, test_hip_hit_is_bigger_second_null, 1);
#endif
    suite_add_tcase(s, tc_core);

    return s;
}
