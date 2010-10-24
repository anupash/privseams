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
#include <stdlib.h> // free()
#include "lib/core/straddr.h"

START_TEST(test_hip_in6_ntop_valid)
{
    const int GUARD_SIZE = 32;      // arbitrary
    struct buf_test {
        char before[GUARD_SIZE];
        char addr[39];              // 16 IPv6 bytes -> 32 hex chars + 7 ':'s
        char null[1];               // terminating null character
        char after[GUARD_SIZE];
    } buf;
    char ones[GUARD_SIZE];
    struct in6_addr in6;

    memset(&buf, '1', sizeof(buf));
    memset(ones, '1', sizeof(ones));
    memset(&in6.s6_addr, 0x22, sizeof(in6.s6_addr));

    fail_unless(hip_in6_ntop(&in6, buf.addr) == buf.addr, NULL);
    // is the buffer before the address untouched?
    fail_unless(memcmp(buf.before, ones, GUARD_SIZE) == 0, NULL);
    // is the first part of the address correct?
    fail_unless(buf.addr[0] == '2', NULL);
    // is the last part of the address correct?
    fail_unless(buf.addr[sizeof(buf.addr) - 1] == '2', NULL);
    // is there a terminating null character?
    fail_unless(buf.null[0] == '\0', NULL);
    // is the buffer after the address untouched?
    fail_unless(memcmp(buf.after, ones, GUARD_SIZE) == 0, NULL);
}
END_TEST

START_TEST(test_hip_in6_ntop_null_addr)
{
    char buf[64];

    fail_unless(hip_in6_ntop(NULL, buf) == NULL, NULL);
}
END_TEST

START_TEST(test_hip_in6_ntop_null_buf)
{
    struct in6_addr in6 = IN6ADDR_LOOPBACK_INIT;

    fail_unless(hip_in6_ntop(&in6, NULL) == NULL, NULL);
}
END_TEST

START_TEST(test_hip_convert_string_to_address_valid)
{
    const char *str = "fe80::215:58ff:fe29:9c36";
    struct in6_addr ip;

    fail_unless(hip_convert_string_to_address(str, &ip) == 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_string_to_address_null_str)
{
    struct in6_addr ip;

    fail_unless(hip_convert_string_to_address(NULL, &ip) < 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_string_to_address_null_addr)
{
    const char *str = "fe80::215:58ff:fe29:9c36";

    fail_unless(hip_convert_string_to_address(str, NULL) < 0, NULL);
}
END_TEST

START_TEST(test_hip_convert_string_to_address_invalid)
{
    const char *str = " fe80::215:58ff:fe29:9c36";
    struct in6_addr ip;

    fail_unless(hip_convert_string_to_address(str, &ip) < 0, NULL);
}
END_TEST

// For unknown reasons, this file does not compile with the following,
// seemingly useless forward declaration
Suite *lib_core_straddr(void);

Suite *lib_core_straddr(void)
{
    Suite *s = suite_create("lib/core/straddr");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_in6_ntop_valid);
    tcase_add_test(tc_core, test_hip_in6_ntop_null_addr);
    tcase_add_test(tc_core, test_hip_in6_ntop_null_buf);
    tcase_add_test(tc_core, test_hip_convert_string_to_address_valid);
    tcase_add_test(tc_core, test_hip_convert_string_to_address_null_str);
    tcase_add_test(tc_core, test_hip_convert_string_to_address_null_addr);
    tcase_add_test(tc_core, test_hip_convert_string_to_address_invalid);
    suite_add_tcase(s, tc_core);

    return s;
}
