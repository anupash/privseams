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

START_TEST(test_convert_string_to_address_v4_valid)
{
    const char *str = "127.0.0.1";
    struct in_addr ip;

    fail_unless(convert_string_to_address_v4(str, &ip) == 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_v4_null_str)
{
    struct in_addr ip;

    fail_unless(convert_string_to_address_v4(NULL, &ip) < 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_v4_null_addr)
{
    const char *str = "127.0.0.1";

    fail_unless(convert_string_to_address_v4(str, NULL) < 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_v4_invalid)
{
    const char *str = " 127.0.0.1";
    struct in_addr ip;

    fail_unless(convert_string_to_address_v4(str, &ip) < 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_valid)
{
    const char *str = "fe80::215:58ff:fe29:9c36";
    struct in6_addr ip;

    fail_unless(convert_string_to_address(str, &ip) == 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_null_str)
{
    struct in6_addr ip;

    fail_unless(convert_string_to_address(NULL, &ip) < 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_null_addr)
{
    const char *str = "fe80::215:58ff:fe29:9c36";

    fail_unless(convert_string_to_address(str, NULL) < 0, NULL);
}
END_TEST

START_TEST(test_convert_string_to_address_invalid)
{
    const char *str = " fe80::215:58ff:fe29:9c36";
    struct in6_addr ip;

    fail_unless(convert_string_to_address(str, &ip) < 0, NULL);
}
END_TEST

START_TEST(test_hip_string_to_lowercase_valid)
{
    char to[128] = { 1 };
    char ones[128] = { 1 };
    const char from[] = "TesT";
    const size_t count = sizeof(from) - 1;
    const unsigned int offset = 32;

    fail_unless(hip_string_to_lowercase(to + offset, from, count) == 0, NULL);
    // was from correctly converted to lower case?
    fail_unless(memcmp(to + offset, "test", count) == 0, NULL);
    // is the beginning of to still intact?
    fail_unless(memcmp(to, ones, offset) == 0, NULL);
    // is the rest of to still intact?
    fail_unless(memcmp(to + offset + count, ones, offset) == 0, NULL);
}
END_TEST

START_TEST(test_hip_string_is_digit_valid)
{
    fail_unless(hip_string_is_digit("123456789") == 0, NULL);
    fail_unless(hip_string_is_digit("abc") < 0, NULL);
}
END_TEST

START_TEST(test_hip_string_is_digit_null)
{
    fail_unless(hip_string_is_digit(NULL) < 0, NULL);
}
END_TEST

START_TEST(test_hip_string_is_digit_empty)
{
    fail_unless(hip_string_is_digit("") < 0, NULL);
}
END_TEST

START_TEST(test_base64_encode_valid)
{
    const char b64[] = "VGVzdA==";
    unsigned char buf[] = "Test";
    unsigned int len = sizeof(buf) - 1; // do not include null character as per doc
    unsigned char *result = NULL;

    fail_unless((result = base64_encode(buf, len)) != NULL, NULL);
    fail_unless(strcmp((char*)result, b64) == 0, NULL);
    free(result); // note it's not documented that we need to free the returned memory
}
END_TEST

START_TEST(test_base64_encode_null_buf)
{
    fail_unless(base64_encode(NULL, 42) == NULL, NULL);
}
END_TEST

START_TEST(test_base64_encode_empty_buf)
{
    unsigned char buf[] = "";
    unsigned char *result = NULL;

    fail_unless((result = base64_encode(buf, 0)) != NULL, NULL);
    fail_unless(strlen((char *)result) == 0, NULL);
}
END_TEST

Suite *lib_core_straddr(void);

Suite *lib_core_straddr(void)
{
    Suite *s = suite_create("lib/core/straddr");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_convert_string_to_address_v4_valid);
    tcase_add_test(tc_core, test_convert_string_to_address_v4_null_str);
    tcase_add_test(tc_core, test_convert_string_to_address_v4_null_addr);
    tcase_add_test(tc_core, test_convert_string_to_address_v4_invalid);
    tcase_add_test(tc_core, test_convert_string_to_address_valid);
    tcase_add_test(tc_core, test_convert_string_to_address_null_str);
    tcase_add_test(tc_core, test_convert_string_to_address_null_addr);
    tcase_add_test(tc_core, test_convert_string_to_address_invalid);
    tcase_add_test(tc_core, test_hip_string_to_lowercase_valid);
    tcase_add_test(tc_core, test_hip_string_is_digit_valid);
    tcase_add_test(tc_core, test_hip_string_is_digit_null);
    tcase_add_test(tc_core, test_hip_string_is_digit_empty);
    tcase_add_test(tc_core, test_base64_encode_valid);
    tcase_add_test(tc_core, test_base64_encode_null_buf);
    tcase_add_test(tc_core, test_base64_encode_empty_buf);
    suite_add_tcase(s, tc_core);

    return s;
}
