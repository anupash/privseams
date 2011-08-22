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

#include <check.h>
#include <stdint.h>
#include <string.h>

#include "lib/core/protodefs.h"
#include "modules/midauth/hipd/midauth.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "../test_suites.h"

#define MIDAUTH_DEFAULT_NONCE_LENGTH 18

START_TEST(test_midauth_builder_build_param_challenge_request_NULL_msg)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";

    fail_unless(hip_build_param_challenge_request(NULL, 0, 0, opaque,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                -1, NULL);
}
END_TEST

#ifdef HAVE_TCASE_ADD_EXIT_TEST
START_TEST(test_midauth_builder_build_param_challenge_request_NULL_opaque)
{
    struct hip_common *const msg = hip_msg_alloc();

    hip_build_param_challenge_request(msg, 0, 0, NULL,
                                      MIDAUTH_DEFAULT_NONCE_LENGTH);
}
END_TEST
#endif /* HAVE_TCASE_ADD_EXIT_TEST */

START_TEST(test_midauth_builder_build_param_challenge_request_0_opaque_len)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    struct hip_common *const msg = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_request(msg, 0, 0, opaque,
                                                  0) == 0, NULL);
}
END_TEST

START_TEST(test_midauth_builder_build_param_challenge_request_CORRECT)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    const char cmp_challenge_request[] = "\xff\x36\x00\x14\x00\x00\x01\x41\x01"
                                         "\x14\x05\x00\x48\x49\x0b\x02\x42\x02"
                                         "\x15\x06\x08\x49\x50\x0C";
    const struct hip_challenge_request *request = NULL;
    struct hip_common *const            msg     = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_request(msg, 0, 0, opaque,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                0, NULL);
    fail_unless((request = hip_get_param(msg, HIP_PARAM_CHALLENGE_REQUEST)) != NULL,
                NULL);
    fail_unless(memcmp(request, &cmp_challenge_request,
                       hip_get_param_total_len(request)) == 0, NULL);
}
END_TEST

START_TEST(test_midauth_builder_build_param_challenge_response_NULL_msg)
{
    const char challenge_request[] = "\xff\x36\x00\x14\x00\x00\x01\x41\x01"
                                     "\x14\x05\x00\x48\x49\x0b\x02\x42\x02"
                                     "\x15\x06\x08\x49\x50\x0C";
    const uint8_t                       solution[] = "\x01\x41\x01\x14\x05\x00\x48\x49";
    const struct hip_challenge_request *request    =
        (const struct hip_challenge_request *) challenge_request;

    fail_unless(hip_build_param_challenge_response(NULL, request, solution) == -1,
                NULL);
}
END_TEST

START_TEST(test_midauth_builder_build_param_challenge_response_NULL_request)
{
    const uint8_t                       solution[] = "\x01\x41\x01\x14\x05\x00\x48\x49";
    const struct hip_challenge_request *request    = NULL;
    struct hip_common *const            msg        = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_response(msg, request, solution) == -1,
                NULL);
}
END_TEST

START_TEST(test_midauth_builder_build_param_challenge_response_NULL_solution)
{
    const char challenge_request[] = "\xff\x36\x00\x14\x00\x00\x01\x41\x01"
                                     "\x14\x05\x00\x48\x49\x0b\x02\x42\x02"
                                     "\x15\x06\x08\x49\x50\x0C";
    const struct hip_challenge_request *request =
        (const struct hip_challenge_request *) challenge_request;
    struct hip_common *const msg = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_response(msg, request, NULL) == -1,
                NULL);
}
END_TEST

START_TEST(test_midauth_builder_build_param_challenge_response_CORRECT)
{
    const char challenge_request[] = "\xff\x36\x00\x14\x00\x00\x01\x41\x01"
                                     "\x14\x05\x00\x48\x49\x0b\x02\x42\x02"
                                     "\x15\x06\x08\x49\x50\x0C";
    const char cmp_challenge_response[] = "\x01\x42\x00\x1C\x00\x00\x01\x41\x01"
                                          "\x14\x05\x00\x48\x49\x01\x41\x01\x14"
                                          "\x05\x00\x48\x49\x0b\x02\x42\x02\x15"
                                          "\x06\x08\x49\x50\x0c";
    const uint8_t                       solution[] = "\x01\x41\x01\x14\x05\x00\x48\x49";
    const struct hip_challenge_request *request    =
        (const struct hip_challenge_request *) challenge_request;
    const struct hip_challenge_response *response = NULL;
    struct hip_common *const             msg      = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_response(msg, request, solution) == 0,
                NULL);
    fail_unless((response = hip_get_param(msg, HIP_PARAM_CHALLENGE_RESPONSE)) != NULL,
                NULL);
    fail_unless(memcmp(response, &cmp_challenge_response,
                       hip_get_param_total_len(response)) == 0, NULL);
}
END_TEST

START_TEST(test_midauth_builder_challenge_request_opaque_len_NULL)
{
    fail_unless(hip_challenge_request_opaque_len(NULL) == 0, NULL);
}
END_TEST

START_TEST(test_midauth_builder_challenge_request_opaque_len_CORRECT)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    const struct hip_challenge_request *request = NULL;
    struct hip_common *const            msg     = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_request(msg, 0, 0, opaque,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                0, NULL);
    fail_unless((request = hip_get_param(msg, HIP_PARAM_CHALLENGE_REQUEST)) != NULL,
                NULL);
    fail_unless(hip_challenge_request_opaque_len(request) ==
                MIDAUTH_DEFAULT_NONCE_LENGTH, NULL);
}
END_TEST

#ifdef HAVE_TCASE_ADD_EXIT_TEST
START_TEST(test_midauth_builder_puzzle_seed_NULL_opaque)
{
    const uint8_t *const opaque = NULL;
    uint8_t              puzzle_value[PUZZLE_LENGTH];

    hip_midauth_puzzle_seed(opaque, MIDAUTH_DEFAULT_NONCE_LENGTH, puzzle_value);
}
END_TEST

START_TEST(test_midauth_builder_puzzle_seed_NULL_puzzle_value)
{
    const uint8_t opaque[] = "\x01\x41\x00\x14\x05\x00\x48\x49\x0b";

    hip_midauth_puzzle_seed(opaque,
                            MIDAUTH_DEFAULT_NONCE_LENGTH,
                            NULL);
}
END_TEST
#endif /* HAVE_TCASE_ADD_EXIT_TEST */

START_TEST(test_midauth_builder_puzzle_seed_0_opaque_len)
{
    const uint8_t opaque[] = "\x01\x41\x00\x14\x05\x00\x48\x49\x0b";
    uint8_t       puzzle_value[PUZZLE_LENGTH];

    fail_unless(hip_midauth_puzzle_seed(opaque,
                                        0,
                                        puzzle_value) == -1, NULL);
}
END_TEST

START_TEST(test_midauth_builder_puzzle_seed_CORRECT)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    uint8_t puzzle_value[PUZZLE_LENGTH];
    uint8_t correct_puzzle_value[] = "\x43\x03\x8F\xD7\x2F\xC7\xD2\xF3";

    fail_unless(hip_midauth_puzzle_seed(opaque,
                                        MIDAUTH_DEFAULT_NONCE_LENGTH,
                                        puzzle_value) == 0, NULL);
    fail_unless(memcmp(correct_puzzle_value, puzzle_value, PUZZLE_LENGTH) == 0,
                NULL);
}
END_TEST

Suite *modules_midauth_lib_builder(void)
{
    Suite *s                  = suite_create("modules/midauth/lib/midauth_builder");
    TCase *tc_midauth_builder = tcase_create("Midauth_builder");

    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_request_NULL_msg);
// the tcase_add_exit_test macro is only available in check 0.9.8 or later but
// scratchbox uses an older version of checkc so we try to avoid this macro
#ifdef HAVE_TCASE_ADD_EXIT_TEST
    tcase_add_exit_test(tc_midauth_builder,
                        test_midauth_builder_build_param_challenge_request_NULL_opaque,
                        1);
#endif
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_request_0_opaque_len);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_request_CORRECT);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_response_NULL_msg);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_response_NULL_request);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_response_NULL_solution);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_build_param_challenge_response_CORRECT);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_challenge_request_opaque_len_NULL);
    tcase_add_test(tc_midauth_builder,
                   test_midauth_builder_challenge_request_opaque_len_CORRECT);

#ifdef HAVE_TCASE_ADD_EXIT_TEST
    tcase_add_exit_test(tc_midauth_builder,
                        test_midauth_builder_puzzle_seed_NULL_opaque, 1);
    tcase_add_exit_test(tc_midauth_builder,
                        test_midauth_builder_puzzle_seed_NULL_puzzle_value, 1);
#endif
    tcase_add_test(tc_midauth_builder, test_midauth_builder_puzzle_seed_0_opaque_len);
    tcase_add_test(tc_midauth_builder, test_midauth_builder_puzzle_seed_CORRECT);

    suite_add_tcase(s, tc_midauth_builder);

    return s;
}
