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

#include "modules/midauth/hipd/midauth.c"
#include "modules/midauth/lib/midauth_builder.h"
#include "../test_suites.h"

#define MIDAUTH_DEFAULT_NONCE_LENGTH 18

/* Test where the HIP packet does not contain any CHALLANGE_REQUESTs */
START_TEST(test_midauth_handle_challenge_request_param_0_CORRECT)
{
    struct hip_packet_context ctx = { 0 };
    const struct hip_challenge_response *response = NULL;

    ctx.input_msg = hip_msg_alloc();
    ctx.output_msg = hip_msg_alloc();

    fail_unless(handle_challenge_request_param(0, 0, &ctx) == 0, NULL);

    /* NOTE we can only check for the existance of the response parameter here
     *      as the puzzle solution differs for each run. */
    fail_unless((response = hip_get_param(ctx.output_msg,
                                          HIP_PARAM_CHALLENGE_RESPONSE)) == NULL,
                NULL);
}
END_TEST

START_TEST(test_midauth_handle_challenge_request_param_1_CORRECT)
{
    const uint8_t opaque1[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                              "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    struct hip_packet_context ctx = { 0 };
    const struct hip_challenge_response *response = NULL;

    ctx.input_msg = hip_msg_alloc();
    ctx.output_msg = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_request(ctx.input_msg, 0, 0, opaque1,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                0, NULL);
    fail_unless(handle_challenge_request_param(0, 0, &ctx) == 0, NULL);

    /* NOTE we can only check for the existance of the response parameter here
     *      as the puzzle solution differs for each run. */
    fail_unless((response = hip_get_param(ctx.output_msg,
                                          HIP_PARAM_CHALLENGE_RESPONSE)) != NULL,
                NULL);
}
END_TEST

START_TEST(test_midauth_handle_challenge_request_param_2_CORRECT)
{
    const uint8_t opaque1[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                              "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    const uint8_t opaque2[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                              "\x02\x42\x02\x15\x06\x08\x49\x50\x0d";
    struct hip_packet_context ctx = { 0 };
    const struct hip_challenge_response *response = NULL;

    ctx.input_msg = hip_msg_alloc();
    ctx.output_msg = hip_msg_alloc();

    fail_unless(hip_build_param_challenge_request(ctx.input_msg, 0, 0, opaque1,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                0, NULL);
    fail_unless(hip_build_param_challenge_request(ctx.input_msg, 0, 0, opaque2,
                                                  MIDAUTH_DEFAULT_NONCE_LENGTH) ==
                0, NULL);
    fail_unless(handle_challenge_request_param(0, 0, &ctx) == 0, NULL);

    /* NOTE we can only check for the existance of the response parameter here
     *      as the puzzle solution differs for each run. */
    fail_unless((response = hip_get_param(ctx.output_msg,
                                          HIP_PARAM_CHALLENGE_RESPONSE)) != NULL,
                NULL);
    fail_unless(hip_get_next_param(ctx.output_msg,
                                   (const struct hip_tlv_common *) response) !=
                NULL, NULL);
}
END_TEST

Suite *modules_midauth_hipd_midauth(void)
{
    Suite *s = suite_create("modules/midauth/hipd/midauth");
    TCase *tc_midauth = tcase_create("Midauth");

    tcase_add_test(tc_midauth, test_midauth_handle_challenge_request_param_0_CORRECT);
    tcase_add_test(tc_midauth, test_midauth_handle_challenge_request_param_1_CORRECT);
    tcase_add_test(tc_midauth, test_midauth_handle_challenge_request_param_2_CORRECT);

    suite_add_tcase(s, tc_midauth);

    return s;
}
