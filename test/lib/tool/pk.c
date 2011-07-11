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

/**
 * @file
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include "lib/core/debug.h"
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"
#include "config.h"
#include "test_suites.h"

START_TEST(test_ecdsa_sign_verify)
{
    unsigned int       i;
    int                nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY            *eckey;
    struct hip_common *msg;

    HIP_DEBUG("Trying sign and verify operations.\n");

    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        eckey = create_ecdsa_key(nids[i]);
        msg   = hip_msg_alloc();
        hip_build_network_hdr(msg, HIP_UPDATE, 0, &in6addr_any, &in6addr_loopback);
        hip_build_param_echo(msg, "AAAAA", 5, 1, 1);

        fail_unless(hip_ecdsa_sign(eckey, msg) == 0, NULL);
        fail_unless(hip_ecdsa_verify(eckey, msg) == 0, NULL);

        EC_KEY_free(eckey);
        free(msg);
    }

    HIP_DEBUG("Successfully passed test for sign and verify operations.\n");
}
END_TEST

START_TEST(test_ecdsa_invalid_sign_verify)
{
    unsigned int             i;
    int                      nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY                  *eckeys[3];
    struct hip_common       *msg;
    struct hip_echo_request *echo_req = NULL;
    struct hip_sig          *sig      = NULL;

    HIP_DEBUG("Trying some invalid sign and verify operations.\n");

    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        eckeys[i] = create_ecdsa_key(nids[i]);
    }

    msg = hip_msg_alloc();
    hip_build_network_hdr(msg, HIP_UPDATE, 0, &in6addr_any, &in6addr_loopback);
    hip_build_param_echo(msg, "AAAAA", 5, 1, 1);
    fail_unless(hip_ecdsa_sign(eckeys[0], msg) == 0, NULL);

    /* verification using wrong keys */
    fail_unless(hip_ecdsa_verify(eckeys[1], msg) != 0, NULL);
    fail_unless(hip_ecdsa_verify(eckeys[2], msg) != 0, NULL);

    /* modified message header */
    msg->type_hdr = HIP_NOTIFY;
    fail_unless(hip_ecdsa_verify(eckeys[0], msg) != 0, NULL);
    msg->type_hdr = HIP_UPDATE;

    /* modified parameter */
    echo_req                   = hip_get_param_readwrite(msg, HIP_PARAM_ECHO_REQUEST_SIGN);
    *((char *) (echo_req + 1)) = 'B';
    fail_unless(hip_ecdsa_verify(eckeys[0], msg) != 0, NULL);
    *((char *) (echo_req + 1)) = 'A';

    /* modified signature */
    sig                = hip_get_param_readwrite(msg, HIP_PARAM_HIP_SIGNATURE);
    sig->signature[0] += 1;
    fail_unless(hip_ecdsa_verify(eckeys[0], msg) != 0, NULL);
    sig->signature[0] -= 1;

    /* invalid inputs for signature generation */
    fail_unless(hip_ecdsa_sign(NULL, msg) != 0, NULL);
    fail_unless(hip_ecdsa_sign(eckeys[0], NULL) != 0, NULL);
    fail_unless(hip_ecdsa_sign(NULL, NULL) != 0, NULL);

    /* invalid inputs for signature verification */
    fail_unless(hip_ecdsa_verify(NULL, msg) != 0, NULL);
    fail_unless(hip_ecdsa_verify(eckeys[0], NULL) != 0, NULL);
    fail_unless(hip_ecdsa_verify(NULL, NULL) != 0, NULL);

    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        EC_KEY_free(eckeys[i]);
    }
    free(msg);

    HIP_DEBUG("Successfully passed test for invalid sign and verify operations.\n");
}
END_TEST

Suite *lib_tool_pk(void)
{
    Suite *s = suite_create("lib/tool/pk");

    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ecdsa_sign_verify);
    tcase_add_test(tc_core, test_ecdsa_invalid_sign_verify);


    suite_add_tcase(s, tc_core);

    return s;
}
