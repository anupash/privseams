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

#include "lib/core/crypto.h"
#include "lib/core/hostid.h"
#include "config.h"
#include "test_suites.h"

START_TEST(test_serialize_deserialize_keys)
{
    unsigned int            i, keyrr_len = 0;
    int                     nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY                 *key     = NULL, *key_deserialized = NULL;
    EVP_PKEY               *key_a   = NULL, *key_b = NULL;
    unsigned char          *keyrr;
    struct hip_host_id_priv hostid;

    HIP_DEBUG("Trying to serialize and deserialize some ECDSA keys.\n");

    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        key_a = EVP_PKEY_new();
        key_b = EVP_PKEY_new();
        key   = create_ecdsa_key(nids[i]);
        fail_unless((keyrr_len = ecdsa_to_key_rr(key, &keyrr)) > 0, NULL);
        memcpy(&hostid.key, keyrr, keyrr_len);
        fail_unless((key_deserialized = hip_key_rr_to_ecdsa(&hostid, 1)) != NULL, NULL);
        EVP_PKEY_assign_EC_KEY(key_a, key);
        EVP_PKEY_assign_EC_KEY(key_b, key_deserialized);
        fail_unless(EVP_PKEY_cmp(key_a, key_b) == 1, NULL);
        EVP_PKEY_free(key_a);
        EVP_PKEY_free(key_b);
    }

    HIP_DEBUG("Successfully passed test for serialization and deserialization of ECDSA keys.\n");
}
END_TEST


Suite *lib_core_hostid(void)
{
    Suite *s = suite_create("lib/core/hostid");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_serialize_deserialize_keys);

    suite_add_tcase(s, tc_core);

    return s;
}
