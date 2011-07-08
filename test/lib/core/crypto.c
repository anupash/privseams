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
#include "config.h"
#include "test_suites.h"

START_TEST(test_create_ecdsa_key_invalid_id)
{
    HIP_DEBUG("Trying to create some invalid ECDSA keys.\n");

    fail_unless(create_ecdsa_key(-1)     == NULL, NULL);
    fail_unless(create_ecdsa_key(0)      == NULL, NULL);
    fail_unless(create_ecdsa_key(1)      == NULL, NULL);
    fail_unless(create_ecdsa_key(11111)  == NULL, NULL);

    HIP_DEBUG("Successfully passed create test for invalid ECDSA keys.\n");
}
END_TEST

START_TEST(test_create_ecdsa_key)
{
    unsigned int i;
    int          nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY      *keys[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Trying to create some valid ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        fail_unless((keys[i] = create_ecdsa_key(nids[i])) != NULL, NULL);
    }

    /* Creation worked, now check keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        fail_unless(EC_KEY_check_key(keys[i]), NULL);
        EC_KEY_free(keys[i]);
    }

    HIP_DEBUG("Successfully passed create test for valid ECDSA keys.\n");
}
END_TEST

START_TEST(test_create_different_ecdsa_keys)
{
    unsigned int i;
    int          nids[2] = { NID_X9_62_prime256v1, NID_X9_62_prime256v1 };
    EC_KEY      *ec_keys[sizeof(nids) / sizeof(int)];
    EVP_PKEY    *keys[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Checking uniqueness of ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        ec_keys[i] = create_ecdsa_key(nids[i]);
        keys[i]    = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(keys[i], ec_keys[i]);
    }

    /* Keys should be statistically unique
     * todo: take more samples */
    fail_unless(EVP_PKEY_cmp(keys[0], keys[1]) == 0, NULL);

    HIP_DEBUG("Successfully passed test for uniqueness of ECDSA keys.\n");
}
END_TEST

START_TEST(test_load_save_ecdsa_key)
{
    unsigned int i;
    int          nids[3] = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EVP_PKEY    *keys[sizeof(nids) / sizeof(int)];
    EVP_PKEY    *keys_loaded[sizeof(nids) / sizeof(int)];
    EC_KEY      *eckeys[sizeof(nids) / sizeof(int)];
    EC_KEY      *eckeys_loaded[sizeof(nids) / sizeof(int)];

    HIP_DEBUG("Trying to save and load some ECDSA keys.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        keys[i]        = EVP_PKEY_new();
        keys_loaded[i] = EVP_PKEY_new();
        eckeys[i]      = create_ecdsa_key(nids[i]);
        EVP_PKEY_assign_EC_KEY(keys[i], eckeys[i]);
    }

    /* Save and reload keys */
    save_ecdsa_private_key("tmp_key1", EVP_PKEY_get1_EC_KEY(keys[0]));
    save_ecdsa_private_key("tmp_key2", EVP_PKEY_get1_EC_KEY(keys[1]));
    save_ecdsa_private_key("tmp_key3", EVP_PKEY_get1_EC_KEY(keys[2]));
    load_ecdsa_private_key("tmp_key1", &eckeys_loaded[0]);
    load_ecdsa_private_key("tmp_key2", &eckeys_loaded[1]);
    load_ecdsa_private_key("tmp_key3", &eckeys_loaded[2]);

    /* Now compare keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        EVP_PKEY_assign_EC_KEY(keys_loaded[i], eckeys_loaded[i]);
        fail_unless(EVP_PKEY_cmp(keys[i], keys_loaded[i]) == 1, NULL);
        // Note: EC_KEYS will be freed when the parent EVP_PKEY is freed.
        EVP_PKEY_free(keys[i]);
        EVP_PKEY_free(keys_loaded[i]);
    }

    HIP_DEBUG("Successfully passed load/save test for ECDSA keys.\n");
}
END_TEST

Suite *lib_core_crypto(void)
{
    Suite *s = suite_create("lib/core/crypto");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_create_ecdsa_key_invalid_id);
    tcase_add_test(tc_core, test_create_ecdsa_key);
    tcase_add_test(tc_core, test_create_different_ecdsa_keys);
    tcase_add_test(tc_core, test_load_save_ecdsa_key);
    suite_add_tcase(s, tc_core);

    return s;
}
