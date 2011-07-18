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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

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

START_TEST(test_save_invalid_ecdsa_key)
{
    EC_KEY *eckey = NULL;
    HIP_DEBUG("Trying some invalid save operations.\n");

    fail_unless(save_ecdsa_private_key("/tmp/tmp_file", NULL) != 0, NULL);

    eckey = create_ecdsa_key(NID_X9_62_prime256v1);
    fail_unless(save_ecdsa_private_key(NULL, eckey) != 0, NULL);
    EC_KEY_free(eckey);

    eckey = EC_KEY_new();
    fail_unless(save_ecdsa_private_key("/tmp/tmp_file", eckey) != 0, NULL);
    EC_KEY_free(eckey);

    fail_unless(save_ecdsa_private_key(NULL, NULL) != 0, NULL);

    HIP_DEBUG("Successfully passed test for invalid save operations.\n");
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
    save_ecdsa_private_key("/tmp/tmp_key1", EVP_PKEY_get1_EC_KEY(keys[0]));
    save_ecdsa_private_key("/tmp/tmp_key2", EVP_PKEY_get1_EC_KEY(keys[1]));
    save_ecdsa_private_key("/tmp/tmp_key3", EVP_PKEY_get1_EC_KEY(keys[2]));
    load_ecdsa_private_key("/tmp/tmp_key1", &eckeys_loaded[0]);
    load_ecdsa_private_key("/tmp/tmp_key2", &eckeys_loaded[1]);
    load_ecdsa_private_key("/tmp/tmp_key3", &eckeys_loaded[2]);

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

START_TEST(test_load_invalid_ecdsa_key)
{
    EC_KEY *eckey = NULL;
    int     err;

    HIP_DEBUG("Trying some invalid load operations.\n");

    err = load_ecdsa_private_key("non_existing", &eckey);
    fail_unless(err != 0 && eckey == NULL, NULL);

    err = load_ecdsa_private_key(NULL, &eckey);
    fail_unless(err != 0 && eckey == NULL, NULL);

    err = load_ecdsa_private_key("/tmp/tmp_key1", NULL);
    fail_unless(err != 0, NULL);

    err = load_ecdsa_private_key(NULL, NULL);
    fail_unless(err != 0, NULL);

    HIP_DEBUG("Successfully passed test for invalid load operations.\n");
}
END_TEST

START_TEST(test_impl_ecdsa_sign_verify)
{
    unsigned int         i;
    const unsigned char *digest    = (const unsigned char *) "ABCD1ABCD2ABCD3ABCD4ABCD5";
    unsigned char       *signature = NULL;
    int                  nids[3]   = { NID_secp160r1, NID_X9_62_prime256v1, NID_secp384r1 };
    EC_KEY              *key       = NULL;

    HIP_DEBUG("Trying to some lowlevel sign, verify operations.\n");

    /* Create keys */
    for (i = 0; i < sizeof(nids) / sizeof(int); i++) {
        key       = create_ecdsa_key(nids[i]);
        signature = malloc(ECDSA_size(key));
        fail_unless(impl_ecdsa_sign(digest, key, signature) == 0, NULL);
        fail_unless(impl_ecdsa_verify(digest, key, signature) == 0, NULL);
        free(signature);
        EC_KEY_free(key);
    }

    HIP_DEBUG("Successfully passed test on lowlevel sign, verify operations.\n");
}
END_TEST

START_TEST(test_invalid_impl_ecdsa_sign_verify)
{
    const unsigned char *digest     = (const unsigned char *) "ABCD1ABCD2ABCD3ABCD4ABCD5";
    const unsigned char *mod_digest = (const unsigned char *) "BBCD1ABCD2ABCD3ABCD4ABCD5";
    unsigned char       *signature  = NULL;
    EC_KEY              *key        = NULL;

    HIP_DEBUG("Trying to some lowlevel sign, verify operations with invalid inputs.\n");

    key       = create_ecdsa_key(NID_secp160r1);
    signature = malloc(ECDSA_size(key));

    /* NULL inputs to sign */
    fail_unless(impl_ecdsa_sign(NULL, key, signature) != 0, NULL);
    fail_unless(impl_ecdsa_sign(digest, NULL, signature) != 0, NULL);
    fail_unless(impl_ecdsa_sign(digest, key, NULL) != 0, NULL);

    /* NULL inputs to verify */
    impl_ecdsa_sign(digest, key, signature);
    fail_unless(impl_ecdsa_verify(NULL, key, signature) != 0, NULL);
    fail_unless(impl_ecdsa_verify(digest, NULL, signature) != 0, NULL);
    fail_unless(impl_ecdsa_verify(digest, key, NULL) != 0, NULL);

    /* Modified signature, digest */
    fail_unless(impl_ecdsa_verify(mod_digest, key, signature) != 0, NULL);
    signature[0] += 1;
    fail_unless(impl_ecdsa_verify(digest, key, signature) != 0, NULL);

    free(signature);
    EC_KEY_free(key);

    HIP_DEBUG("Successfully passed test on lowlevel sign, verify operations with invalid inputs.\n");
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
    tcase_add_test(tc_core, test_save_invalid_ecdsa_key);
    tcase_add_test(tc_core, test_load_invalid_ecdsa_key);
    tcase_add_test(tc_core, test_impl_ecdsa_sign_verify);
    tcase_add_test(tc_core, test_invalid_impl_ecdsa_sign_verify);

    suite_add_tcase(s, tc_core);

    return s;
}
