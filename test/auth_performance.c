/**
 * @file
 *
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
 *
 * This file contains a benchmark for the cryptographic authentication functions.
 *
 * @brief Authentication function benchmark
 *
 * @author Tobias Heer
 */

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/aes.h>
#include <openssl/dsa.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef HAVE_EC_CRYPTO
#include <openssl/ecdsa.h>
#endif

#include "lib/core/crypto.h"
#include "lib/core/keylen.h"
#include "lib/core/debug.h"
#include "lib/core/protodefs.h"
#include "lib/core/statistics.h"

#define PACKET_LENGTH 1280

int num_measurements = 100;
int key_pool_size    = 5;
int rsa_key_len      = 1024;
int dsa_key_len      = 1024;
#define ECDSA_CURVE NID_sect163r1

/*!
 * \brief Determine and print the gettimeofday time resolution.
 *
 * \author Tobias Heer
 *
 * Determine the time resolution of gettimeofday.
 *
 * \return void
 */
static void print_timeres(void)
{
    struct timeval tv1, tv2;
    int i;
    printf( "-------------------------------\n"
            "Determine gettimeofday resolution:\n");


    for (i = 0; i < 10; i++) {
        gettimeofday(&tv1, NULL);
        do {
            gettimeofday(&tv2, NULL);
        } while (tv1.tv_usec == tv2.tv_usec);

        printf("Resolution: %ld us\n", tv2.tv_usec - tv1.tv_usec +
               1000000 * (tv2.tv_sec - tv1.tv_sec));
    }

    printf( "-------------------------------\n\n");
}

int main(void)
{
    int i;
    int err              = 0;
    struct timeval start_time;
    struct timeval stop_time;
    uint64_t timediff    = 0;

    unsigned int sig_len = 0;
    unsigned char data[PACKET_LENGTH * num_measurements];
    unsigned char hashed_data[SHA_DIGEST_LENGTH * num_measurements];
    unsigned char key[HIP_MAX_KEY_LEN];
    unsigned int hashed_data_len = 0;

    AES_KEY *aes_enc_key         = NULL;
    AES_KEY *aes_dec_key         = NULL;
    unsigned char cbc_iv[AES_BLOCK_SIZE];
    unsigned char enc_data[num_measurements * PACKET_LENGTH];
    unsigned char dec_data[num_measurements * PACKET_LENGTH];

    RSA *rsa_key_pool[key_pool_size];
    unsigned char *rsa_sig_pool[num_measurements];

    DSA *dsa_key_pool[key_pool_size];
    DSA_SIG *dsa_sig_pool[num_measurements];

#ifdef HAVE_EC_CRYPTO
    EC_KEY *ecdsa_key_pool[key_pool_size];
    ECDSA_SIG *ecdsa_sig_pool[num_measurements];
#endif

    hip_set_logdebug(LOGDEBUG_NONE);

    print_timeres();

    // data to be signed
    printf("generating payload data for %i packets (packet length %i bytes)...\n\n",
           num_measurements, PACKET_LENGTH);
    RAND_bytes(data, PACKET_LENGTH * num_measurements);

    printf("-------------------------------\n"
           "SHA1 performance test (20 byte input)\n"
           "-------------------------------\n");

    printf("Calculating hashes over %d inputs...\n", num_measurements);

    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * 20], 20, &hashed_data[i * SHA_DIGEST_LENGTH]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        printf("%i. sha1-20: %.3f ms\n", i + 1, timediff / 1000.0);
    }

    printf("-------------------------------\n"
           "SHA1 performance test (40 byte input)\n"
           "-------------------------------\n");

    printf("Calculating hashes over %d inputs...\n", num_measurements);

    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * 40], 40, &hashed_data[i * SHA_DIGEST_LENGTH]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        printf("%i. sha1-40: %.3f ms\n", i + 1, timediff / 1000.0);
    }

    printf("-------------------------------\n"
           "SHA1 performance test (1280 byte input)\n"
           "-------------------------------\n");

    printf("Calculating hashes over %d packets...\n", num_measurements);

    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        printf("%i. sha1-1280: %.3f ms\n", i + 1, timediff / 1000.0);
    }


    printf("-------------------------------\n"
           "SHA1-HMAC performance test\n"
           "-------------------------------\n");

    printf("Calculating hashes over %d packets...\n", num_measurements);

    RAND_bytes(key, 20);

    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        // HMAC on data
        HMAC(EVP_sha1(), key, 20, &data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH], &hashed_data_len);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);
        printf("%i. sha1-hmac: %.3f ms\n", i + 1, timediff / 1000.0);
    }


    printf("\n-------------------------------\n"
           "AES performance test\n"
           "-------------------------------\n");

    // create a key pool
    aes_enc_key = malloc(sizeof(AES_KEY));
    aes_dec_key = malloc(sizeof(AES_KEY));
    AES_set_encrypt_key(key, 8 * hip_enc_key_length(HIP_ESP_AES_SHA1),
                        aes_enc_key);
    AES_set_decrypt_key(key, 8 * hip_enc_key_length(HIP_ESP_AES_SHA1),
                        aes_dec_key);
    RAND_bytes(cbc_iv, AES_BLOCK_SIZE);

    printf("\nCalculating %d AES encryption\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        AES_cbc_encrypt(&data[i * PACKET_LENGTH], &enc_data[i * PACKET_LENGTH],
                        PACKET_LENGTH, aes_enc_key, cbc_iv, AES_ENCRYPT);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        printf("%i. AES encrypt: %.3f ms\n", i + 1, timediff / 1000.0);
    }

    printf("\nCalculating %d AES decryption\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        AES_cbc_encrypt(&enc_data[i * PACKET_LENGTH],
                        &dec_data[i * PACKET_LENGTH],
                        PACKET_LENGTH, aes_dec_key,
                        cbc_iv,
                        AES_DECRYPT);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        printf("%i. AES decrypt: %.3f ms\n", i + 1, timediff / 1000.0);
    }


    printf("\n-------------------------------\n"
           "RSA performance test\n"
           "-------------------------------\n");

    // create a key pool
    printf("Creating key pool of %d keys of length %d.\n", key_pool_size,
           rsa_key_len);
    for (i = 0; i < key_pool_size; i++) {
        rsa_key_pool[i] = create_rsa_key(rsa_key_len);
    }

    printf("\nCalculating %d RSA signatures\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        sig_len         = RSA_size(rsa_key_pool[i % key_pool_size]);

        rsa_sig_pool[i] = malloc(sig_len);

        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH]);

        // sign
        err = RSA_sign(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH],
                       SHA_DIGEST_LENGTH,
                       rsa_sig_pool[i], &sig_len,
                       rsa_key_pool[i % key_pool_size]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        if (err <= 0) {
            printf("RSA signature unsuccessful\n");
        } else {
            printf("%i. rsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
        }
    }

    printf("\nVerifying %d RSA signatures\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH]);

        err = RSA_verify(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH],
                         SHA_DIGEST_LENGTH,
                         rsa_sig_pool[i],
                         RSA_size(rsa_key_pool[i % key_pool_size]),
                         rsa_key_pool[i % key_pool_size]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        if (err <= 0) {
            printf("Verification failed\n");
        } else {
            printf("%i. rsa verification: %.3f ms\n", i + 1, timediff / 1000.0);
        }
    }


    printf("\n-------------------------------\n"
           "DSA performance test\n"
           "-------------------------------\n");

    printf("Creating key pool of %d keys of length %d...\n", key_pool_size,
           dsa_key_len);
    for (i = 0; i < key_pool_size; i++) {
        dsa_key_pool[i] = create_dsa_key(dsa_key_len);
    }

    printf("\nCalculating %d DSA signatures\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        sig_len         = sizeof(DSA_SIG *);

        dsa_sig_pool[i] = malloc(sig_len);

        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH]);

        // sign
        dsa_sig_pool[i] = DSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH],
                                      SHA_DIGEST_LENGTH,
                                      dsa_key_pool[i % key_pool_size]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        if (!dsa_sig_pool[i]) {
            printf("DSA signature not successful\n");
        } else {
            printf("%i. dsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
        }
    }

    printf("\nVerifying %d DSA signatures\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        gettimeofday(&start_time, NULL);

        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH]);

        err = DSA_do_verify(&hashed_data[i * SHA_DIGEST_LENGTH],
                            SHA_DIGEST_LENGTH,
                            dsa_sig_pool[i],
                            dsa_key_pool[i % key_pool_size]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        if (err <= 0) {
            printf("Verification failed\n");
        } else {
            printf("%i. dsa verification: %.3f ms\n", i + 1, timediff / 1000.0);
        }
    }


#ifdef HAVE_EC_CRYPTO
    printf("\n-------------------------------\n"
           "ECDSA performance test\n"
           "-------------------------------\n");

    printf("Creating key pool of %d keys for curve ECDSA_CURVE...\n",
           key_pool_size);
    for (i = 0; i < key_pool_size; i++) {
        ecdsa_key_pool[i] = EC_KEY_new_by_curve_name(ECDSA_CURVE);
        if (!ecdsa_key_pool[i]) {
            printf("ec key setup failed!\n");
        }

        if (!EC_KEY_generate_key(ecdsa_key_pool[i])) {
            printf("ec key generation failed!\n");
        }
    }

    printf("\nCalculating %d ECDSA signatures\n", num_measurements);
    for (i = 0; i < num_measurements; i++) {
        sig_len           = ECDSA_size(ecdsa_key_pool[i % key_pool_size]);

        ecdsa_sig_pool[i] = malloc(sig_len);

        gettimeofday(&start_time, NULL);

        // SHA1 on data
        SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH,
             &hashed_data[i * SHA_DIGEST_LENGTH]);

        // sign
        ecdsa_sig_pool[i] = ECDSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH],
                                          SHA_DIGEST_LENGTH,
                                          ecdsa_key_pool[i % key_pool_size]);

        gettimeofday(&stop_time, NULL);

        timediff = calc_timeval_diff(&start_time, &stop_time);

        if (!ecdsa_sig_pool[i]) {
            printf("ECDSA signature not successful\n");
        } else {
            printf("%i. ecdsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
        }
    }
#endif

    return err;
}
