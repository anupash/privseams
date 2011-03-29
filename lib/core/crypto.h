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

#ifndef HIP_LIB_CORE_CRYPTO_H
#define HIP_LIB_CORE_CRYPTO_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>

#include "debug.h"
#include "ife.h"
#include "transform.h"
#include "builder.h"

#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */



/* These should be consistent with the table length in crypto.c and
 * crypto/dh.c */
#define HIP_DH_384                    1 /* 384-bit group */
#define HIP_DH_OAKLEY_1               2 /* 768-bit OAKLEY well known group 1 */
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
#define HIP_DH_OAKLEY_17              5 /* 6144-bit MODP group */
#define HIP_DH_OAKLEY_18              6 /* 8192-bit MODP group */
#define HIP_FIRST_DH_GROUP_ID         HIP_DH_OAKLEY_5
#define HIP_SECOND_DH_GROUP_ID        HIP_DH_384
#define HIP_MAX_DH_GROUP_ID           7

#define DSA_KEY_DEFAULT_BITS       1024
#define RSA_KEY_DEFAULT_BITS       1024

#define DEFAULT_HOST_DSA_KEY_FILE_BASE HIPL_SYSCONFDIR "/hip_host_dsa_key"
#define DEFAULT_HOST_RSA_KEY_FILE_BASE HIPL_SYSCONFDIR "/hip_host_rsa_key"
#define DEFAULT_PUB_FILE_SUFFIX        ".pub"

#define DEFAULT_PUB_HI_FILE_NAME_SUFFIX  "_pub"
#define DEFAULT_ANON_HI_FILE_NAME_SUFFIX "_anon"

#ifdef OPENSSL_NO_SHA0
#define HIP_SHA(buffer, total_len, hash)   SHA1((buffer), (total_len), (hash));
#else
#define HIP_SHA(buffer, total_len, hash)   SHA((buffer), (total_len), (hash));
#endif

#ifdef OPENSSL_NO_SHA0
#define HIP_SHA(buffer, total_len, hash)   SHA1((buffer), (total_len), (hash));
#else
#define HIP_SHA(buffer, total_len, hash)   SHA((buffer), (total_len), (hash));
#endif

int ssl_rsa_verify(uint8_t *digest, uint8_t *public_key, uint8_t *signature, int pub_klen);
int ssl_dsa_verify(uint8_t *digest, uint8_t *public_key, uint8_t *signature);
/* In kernel these come from crypto/dh.h, included above */
int hip_gen_dh_shared_key(DH *dh, uint8_t *peer_key, size_t peer_len, uint8_t *out,
                          size_t outlen);
int hip_encode_dh_publickey(DH *dh, uint8_t *out, int outlen);
DH *hip_generate_dh_key(const int group_id);
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
DSA *create_dsa_key(const int bits);
RSA *create_rsa_key(const int bits);
int save_dsa_private_key(const char *const filenamebase, DSA *const dsa);
int save_rsa_private_key(const char *const filenamebase, RSA *const rsa);
int load_dsa_private_key(const char *const filenamebase, DSA **const dsa);
int load_rsa_private_key(const char *const filename, RSA **const rsa);
int impl_dsa_sign(const unsigned char *const digest, DSA *const dsa, unsigned char *const signature);
int impl_dsa_verify(const unsigned char *const digest, DSA *const dsa, const unsigned char *const signature);
int hip_write_hmac(int type, const void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
                         uint8_t *enc_key, int direction);
void get_random_bytes(void *buf, int n);

#endif /* HIP_LIB_CORE_CRYPTO_H */
