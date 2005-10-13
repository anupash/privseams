#ifndef HIP_CRYPTO_H
#define HIP_CRYPTO_H

#include "hip.h"
//#include "debug.h"

#include <sys/time.h>
#include <time.h>
#include "hip.h"
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "hidb.h"

#define HIP_DSA_SIG_SIZE 41 /* T(1) + R(20) + S(20)  from RFC 2536 */
#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */



/* These should be consistent with the table length in crypto.c and crypto/dh.c */
#define HIP_DH_384                    1 /* 384-bit group */
#define HIP_DH_OAKLEY_1               2 /* 768-bit OAKLEY well known group 1 */
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
#define HIP_DH_OAKLEY_17              5 /* 6144-bit MODP group */
#define HIP_DH_OAKLEY_18              6 /* 8192-bit MODP group */
#define HIP_DEFAULT_DH_GROUP_ID       HIP_DH_OAKLEY_5
#define HIP_MAX_DH_GROUP_ID 7 

int hip_build_digest(const int type, const void *in, int in_len, void *out);

int ssl_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen);
int ssl_dsa_verify(u8 *digest, u8 *public_key, u8 *signature);

int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction);
int hip_init_cipher(void);
void hip_uninit_cipher(void);

/* In kernel these come from crypto/dh.h, included above */
int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out,
			  size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
void hip_free_dh(DH *target);
u16 hip_get_dh_size(u8 hip_dh_group_type);
void get_random_bytes(void *buf, int n);

#endif /* HIP_CRYPTO_H */
