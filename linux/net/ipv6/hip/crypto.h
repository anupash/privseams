#ifndef HIP_CRYPTO_H
#define HIP_CRYPTO_H

#ifdef __KERNEL__
#  include <linux/crypto.h>
#  include "crypto/dh.h"
#  include "crypto/rsa.h"
#  include "crypto/dsa.h"
#  include "hip.h"

extern struct crypto_tfm *impl_sha1;

#else
#  include <sys/time.h>
#  include <time.h>
#  include <net/hip.h>
#  include <openssl/dsa.h>
#  include <openssl/rsa.h>
#  include <openssl/dh.h>
#  include <openssl/sha.h>
#  include <openssl/bn.h>
#  include <openssl/bio.h>
#  include <openssl/pem.h>
#  include <openssl/err.h> 
#  include "debug.h"

typedef enum {
        KEY_LEN_NULL = 0, /* RFC 2410 */
        KEY_LEN_MD5 = 16, /* 128 bits per RFC 2403 */
        KEY_LEN_SHA1 = 20, /* 160 bits per RFC 2404 */
        KEY_LEN_3DES = 24, /* 192 bits (3x64-bit keys) RFC 2451 */
        KEY_LEN_AES = 16, /* 128 bits per RFC 3686; also 192, 256-bits */
        KEY_LEN_BLOWFISH = 16, /* 128 bits per RFC 2451 */
} HIP_KEYLENS;

#define HIP_DSA_SIG_SIZE 41 /* T(1) + R(20) + S(20)  from RFC 2536 */
#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */

#endif /* __KERNEL__ */

/* These should be consistent with the table length in crypto.c and crypto/dh.c */
#define HIP_DH_384                    1 /* 384-bit group */
#define HIP_DH_OAKLEY_1               2 /* 768-bit OAKLEY well known group 1 */
#define HIP_DH_OAKLEY_5               3 /* 1536-bit MODP group */
#define HIP_DH_OAKLEY_15              4 /* 3072-bit MODP group */
#define HIP_DH_OAKLEY_17              5 /* 6144-bit MODP group */
#define HIP_DH_OAKLEY_18              6 /* 8192-bit MODP group */
#define HIP_DEFAULT_DH_GROUP_ID       HIP_DH_OAKLEY_5
#define HIP_MAX_DH_GROUP_ID 7 

extern time_t load_time;

int hip_build_digest(const int type, const void *in, int in_len, void *out);
#ifdef __KERNEL__
int hip_build_digest_repeat(struct crypto_tfm *dgst, struct scatterlist *sg, 
			    int nsg, void *out);
#endif

int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction);
int hip_init_cipher(void);
void hip_uninit_cipher(void);

#ifndef __KERNEL__
/* In kernel these come from crypto/dsa.h, included above */
int hip_dsa_sign(u8 *digest, u8 *private_key, u8 *signature);
int hip_dsa_verify(u8 *digest, u8 *public_key, u8 *signature);

/* In kernel these come from crypto/rsa.h, included above */
int hip_rsa_sign(u8 *digest, u8 *private_key, u8 *signature, int priv_klen);
int hip_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen);

/* In kernel these come from crypto/dh.h, included above */
int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out,
			  size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
void hip_free_dh(DH *target);
u16 hip_get_dh_size(u8 hip_dh_group_type);
#endif

#endif /* HIP_CRYPTO_H */
