#ifndef HIP_CRYPTO_H
#define HIP_CRYPTO_H

#ifdef __KERNEL__
#  include <linux/crypto.h>
#  include "crypto/dh.h"
#  include "crypto/rsa.h"
#  include "crypto/dsa.h"
#  include "hip.h"
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
struct crypto_tfm {
  /* XX FIXME */
  // OpenSSL context?
};

#endif /* __KERNEL__ */

/* this should be consistent with the table length in dh.c */
#define HIP_MAX_DH_GROUP_ID 7 

extern struct crypto_tfm *impl_sha1;
extern time_t load_time;

// this is from kernel...
//void crypto_digest_digest(struct crypto_tfm *tfm, char *src_buf, int ignore,
//			  char *dst_buf);
int hip_build_digest(const int type, const void *in, int in_len, void *out);
#ifdef __KERNEL__
int hip_build_digest_repeat(struct crypto_tfm *dgst, struct scatterlist *sg, 
			    int nsg, void *out);
#else
int hip_build_digest_repeat(struct crypto_tfm *dgst, char *data, 
			    int ignore, void *out);
#endif

int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction);
int hip_init_cipher(void);
void hip_uninit_cipher(void);

#ifndef __KERNEL__
/* In kernel these come from crypto/dsa.h, above */
int hip_dsa_sign(u8 *digest, u8 *private_key, u8 *signature);
int hip_dsa_verify(u8 *digest, u8 *public_key, u8 *signature);

/* In kernel these come from crypto/rsa.h, above */
int hip_rsa_sign(u8 *digest, u8 *private_key, u8 *signature, int priv_klen);
int hip_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen);

/* In kernel these come from crypto/dh.h, above */
int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out,
			  size_t outlen);
int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen);
DH *hip_generate_dh_key(int group_id);
DH *hip_dh_clone(DH *src);
void hip_free_dh_structure(DH *target);
#endif

#endif /* HIP_CRYPTO_H */
