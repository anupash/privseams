#ifndef HIP_CRYPTO_H
#define HIP_CRYPTO_H

struct crypto_tfm {
  /* XX FIXME */
};

void crypto_digest_digest(struct crypto_tfm *tfm, char *src_buf, int ignore,
			  char *dst_buf);
int hip_build_digest(const int type, const void *in, int in_len, void *out);
int hip_build_digest_repeat(struct crypto_tfm *dgst, char *data, 
			    int ignore, void *out);
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction);

#endif /* HIP_CRYPTO_H */
