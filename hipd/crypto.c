#include "crypto.h"

struct crypto_tfm impl_sha1; /* XX FIX: FILL THIS STRUCTURE */

void crypto_digest_digest(struct crypto_tfm *tfm, char *src_buf, int ignore,
			  char *dst_buf) {
  exit(1); /* XX FIXME */
}

/**
 * hip_build_digest - calculate a digest over given data
 * @type: the type of digest, e.g. "sha1"
 * @in: the beginning of the data to be digested
 * @in_len: the length of data to be digested in octets
 * @out: the digest
 *
 * @out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out) {
  exit(1); /* XX FIXME */
  return 1;
}

/**
 * hip_build_digest_repeat - Calculate digest repeatedly
 * @dgst: Digest transform
 * @sg: Valid scatterlist array
 * @nsg: Number of scatterlists in the @sg array.
 * @out: Output buffer. Should contain enough bytes for the digest.
 * 
 * Use this function instead of the one above when you need to do repeated
 * calculations *IN THE SAME MEMORY SPACE (SIZE _AND_ ADDRESS)*
 * This is an optimization for cookie solving. There we do a lots of digests
 * in the same memory block and its size is constant.
 * So instead of calling N times hip_map_virtual_to_pages() the caller maps
 * once and all the digest iterations use the same pages.
 * This improves the speed greatly.
 *
 * Returns 0 always. The digest is written to @out.
*/
int hip_build_digest_repeat(struct crypto_tfm *dgst, char *data, int ignore,
			    void *out)
{
  exit(1); /* XX FIXME */
  return 1;
}

/**
 * hip_write_hmac - calculate hmac
 * @type: Type (digest algorithm) of HMAC
 * @key: Pointer to the key used for HMAC
 * @in: Input buffer pointer
 * @in_len: Length of buffer
 * @out: Output buffer pointer. For SHA1-HMAC this is 160bits
 *
 * Returns true, if ok.
 */
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out)
{
  exit(1); /* XX FIXME */
  return 1;
}

/**
 * hip_crypto_encrypted - encrypt/decrypt data
 * @data: data to be encrypted/decrypted
 * @iv: initialization vector
 * @enc_alg: encryption algorithm to use
 * @enc_len: length of @data
 * @enc_key: encryption/decryption key to use
 * @direction: flag for selecting encryption/decryption
 *
 * @direction is HIP_DIRECTION_ENCRYPT if @data is to be encrypted
 * or HIP_DIRECTION_DECRYPT if @data is to be decrypted.
 *
 * The result of the encryption/decryption of @data is overwritten to @data.
 *
 * Returns: 0 is encryption/decryption was successful, otherwise < 0.
 */
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction)
{
  exit(1); /* XX FIXME */
  return 1;
}

void get_random_bytes(void *buf, int nbytes)
{
  gcry_randomize(buf, nbytes, GCRY_STRONG_RANDOM);
}
