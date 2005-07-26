#include "crypto.h"

/* All cipher and digest implementations we support. */
static struct crypto_tfm *impl_3des_cbc = NULL;
static struct crypto_tfm *impl_aes_cbc = NULL;

struct crypto_tfm *impl_null = NULL;
struct crypto_tfm *impl_sha1 = NULL;

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
int hip_build_digest(const int type, const void *in, int in_len, void *out)
{
	struct crypto_tfm *impl = NULL;
	struct scatterlist sg[HIP_MAX_SCATTERLISTS];
	unsigned int nsg = HIP_MAX_SCATTERLISTS;

	int err = 0;
	switch(type) {
	case HIP_DIGEST_SHA1:
		impl = impl_sha1;
		break;
	case HIP_DIGEST_MD5:
		HIP_DEBUG("Not implemented\n");
	default:
		HIP_ERROR("Unknown digest: %x\n",type);
		return -EFAULT;
	}

	_HIP_DEBUG("Mapping virtual to pages\n");

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1 ) {
		HIP_ERROR("Error mapping virtual addresses to physical pages\n");
		return -EFAULT;
	}

	_HIP_DEBUG("Mapping virtual to pages successful\n");

	crypto_digest_init(impl);
	crypto_digest_digest(impl, sg, nsg, out);

	return 0;
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
int hip_build_digest_repeat(struct crypto_tfm *dgst, struct scatterlist *sg, 
			    int nsg, void *out)
{
	crypto_digest_init(dgst); // is this necessary always?
	crypto_digest_digest(dgst, sg, nsg, out);
	return 0;
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
	int err = 0;
	int keylen = 20; // anticipating HIP_DIGEST_SHA1_HMAC
	struct crypto_tfm *impl = NULL;
	struct scatterlist sg[HIP_MAX_SCATTERLISTS];
	int nsg = HIP_MAX_SCATTERLISTS;

	switch(type) {
	case HIP_DIGEST_SHA1_HMAC:
		impl = impl_sha1;
		break;
	case HIP_DIGEST_MD5_HMAC:
		HIP_DEBUG("MD5_HMAC not implemented\n");
	default:
		HIP_ERROR("Unknown HMAC type 0x%x\n",type);
		return 0;
	}

	_HIP_HEXDUMP("HMAC key", key, keylen);
	_HIP_HEXDUMP("hmac in", in, in_len);

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1) {
		HIP_ERROR("Mapping failed\n");
		return 0;
	}

	crypto_hmac(impl, key, &keylen, sg, nsg, out);
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
	int err = 0;
	int key_len;  /* in bytes */
	struct crypto_tfm *impl = NULL;
	struct scatterlist src_sg[HIP_MAX_SCATTERLISTS];
	unsigned int src_nsg = HIP_MAX_SCATTERLISTS;
	/* crypto_cipher_encrypt_iv writes a new iv on top of the old when
	   encrypting, so we need to preserve the the original. Also, we
	   encrypt only once in HIP, so we can discard the new iv. */
	char *iv_copy = NULL;

	/* I haven't tested if the function works with 3DES + NULL iv. The
	   NULL transform + NULL iv combination works, though. -miika */

	/* We cannot use the same memory are for en/decryption? */
	void *result = NULL;
	result = HIP_MALLOC(enc_len, GFP_KERNEL);
	if (!result) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(result, data, enc_len);

	_HIP_HEXDUMP("hip_crypto_encrypted encrypt data", data, enc_len);
	switch(enc_alg) {
	case HIP_HIP_AES_SHA1:
		impl = impl_aes_cbc;
		key_len = ESP_AES_KEY_BITS >> 3;
		iv_copy = HIP_MALLOC(16, GFP_KERNEL);
		if (!iv_copy) {
			err = -ENOMEM;
			goto out_err;
		}
		memcpy(iv_copy, iv, 16);
		break;
	case HIP_HIP_3DES_SHA1:
		impl = impl_3des_cbc;
		key_len = ESP_3DES_KEY_BITS >> 3;
		iv_copy = HIP_MALLOC(8, GFP_KERNEL);
		if (!iv_copy) {
			err = -ENOMEM;
			goto out_err;
		}
		memcpy(iv_copy, iv, 8);
		break;
	case HIP_HIP_NULL_SHA1:
		impl = impl_null;
		key_len = 0;
		iv_copy = NULL;
		break;
	default:
		HIP_ERROR("Attempted to use unknown CI (enc_alg=%d)\n",
			  enc_alg);
		err = -EFAULT;
		goto out_err;
	}

	_HIP_DEBUG("Mapping virtual to pages\n");

	err = hip_map_virtual_to_pages(src_sg, &src_nsg, result, enc_len);
	if (err || src_nsg < 1) {
		HIP_ERROR("Error mapping source data\n");
		err = -EFAULT;
		goto out_err;
	}

	_HIP_DEBUG("Mapping virtual to pages successful\n");

	/* we will write over the source */
	err = crypto_cipher_setkey(impl, enc_key, key_len);
	if (err) {
		if (impl->crt_flags & CRYPTO_TFM_RES_BAD_KEY_SCHED) {
			HIP_ERROR("key is weak.\n");
			HIP_HEXDUMP("key", enc_key, key_len);
		}
		HIP_ERROR("Could not set encryption/decryption key\n");
		err = -EFAULT;
		goto out_err;
	}

	HIP_DEBUG("enc_len=%d\n", enc_len);
	switch(direction) {
	case HIP_DIRECTION_ENCRYPT:
		if (iv_copy) {
			err = crypto_cipher_encrypt_iv(impl, src_sg, src_sg,
						       enc_len, iv_copy);
			/* The encrypt function writes crap on iv */
			//memset(iv, 0, 8);
		} else {
			err = crypto_cipher_encrypt(impl, src_sg, src_sg,
						    enc_len);
		}
		if (err) {
			HIP_ERROR("Encryption failed\n");
			//err = -EFAULT;
			goto out_err;
		}

		break;
	case HIP_DIRECTION_DECRYPT:
		if (iv_copy) {
			err = crypto_cipher_decrypt_iv(impl, src_sg, src_sg,
						       enc_len, iv_copy);
		} else {
			err = crypto_cipher_decrypt(impl, src_sg, src_sg,
						    enc_len);
		}
		if (err) {
			HIP_ERROR("Decryption failed\n");
			//err = -EFAULT;
			goto out_err;
		}
		break;
	default:
		HIP_ERROR("Undefined direction (%d)\n", direction);
		err = -EINVAL;
		break;
	}

	memcpy(data, result, enc_len);

 out_err:
	if (iv_copy)
		HIP_FREE(iv_copy);
	if (result)
		HIP_FREE(result);
	return err;
}

/**
 * hip_init_cipher - initialize needed cipher algorithms
 * There is no need to delay initialization and locking of these
 * algorithms since we require their use. Some optional algorithms
 * may be initialized later.
 * Currently we use AES, 3DES-CBC, NULL-ECB?, SHA1(+HMAC), DSA, DH
 * Returns: 1 if all algorithms were initialized, otherwise < 0.
 */
int hip_init_cipher(void)
{
	int err = 0;
	u32 supported_groups;

	/* instruct the "IPsec" to check for available algorithms */
	xfrm_probe_algs();

// FIXME: tkoponen, none of the below is needed if hipd is in userspace?
	/* Get implementations for all the ciphers we support */
	impl_aes_cbc = crypto_alloc_tfm("aes", CRYPTO_TFM_MODE_CBC);
	if (!impl_aes_cbc) {
		HIP_ERROR("Unable to register AES cipher\n");
		err = -1;
		goto out_err;
	}

	/* Get implementations for all the ciphers we support */
	impl_3des_cbc = crypto_alloc_tfm("des3_ede", CRYPTO_TFM_MODE_CBC);
	if (!impl_3des_cbc) {
		HIP_ERROR("Unable to register 3DES cipher\n");
		err = -1;
		goto out_err;
	}

	impl_null = crypto_alloc_tfm("cipher_null", CRYPTO_TFM_MODE_ECB);
	if (!impl_null) {
		HIP_ERROR("Unable to register NULL cipher\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("Initializing SHA1\n");
	schedule();
	
	impl_sha1 = crypto_alloc_tfm("sha1", 0);
	if (!impl_sha1) {
		HIP_ERROR("Unable to register SHA1 digest\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("SHA1 initialized\n");
	schedule();

	supported_groups = (1 << HIP_DH_OAKLEY_1 | 
			    1 << HIP_DH_OAKLEY_5 |
			    1 << HIP_DH_384);

	/* Does not return errors. Should it?
	   the code will try to regenerate the key if it is
	   missing...
	*/
	HIP_DEBUG("Generating DH keys\n");
	schedule();
	
	hip_regen_dh_keys(supported_groups);	

	return 0;

 out_err:
	hip_uninit_cipher();
	return err;
}

/**
 * hip_uninit_cipher - uninitialize needed cipher algorithms
 *
 * Actually this does nothing because it looks like the cipher
 * implementations do not require freeing, although it seems possible
 * to unregister them.
 */
void hip_uninit_cipher(void)
{
        /* 
	 * jlu XXX: If I understand correctly, the implementations do
	 * not require freeing, although it seems possible to unregister them...
	 * Really weird. Something is broken somewhere.
	 */
	hip_dh_uninit();

	if (impl_sha1)
		crypto_free_tfm(impl_sha1);
	if (impl_null)
		crypto_free_tfm(impl_null);
	if (impl_3des_cbc)
		crypto_free_tfm(impl_3des_cbc);
	if (impl_aes_cbc)
		crypto_free_tfm(impl_aes_cbc);

	return;
}

