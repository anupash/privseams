/*
 * HIP input
 *
 * Licence: GNU/GPL
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *          Anthony D. Joseph <adj@hiit.fi>
 *
 */

#include "input.h"

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac, 
			   void *hmac_key, int hmac_type);

/*****************************************************************************
 *                            UTILITY FUNCTIONS                              *
 *****************************************************************************/

/**
 * hip_controls_sane - check for illegal controls
 * @controls: control value to be checked
 * @legal: legal control values to check @controls against
 *
 * Controls are given in host byte order.
 *
 * Returns 1 if there are no illegal control values in @controls,
 * otherwise 0.
 */
static inline int hip_controls_sane(u16 controls, u16 legal)
{
	return ((controls & ( HIP_CONTROL_CERTIFICATES |
			     HIP_CONTROL_HIT_ANON
#ifdef CONFIG_HIP_RVS
			     | HIP_CONTROL_RVS_CAPABLE //XX:FIXME
#endif
			     | HIP_CONTROL_SHT_MASK /* should check reserved ? */
			     | HIP_CONTROL_DHT_MASK
			      )) | legal) == legal;
}

/**
 * hip_create_signature - Calculate SHA1 hash over the data and sign it.
 * @buffer_start: Pointer to start of the buffer over which the hash is
 *                calculated.
 * @buffer_length: Length of the buffer.
 * @host_id: DSA private key.
 * @signature: Place for signature.
 *
 * Signature size for DSA is 41 bytes.
 *
 * Returns 1 if success, otherwise 0.
 */
int hip_create_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature)
{
	int err = 0;
	u8 sha1_digest[HIP_AH_SHA_LEN];

	_HIP_HEXDUMP("Signature data (create)", buffer_start, buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1, buffer_start, buffer_length,
			     sha1_digest) < 0)
	{
		HIP_ERROR("Building of SHA1 digest failed\n");
		goto out_err;
	}

	HIP_HEXDUMP("create digest", sha1_digest, HIP_AH_SHA_LEN);
	_HIP_HEXDUMP("dsa key", (u8 *)(host_id + 1), ntohs(host_id->hi_length));

	if (hip_get_host_id_algo(host_id) == HIP_HI_RSA) {
		err = hip_rsa_sign(sha1_digest, (u8 *)(host_id + 1), signature, 
				   3+128*2+64+64
				   /*e+n+d+p+q*/
				   /*1 + 3 + 128 * 3*/ );
	} else {
		err = hip_dsa_sign(sha1_digest,(u8 *)(host_id + 1), signature);
	}

	if (err) {
		HIP_ERROR("Signing error\n");
		return 0;
	}

	err = 1;

 out_err:
	return err;
}


/**
 * hip_verify_signature - Verifies that the signature matches the data it has 
 * been calculated over.
 * @buffer_start: Pointer to the start of the buffer over which to calculate
 *                SHA1-160 digest.
 * @buffer_length: Length of the buffer at @buffer_start
 * @host_id: Pointer to HOST_ID (as specified by the HIP draft).
 * @signature: Pointer to the signature
 *
 * Returns 1 if the signature was ok, else 0
 */
int hip_verify_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature)
{
	u8 *public_key = (u8 *) (host_id + 1);
	int tmp, ok = 0;
	unsigned char sha1_digest[HIP_AH_SHA_LEN];
	int use_rsa = 0;

	/* check for all algorithms */

	if (hip_get_host_id_algo(host_id) == HIP_HI_RSA) {
		use_rsa = 1;
	} else if (hip_get_host_id_algo(host_id) != HIP_HI_DSA) {
		HIP_ERROR("Unsupported algorithm:%d\n",
			  hip_get_host_id_algo(host_id));
		goto out_err;
	}

	_HIP_HEXDUMP("Signature data (verify)",buffer_start,buffer_length);
	_HIP_DEBUG("buffer_length=%d\n", buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1, buffer_start,
			     buffer_length,sha1_digest)) {
		HIP_ERROR("Could not calculate SHA1 digest\n");
		goto out_err;
	}

	HIP_HEXDUMP("Verify hexdump", sha1_digest, HIP_AH_SHA_LEN);

	//public_key_len = hip_get_param_contents_len(host_id) - 4;

	_HIP_HEXDUMP("verify key", public_key, public_key_len);

	if (use_rsa) {
		size_t public_key_len;
		public_key_len = ntohs(host_id->hi_length) - 
			sizeof(struct hip_host_id_key_rdata);
		_HIP_HEXDUMP("Verify hexdump sig **", signature, 
			     HIP_RSA_SIGNATURE_LEN);
		tmp = hip_rsa_verify(sha1_digest, public_key, signature, 
				     public_key_len);
		HIP_HEXDUMP("public key",public_key,public_key_len);
	} else {
		_HIP_HEXDUMP("Verify hexdump sig **", signature, 
			     HIP_DSA_SIGNATURE_LEN);
		tmp = hip_dsa_verify(sha1_digest, public_key, signature);
	}
	
	switch(tmp) {
	case 0:
		ok = 1;
		break;
	case 1:
		HIP_HEXDUMP("digest",sha1_digest, HIP_AH_SHA_LEN);
		HIP_HEXDUMP("signature", signature,  use_rsa ? HIP_RSA_SIGNATURE_LEN : HIP_DSA_SIGNATURE_LEN);		
		break;
	default:
		break;
	}

 out_err:
	return ok;
}

/**
 * hip_verify_packet_hmac - verify packet HMAC
 * @msg: HIP packet
 * @entry: HA
 *
 * Returns: 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	int err, len, orig_len;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (!hmac) {
		HIP_ERROR("Packet contained no HMAC parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	_HIP_DEBUG("HMAC found\n");

	/* hmac verification modifies the msg length temporarile, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	_HIP_HEXDUMP("HMACced data", msg, len);
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));
	err = hip_verify_hmac(msg, hmac->hmac_data,
			      tmpkey.key, HIP_DIGEST_SHA1_HMAC);
	if (err) {
		HIP_ERROR("HMAC validation failed\n");
		goto out_err;
	} 

	hip_set_msg_total_len(msg, orig_len);

 out_err:
	return err;
}

/**
 * hip_verify_packet_hmac2 - verify packet HMAC
 * @msg: HIP packet
 * @entry: HA
 *
 * Returns: 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated. Assumes that the hmac includes only the header
 * and host id.
 */
int hip_verify_packet_hmac2(struct hip_common *msg,
			    struct hip_crypto_key *crypto_key,
			    struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;
	struct hip_common *msg_copy = NULL;
	struct hip_spi *spi;

	msg_copy = hip_msg_alloc();
	if (!msg) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(msg_copy, msg, sizeof(struct hip_common));
	hip_set_msg_total_len(msg_copy, 0);
	hip_zero_msg_checksum(msg_copy);

	spi = hip_get_param(msg, HIP_PARAM_SPI);
	HIP_ASSERT(spi);
	err = hip_build_param(msg_copy, spi);
	if (err) {
		err = -EFAULT;
		goto out_err;
	}

	hip_build_param(msg_copy, host_id);

	hmac = hip_get_param(msg, HIP_PARAM_HMAC2);
	if (!hmac) {
		HIP_ERROR("Packet contained no HMAC parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	_HIP_DEBUG("HMAC found\n");

	HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));
	err = hip_verify_hmac(msg_copy, hmac->hmac_data,
			      tmpkey.key, HIP_DIGEST_SHA1_HMAC);
	if (err) {
		HIP_ERROR("HMAC validation failed\n");
		goto out_err;
	} 

 out_err:

	if (msg_copy)
		HIP_FREE(msg_copy);

	return err;
}

/**
 * hip_verify_packet_signature - verify packet SIGNATURE
 * @msg: HIP packet
 * @hid: HOST ID
 *
 * Returns: 0 if SIGNATURE was validated successfully, < 0 if SIGNATURE could
 * not be validated.
 */
int hip_verify_packet_signature(struct hip_common *msg,
				struct hip_host_id *hid)
{
	int err = 0;
	struct hip_sig *sig;
 	int len, origlen;

	origlen = hip_get_msg_total_len(msg);

 	sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
		HIP_ERROR("Could not find signature\n");
 		goto out_err;
 	}

	_HIP_HEXDUMP("SIG", sig, hip_get_param_total_len(sig));

 	len = ((u8 *) sig) - ((u8 *) msg);
 	hip_zero_msg_checksum(msg);
 	hip_set_msg_total_len(msg, len);

 	if (len < 0) {
 		err = -ENOENT;
		HIP_ERROR("Invalid signature len\n");
 		goto out_err;
 	}

 	if (!hip_verify_signature(msg, len, hid,
 				  (u8 *) (sig + 1))) {
 		HIP_ERROR("Verification of signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}

 out_err:
 	hip_set_msg_total_len(msg, origlen);
	return err;
}

/**
 * hip_verify_packet_signature2 - verify packet SIGNATURE2
 * @msg: HIP packet
 * @hid: HOST ID
 *
 * Returns: 0 if SIGNATURE2 was validated successfully, < 0 if
 * SIGNATURE2 could not be validated.
 */
int hip_verify_packet_signature2(struct hip_common *msg,
				struct hip_host_id *hid)
{
	int err = 0;
	struct hip_sig2 *sig2;
	int origlen, len;
	struct in6_addr tmpaddr;
	struct hip_puzzle *pz;
	uint8_t opaque[3];
	uint64_t randi;

	origlen = hip_get_msg_total_len(msg);

	sig2 = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE2);
	if (!sig2) {
		HIP_ERROR("No SIGNATURE2 found\n");
		err = -ENOENT;
		goto out_err;
	}

	len = (((u8 *)sig2 - ((u8 *) msg)));

 	ipv6_addr_copy(&tmpaddr, &msg->hitr);
 	memset(&msg->hitr, 0, sizeof(struct in6_addr));

	hip_set_msg_total_len(msg, len);
	msg->checksum = 0;

	pz = hip_get_param(msg, HIP_PARAM_PUZZLE);
	if (!pz) {
		HIP_ERROR("Illegal R1 packet (puzzle missing)\n");
		err = -ENOENT;
		goto out_err;
	}

	memcpy(opaque, pz->opaque, 3);
	randi = pz->I;

	memset(pz->opaque, 0, 3);
	pz->I = 0;

	if (!hip_verify_signature(msg, len, hid,
				  (u8 *)(sig2 + 1))) {
		HIP_ERROR("Signature verification failed\n");
		/* well if we fail, then we better dump the packet */
		HIP_HEXDUMP("Failed packet", msg, len);
		err = -EINVAL;
		goto out_err;
	}

	memcpy(pz->opaque, opaque, 3);
	pz->I = randi;

 	ipv6_addr_copy(&msg->hitr, &tmpaddr);

 	/* the checksum is not restored because it was already checked in
 	   hip_inbound */
 out_err:
 	hip_set_msg_total_len(msg, origlen);
	return err;
}


/**
 * hip_produce_keying_material - Create shared secret and produce keying material 
 * @msg: the HIP packet received from the peer
 * @ctx: context
 *
 * The initial ESP keys are drawn out of the keying material.
 *
 * Returns zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx)
{
	u8 *dh_shared_key = NULL;
	int hip_transf_length, hmac_transf_length;
	int auth_transf_length, esp_transf_length;
	int hip_tfm, esp_tfm;
	int dh_shared_len = 1024;
	int err = 0;
	struct hip_keymat_keymat km;
	char *keymat = NULL;
	size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
	size_t keymat_len; /* note SHA boundary */
	struct hip_tlv_common *param = NULL;
	int we_are_HITg = 0;

	/* perform light operations first before allocating memory or
	 * using lots of cpu time */
	param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		HIP_ERROR("Could not find HIP transform\n");
		err = -EINVAL;
		goto out_err;
	}
	hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param);
	if (hip_tfm == 0) {
		HIP_ERROR("Could not select proper HIP transform\n");
		err = -EINVAL;
		goto out_err;
	}

	param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM);
	if (!param) {
		HIP_ERROR("Could not find ESP transform\n");
		err = -EINVAL;
		goto out_err;
	}
	esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param);
	if (esp_tfm == 0) {
		HIP_ERROR("Could not select proper ESP transform\n");
		err = -EINVAL;
		goto out_err;
	}

	hip_transf_length = hip_transform_key_length(hip_tfm);
	hmac_transf_length = hip_hmac_key_length(esp_tfm);
	esp_transf_length = hip_enc_key_length(esp_tfm);
	auth_transf_length = hip_auth_key_length_esp(esp_tfm);

	HIP_DEBUG("transform lengths: hip=%d, hmac=%d, esp=%d, auth=%d\n",
		  hip_transf_length, hmac_transf_length, esp_transf_length,
		  auth_transf_length);

	/* Create only minumum amount of KEYMAT for now. From draft
	 * chapter HIP KEYMAT we know how many bytes we need for all
	 * keys used in the base exchange. */
	keymat_len_min = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length + esp_transf_length +
		auth_transf_length + esp_transf_length + auth_transf_length;

	keymat_len = keymat_len_min;
	if (keymat_len % HIP_AH_SHA_LEN)
		keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);

	HIP_DEBUG("keymat_len_min=%u keymat_len=%u\n", keymat_len_min, 
		  keymat_len);

	keymat = HIP_MALLOC(keymat_len, GFP_KERNEL);
	if (!keymat) {
		HIP_ERROR("No memory for KEYMAT\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* 1024 should be enough for shared secret. The length of the
	 * shared secret actually depends on the DH Group. */

	/* TODO: 1024 -> hip_get_dh_size ? */
	dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_KERNEL);
	if (!dh_shared_key) {
		HIP_ERROR("No memory for DH shared key\n");
		err = -ENOMEM;
		goto out_err;
	}
	memset(dh_shared_key, 0, dh_shared_len);

	param = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (!param) {
		err = -ENOENT;
		HIP_ERROR("No Diffie-Hellman param found\n");
		goto out_err;
	}

	dh_shared_len = hip_calculate_shared_secret((struct hip_diffie_hellman *) param, 
						    dh_shared_key, dh_shared_len);
	if (dh_shared_len < 0) {
		HIP_ERROR("Calculation of shared secret failed\n");
		err = -EINVAL;
		goto out_err;
	}
	_HIP_DEBUG("dh_shared_len=%u\n", dh_shared_len);
	_HIP_HEXDUMP("DH SHARED KEY", dh_shared_key, dh_shared_len);

	hip_make_keymat(dh_shared_key, dh_shared_len,
			&km, keymat, keymat_len,
			&msg->hits, &msg->hitr, &ctx->keymat_calc_index);

	/* draw from km to keymat, copy keymat to dst, length of
	 * keymat is len */
#define KEYMAT_DRAW_AND_COPY(dst, len)				\
         {							\
	   void *p = hip_keymat_draw(&km, len);		        \
	   if (!p) {						\
		 HIP_ERROR("Could not draw from keymat\n");	\
		 err = -EINVAL;					\
		 goto out_err;					\
	   }							\
	   memcpy(dst, p, len);					\
        }

	/* Draw keys: */
	we_are_HITg = hip_hit_is_bigger(&msg->hitr, &msg->hits);
	HIP_DEBUG("we are HIT%c\n", we_are_HITg ? 'g' : 'l');
	if (we_are_HITg) {
		KEYMAT_DRAW_AND_COPY(&ctx->hip_enc_out.key, hip_transf_length);
		KEYMAT_DRAW_AND_COPY(&ctx->hip_hmac_out.key, hmac_transf_length);
		KEYMAT_DRAW_AND_COPY(&ctx->hip_enc_in.key, hip_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->hip_hmac_in.key, hmac_transf_length);
		KEYMAT_DRAW_AND_COPY(&ctx->esp_out.key, esp_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->auth_out.key, auth_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->esp_in.key, esp_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->auth_in.key, auth_transf_length);
 	} else {
 	 	KEYMAT_DRAW_AND_COPY(&ctx->hip_enc_in.key, hip_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->hip_hmac_in.key, hmac_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->hip_enc_out.key, hip_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->hip_hmac_out.key, hmac_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->esp_in.key, esp_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->auth_in.key, auth_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->esp_out.key, esp_transf_length);
 		KEYMAT_DRAW_AND_COPY(&ctx->auth_out.key, auth_transf_length);
 	}
 	HIP_HEXDUMP("HIP-gl encryption", &ctx->hip_enc_out.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-gl integrity (HMAC) key", &ctx->hip_hmac_out.key,
 		    hmac_transf_length);
 	_HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n", hip_transf_length);
	HIP_HEXDUMP("HIP-lg encryption", &ctx->hip_enc_in.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-lg integrity (HMAC) key", &ctx->hip_hmac_in.key, hmac_transf_length);
 	HIP_HEXDUMP("SA-gl ESP encryption key", &ctx->esp_out.key, esp_transf_length);
 	HIP_HEXDUMP("SA-gl ESP authentication key", &ctx->auth_out.key, auth_transf_length);
 	HIP_HEXDUMP("SA-lg ESP encryption key", &ctx->esp_in.key, esp_transf_length);
 	HIP_HEXDUMP("SA-lg ESP authentication key", &ctx->auth_in.key, auth_transf_length);

#undef KEYMAT_DRAW_AND_COPY

	/* the next byte when creating new keymat */
	ctx->current_keymat_index = keymat_len_min; /* offset value, so no +1 ? */
	ctx->keymat_calc_index = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;

	memcpy(ctx->current_keymat_K, keymat+(ctx->keymat_calc_index-1)*HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

	_HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
		   ctx->keymat_calc_index, ctx->current_keymat_index);
	_HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K, HIP_AH_SHA_LEN);

	/* store DH shared key */
	ctx->dh_shared_key = dh_shared_key;
	ctx->dh_shared_key_len = dh_shared_len;

	/* on success HIP_FREE for dh_shared_key is called by caller */
 out_err:
	if (err) {
		if (dh_shared_key)
			HIP_FREE(dh_shared_key);
	}
	if (keymat)
		HIP_FREE(keymat);

	return err;
}


/*****************************************************************************
 *                           PACKET/PROTOCOL HANDLING                        *
 *****************************************************************************/

/**
 * hip_create_i2 - Create I2 packet and send it
 * @ctx: Context that includes the incoming R1 packet
 * @solved_puzzle: Value that solves the puzzle
 * @entry: HA
 *
 * Returns: zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle, 
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry)
{
	int err = 0, dh_size = 0, written, host_id_in_enc_len;
	uint32_t spi_in = 0;
	hip_transform_suite_t transform_hip_suite, transform_esp_suite; 
	struct hip_host_id *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	char *enc_in_msg = NULL, *host_id_in_enc = NULL, *iv = NULL;
	struct in6_addr daddr;
	u8 *dh_data = NULL;
	struct hip_spi *hspi;
	struct hip_common *i2 = NULL;
	struct hip_param *param;
	struct hip_diffie_hellman *dh_req;
	//int algo;
	u8 *signature = NULL;

	struct hip_spi_in_item spi_in_data;
	uint16_t mask;

	HIP_DEBUG("\n");

	HIP_ASSERT(entry);

	/* allocate space for new I2 */
	i2 = hip_msg_alloc();
	if (!i2) {
		HIP_ERROR("Allocation of I2 failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* allocate memory for writing Diffie-Hellman shared secret */
	dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID);
	if (dh_size == 0) {
		HIP_ERROR("Could not get dh size\n");
		err = -EINVAL;
		goto out_err;
	}
	dh_data = HIP_MALLOC(dh_size, GFP_KERNEL);
	if (!dh_data) {
		HIP_ERROR("Failed to alloc memory for dh_data\n");
		err = -ENOMEM;
		goto out_err;
	}
	
#if 0 // does not work correctly with DSA-RSA base exhcange -miika
	{
		struct hip_host_id *mofo;
		mofo = hip_get_param(ctx->input, HIP_PARAM_HOST_ID);
		
		algo = hip_get_host_id_algo(mofo);
	}
#endif
	
	/* Get a localhost identity, allocate memory for the public key part
	   and extract the public key from the private key. The public key is
	   needed in the ESP-ENC below. */
	host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO);
	if (!host_id_pub) {
		err = -EINVAL;
		HIP_ERROR("No localhost public key found\n");
		goto out_err;
	}

	host_id_private = hip_get_host_id(HIP_DB_LOCAL_HID, NULL, HIP_HI_DEFAULT_ALGO);
	if (!host_id_private) {
		err = -EINVAL;
		HIP_ERROR("No localhost private key found\n");
		goto out_err;
	}

	{
		int sigsize;
		
		if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
			sigsize = HIP_RSA_SIGNATURE_LEN;
		} else {
			sigsize = HIP_DSA_SIGNATURE_LEN;
		}

		signature = HIP_MALLOC(sigsize,GFP_KERNEL);
		if (!signature) {
			HIP_ERROR("No memory for signature\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);

	/* create I2 */
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(i2, HIP_I2, mask,
			      &(ctx->input->hitr),
			      &(ctx->input->hits));

	/********** SPI **********/
	/* SPI and LSI are set below where IPsec is set up */
	err = hip_build_param_spi(i2, 0);
	if (err) {
		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
		goto out_err;
	}

	/********** R1 COUNTER (OPTIONAL) ********/
	/* we build this, if we have recorded some value (from previous R1s) */
	{
		uint64_t rtmp;

		HIP_LOCK_HA(entry);
		rtmp = entry->birthday;
		HIP_UNLOCK_HA(entry);

		if (rtmp) {
			err = hip_build_param_r1_counter(i2, rtmp);
			if (err) {
				HIP_ERROR("Could not build R1 GENERATION parameter\n");
				goto out_err;
			}
		}
	}

	/********** SOLUTION **********/
	{
		struct hip_puzzle *pz;

		pz = hip_get_param(ctx->input, HIP_PARAM_PUZZLE);
		if (!pz) {
			HIP_ERROR("Internal error: PUZZLE parameter mysteriously gone\n");
			err = -ENOENT;
			goto out_err;
		}

		err = hip_build_param_solution(i2, pz, ntoh64(solved_puzzle));
		if (err) {
			HIP_ERROR("Building of solution failed (%d)\n", err);
			goto out_err;
		}
	}

	/********** Diffie-Hellman *********/
  	dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN);
	if (!dh_req) {
		err = -ENOENT;
		HIP_ERROR("Internal error\n");
		goto out_err;
	}

	written = hip_insert_dh(dh_data, dh_size, dh_req->group_id);
	if (written < 0) {
		err = -ENOENT;
		HIP_ERROR("Error while extracting DH key\n");
		goto out_err;
	}

	_HIP_HEXDUMP("Own DH key", dh_data, n);

	err = hip_build_param_diffie_hellman_contents(i2,dh_req->group_id,
						      dh_data, written);
	if (err) {
		HIP_ERROR("Building of DH failed (%d)\n", err);
		goto out_err;
	}

        /********** HIP transform. **********/
	param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		goto out_err;
	}

	transform_hip_suite =
		hip_select_hip_transform((struct hip_hip_transform *) param);
	if (transform_hip_suite == 0) {
		HIP_ERROR("Could not find acceptable hip transform suite\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Select only one transform */
	err = hip_build_param_transform(i2, HIP_PARAM_HIP_TRANSFORM,
					&transform_hip_suite, 1);
	if (err) {
		HIP_ERROR("Building of HIP transform failed\n");
		goto out_err;
	}

	/********** ESP-ENC transform. **********/
	param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		goto out_err;
	}

	/* Select only one transform */
	transform_esp_suite =
		hip_select_esp_transform((struct hip_esp_transform *) param);
	if (transform_esp_suite == 0) {
		HIP_ERROR("Could not find acceptable hip transform suite\n");
		goto out_err;
	}
	err = hip_build_param_transform(i2, HIP_PARAM_ESP_TRANSFORM,
					&transform_esp_suite, 1);
	if (err) {
		HIP_ERROR("Building of ESP transform failed\n");
		goto out_err;
	}

	/************ Encrypted ***********/

	switch (transform_hip_suite) {
	case HIP_HIP_AES_SHA1:
 		err = hip_build_param_encrypted_aes_sha1(i2, host_id_pub);
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 16);
 		host_id_in_enc = enc_in_msg +
			sizeof(struct hip_encrypted_aes_sha1);
		break;
	case HIP_HIP_3DES_SHA1:
 		err = hip_build_param_encrypted_3des_sha1(i2, host_id_pub);
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 8);
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_3des_sha1);
		break;
	case HIP_HIP_NULL_SHA1:
 		err = hip_build_param_encrypted_null_sha1(i2, host_id_pub);
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = NULL;
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_null_sha1);
		break;
	default:
 		HIP_ERROR("HIP transform not supported (%d)\n",
 			  transform_hip_suite);
 		err = -ENOSYS;
		break;
	}

 	if (err) {
 		HIP_ERROR("Building of param encrypted failed (%d)\n",
 			  err);
 		goto out_err;
 	}

	HIP_HEXDUMP("enc(host_id)", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));

	/* Calculate the length of the host id inside the encrypted param */
	host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

	/* Adjust the host id length for AES (block size 16).
	   build_param_encrypted_aes has already taken care that there is
	   enough padding */
	if (transform_hip_suite == HIP_HIP_AES_SHA1) {
		int remainder = host_id_in_enc_len % 16;
		if (remainder) {
			HIP_DEBUG("Remainder %d (for AES)\n", remainder);
			host_id_in_enc_len += remainder;
		}
	}

	_HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));
	_HIP_HEXDUMP("encinmsg", enc_in_msg,
		    hip_get_param_total_len(enc_in_msg));
	HIP_HEXDUMP("enc key", &ctx->hip_enc_out.key, HIP_MAX_KEY_LEN);
	_HIP_HEXDUMP("IV", enc_in_msg->iv, 8); // or 16
	HIP_DEBUG("host id type: %d\n",
		  hip_get_host_id_algo((struct hip_host_id *)host_id_in_enc));
 	err = hip_crypto_encrypted(host_id_in_enc, iv,
				   transform_hip_suite,
				   host_id_in_enc_len,
				   &ctx->hip_enc_out.key,
				   HIP_DIRECTION_ENCRYPT);
	if (err) {
		HIP_ERROR("Building of param encrypted failed %d\n", err);
		goto out_err;
	}
	_HIP_HEXDUMP("encinmsg 2", enc_in_msg,
		     hip_get_param_total_len(enc_in_msg));
	_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);

	/* it appears as the crypto function overwrites the IV field, which
	 * definitely breaks our 2.4 responder... Perhaps 2.6 and 2.4 cryptos
	 * are not interoprable or we screw things pretty well in 2.4 :)
	 */

	//memset((u8 *)enc_in_msg->iv, 0, 8);

        /* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */
	{
		int err;

		/* let the setup routine give us a SPI. */
		spi_in = 0;
		err = hip_add_sa(&ctx->input->hits, &ctx->input->hitr,
				 &spi_in, transform_esp_suite, 
				 &ctx->esp_in, &ctx->auth_in, 
				 0, HIP_SPI_DIRECTION_IN);

		if (err) {
			HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
			/* hip_delete_spd/hip_delete_sa ? */
			goto out_err;
		}
		/* XXX: -EAGAIN */
		HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
	}

 	hspi = hip_get_param(i2, HIP_PARAM_SPI);
 	HIP_ASSERT(hspi); /* Builder internal error */
	hspi->spi = htonl(spi_in);

	/* LSI not created, as it is local, and we do not support IPv4 */

#ifdef CONFIG_HIP_RVS
	/************ RVA_REQUEST (OPTIONAL) ***************/
	{
		/* we've requested RVS, and the peer is rvs capable */
		int type = HIP_RVA_RELAY_I1;

		if (!(entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
			goto next_echo_resp;

		if (!(entry->peer_controls & HIP_CONTROL_RVS_CAPABLE))
			goto next_echo_resp;

		err = hip_build_param_rva(i2, 0, &type, 1, 1);
		if (err) {
			HIP_ERROR("Could not build RVA_REQUEST parameter\n");
			goto out_err;
		}
	}
 next_echo_resp:

#endif
	/********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
	/* must reply... */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST_SIGN);
		if (ping) {
			int ln;

			ln = hip_get_param_contents_len(ping);
			err = hip_build_param_echo(i2, ping + 1, ln, 1, 0);
			if (err) {
				HIP_ERROR("Error while creating echo reply parameter\n");
				goto out_err;
			}
		}
	}

	/************* HMAC ************/

	err = hip_build_param_hmac_contents(i2,
					    &ctx->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}

	/********** Signature **********/

        /* Should have been fetched during making of hip_encrypted */
	HIP_ASSERT(host_id_private);

	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */
	if (!hip_create_signature(i2, hip_get_msg_total_len(i2), 
				  host_id_private, signature)) {
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Only DSA supported currently */
//	HIP_ASSERT(hip_get_host_id_algo(host_id_private) == HIP_HI_DSA);

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(i2,signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {
		err = hip_build_param_signature_contents(i2,
							 signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

	if (err) {
		HIP_ERROR("Building of signature failed (%d)\n", err);
		goto out_err;
	}

	/********** ECHO_RESPONSE (OPTIONAL) ************/
	/* must reply */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST);
		if (ping) {
			int ln;

			ln = hip_get_param_contents_len(ping);
			err = hip_build_param_echo(i2, (ping + 1), ln, 0, 0);
			if (err) {
				HIP_ERROR("Error while creating echo reply parameter\n");
				goto out_err;
			}
		}
	}

      	/********** I2 packet complete **********/

	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_ipv6_devaddr2ifindex(r1_daddr);
	HIP_LOCK_HA(entry);
	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
	if (err) {
		HIP_UNLOCK_HA(entry);
		goto out_err;
	}
	entry->esp_transform = transform_esp_suite;
	/* Store the keys until we receive R2 */
	err = hip_store_base_exchange_keys(entry,ctx,1);
	HIP_UNLOCK_HA(entry);

	if (err) {
		HIP_DEBUG("hip_store_base_exchange_keys failed\n");
		goto out_err;
	}

	/* todo: Also store the keys that will be given to ESP later */
	err = hip_hadb_get_peer_addr(entry, &daddr);
	if (err) {
		HIP_DEBUG("hip_sdb_get_peer_address failed, err = %d\n", err);
		goto out_err;
	}

	/* state E1: Receive R1, process. If successful,
	   send I2 and go to E2. */
	err = hip_csum_send(NULL, &daddr, i2); // HANDLER
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("moving to state I2_SENT\n");

 out_err:
	if (signature)
		HIP_FREE(signature);
	if (host_id_private)
		HIP_FREE(host_id_private);
	if (host_id_pub)
		HIP_FREE(host_id_pub);
	if (i2)
		HIP_FREE(i2);
	if (dh_data)
		HIP_FREE(dh_data);

	return err;
}

/**
 * hip_handle_r1 - handle incoming R1 packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: HA
 *
 * This function is the actual point from where the processing of R1
 * is started and corresponding I2 is created.
 *
 * On success (R1 payloads are checked and daemon is called) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r1(struct hip_common *r1,
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry)
{
	int err = 0;
	uint64_t solved_puzzle;

	struct hip_context *ctx = NULL;
	struct hip_host_id *peer_host_id;
	struct hip_r1_counter *r1cntr;
	struct hip_lhi peer_lhi;

	HIP_DEBUG("\n");

	ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		HIP_ERROR("Could not allocate memory for context\n");
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	ctx->input = r1;
	//ctx->skb_in = skb;

	/* according to the section 8.6 of the base draft,
	 * we must first check signature
	 */
	peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID);
 	if (!peer_host_id) {
 		HIP_ERROR("No HOST_ID found in R1\n");
 		err = -ENOENT;
 		goto out_err;
 	}

	err = hip_verify_packet_signature2(r1, peer_host_id);
	if (err) {
 		HIP_ERROR("Verification of R1 signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}

	HIP_DEBUG("SIGNATURE in R1 ok\n");

	/* R1 generation check */

	/* we have problems with creating precreated R1s in reasonable
	   fashion... so we don't mind about generations */
	r1cntr = hip_get_param(r1, HIP_PARAM_R1_COUNTER);
#if 0
	if (r1cntr) {
		err = -EINVAL;
		HIP_LOCK_HA(entry);
		if (entry->state == HIP_STATE_I2_SENT) {
			if (entry->birthday) {
				if (entry->birthday < r1cntr->generation) {
					/* perhaps changing the state should be performed somewhere else. */
					entry->state = HIP_STATE_I1_SENT;
					// SYNCH not needed?
				} else {
					/* dropping due to generation check */
					HIP_UNLOCK_HA(entry);
					HIP_INFO("Dropping R1 due to the generation counter being too small\n");
					goto out_err;
				}
			}
		}
		HIP_UNLOCK_HA(entry);
	}
#endif		
	/* Do control bit stuff here... */

	/* validate HIT against received host id */
	{
		struct in6_addr tmphit;

		hip_host_id_to_hit(peer_host_id, &tmphit,
				   HIP_HIT_TYPE_HASH126);

		if (ipv6_addr_cmp(&tmphit, &r1->hits) != 0) {
			HIP_ERROR("Sender HIT does not match the advertised host_id\n");
			HIP_DEBUG_HIT("received", &r1->hits);
 			HIP_DEBUG_HIT("calculated", &tmphit);
			err = -EINVAL;
			goto out_err;
		}
	}

	/* We must store the R1 generation counter, _IF_ it exists */
	if (r1cntr) {
		HIP_DEBUG("Storing R1 generation counter\n");
		HIP_LOCK_HA(entry);
		entry->birthday = r1cntr->generation;
		HIP_UNLOCK_HA(entry);
	}

	/* solve puzzle */
	{
		struct hip_puzzle *pz;

		pz = hip_get_param(r1, HIP_PARAM_PUZZLE);
		if (!pz) {
			HIP_ERROR("Malformed R1 packet. PUZZLE parameter missing\n");
			err = -EINVAL;
			goto out_err;
		}

		solved_puzzle = hip_solve_puzzle(pz, r1, HIP_SOLVE_PUZZLE);
		if (solved_puzzle == 0) {
			/* we should communicate to lower levels that we need a
			 * retransmission of I1
			 */
			HIP_ERROR("Solving of puzzle failed\n");
			err = -EINVAL;
			goto out_err;
		}
	}

	HIP_DEBUG("Puzzle solved successfully\n");

	/* calculate shared secret and create keying material */
	ctx->dh_shared_key = NULL;
	err = hip_produce_keying_material(r1, ctx);
	if (err) {
		HIP_ERROR("Could not produce keying material\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Everything ok, save host id to db */
	{
		char *str;
		int len;

		if (hip_get_param_host_id_di_type_len(peer_host_id, &str, 
						      &len) < 0)
			goto out_err;
		HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
			  str, len, hip_get_param_host_id_hostname(peer_host_id));
	}

 	peer_lhi.anonymous = 0;
	ipv6_addr_copy(&peer_lhi.hit, &r1->hits);

 	err = hip_add_host_id(HIP_DB_PEER_HID, &peer_lhi, peer_host_id, 
			      NULL, NULL, NULL);
 	if (err == -EEXIST) {
 		HIP_INFO("Host id already exists. Ignoring.\n");
 		err = 0;
 	} else if (err) {
 		HIP_ERROR("Failed to add peer host id to the database\n");
 		goto out_err;
  	}

	entry->peer_controls = ntohs(r1->control);
	
	HIP_DEBUG("R1 Successfully received\n");

 	err = hip_create_i2(ctx, solved_puzzle, r1_saddr, r1_daddr, entry);
 	if (err) {
 		HIP_ERROR("Creation of I2 failed (%d)\n", err);
		goto out_err;
 	}

	HIP_DEBUG("Created I2 successfully\n");

 out_err:
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);
	return err;
}

/**
 * hip_receive_r1 - receive an R1 packet
 * @skb: sk_buff that contains the HIP packet
 *
 * This is the initial function which is called when an R1 packet is
 * received. First we check if we have sent the corresponding I1. If
 * yes, then the received R1 is handled in hip_handle_r1. In
 * established state we also handle the R1. Otherwise the packet is
 * dropped and not handled in any way.
 *
 * Always frees the skb
 */
int hip_receive_r1(struct hip_common *hip_common,
		   struct in6_addr *r1_saddr,
		   struct in6_addr *r1_daddr)
{
	hip_ha_t *entry;
	int state, mask;
	int err = 0;

	HIP_DEBUG("Received R1\n");

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

 	//mask = HIP_CONTROL_CERTIFICATES | HIP_CONTROL_HIT_ANON |
	  //	HIP_CONTROL_RVS_CAPABLE;
	//	mask |= HIP_CONTROL_SHT_MASK | HIP_CONTROL_DHT_MASK; /* test */

	mask = hip_create_control_flags(1, 1, HIP_CONTROL_SHT_ALL,
					HIP_CONTROL_DHT_ALL);
 	if (!hip_controls_sane(ntohs(hip_common->control), mask)) {
		HIP_ERROR("Received illegal controls in R1: 0x%x Dropping\n",
			  ntohs(hip_common->control));
		goto out_drop;
	}

	entry = hip_hadb_find_byhit(&hip_common->hits);
	HIP_DEBUG_HIT("RECEIVE R1 SENDER HIT: ", &hip_common->hits);
	if (!entry) {
		err = -EFAULT;
		HIP_ERROR("Received R1 with no local state. Dropping\n");
		goto out_drop;
	}

	/* An implicit and insecure REA. If sender's address is different than
	 * the one that was mapped, then we will overwrite the mapping with
	 * the newer address.
	 * This enables us to use the rendezvous server, while not supporting
	 * the REA TLV.
	 */

	{
		struct in6_addr daddr;
		
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, r1_saddr) != 0) {
			HIP_DEBUG("Mapped address didn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", r1_saddr, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}
		
	}

	/* since the entry is in the hit-list and since the previous
	 * function increments by one, we must have at least 2 references
	 */
	HIP_ASSERT(atomic_read(&entry->refcnt) >= 2);

	/* I hope wmb() takes care of the locking needs */
	wmb();
	state = entry->state;

	HIP_DEBUG("entry->state is %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
		/* E1. The normal case. Process, send I2, goto E2. */
		err = hip_handle_r1(hip_common, r1_saddr, r1_daddr, entry);
		HIP_LOCK_HA(entry);
		if (err < 0)
			HIP_ERROR("Handling of R1 failed\n");
		else {
			if (state == HIP_STATE_I1_SENT) {
				// SYNCH
				entry->state = HIP_STATE_I2_SENT;
			}
		}
		HIP_UNLOCK_HA(entry);
		break;
	case HIP_STATE_R2_SENT:
		/* E2. Drop and stay. */
		HIP_ERROR("Received R1 in state R2_SENT. Dropping\n");
		break;
	case HIP_STATE_ESTABLISHED:
		HIP_ERROR("Received R1 in state ESTABLISHED. Dropping\n");
 		break;
 	case HIP_STATE_REKEYING:
		HIP_ERROR("Received R1 in state REKEYING. Dropping\n");
		break;
	case HIP_STATE_NONE:
	case HIP_STATE_UNASSOCIATED:
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received in odd state: %d. Dropping.\n", state); 
		break;
	}

	hip_put_ha(entry);
 out_drop:
	return err;
}

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @ctx: Context of processed I2 packet.
 * @entry: HA
 *
 * Returns: 0 on success, < 0 on error.
 */
int hip_create_r2(struct hip_context *ctx,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,
		  hip_ha_t *entry)
{
	uint32_t spi_in;
 	struct hip_host_id *host_id_private = NULL, *host_id_public = NULL;
 	struct hip_common *r2 = NULL;
	struct hip_common *i2;
 	int err = 0;
	int clear = 0;
	u8 *signature;
	uint16_t mask;
#ifdef CONFIG_HIP_RVS
	int create_rva = 0;
#endif

	HIP_DEBUG("\n");

	/* assume already locked entry */
	i2 = ctx->input;

	/* Build and send R2
	   IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
	r2 =  hip_msg_alloc();
	if (!r2) {
		err = -ENOMEM;
		HIP_ERROR("No memory for R2\n");
		goto out_err;
	}

	/* just swap the addresses to use the I2's destination HIT as
	 * the R2's source HIT */
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(r2, HIP_R2, mask,
			      &ctx->input->hitr, &ctx->input->hits);

 	/********** SPI_LSI **********/
	barrier();
	spi_in = hip_hadb_get_latest_inbound_spi(entry);

	err = hip_build_param_spi(r2, spi_in);
 	if (err) {
 		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
 		goto out_err;
	}

#ifdef CONFIG_HIP_RVS
 	/* Do the Rendezvous functionality */
 	{
 		struct hip_rva_request *rreq;
 		int rva_types[4] = {0};
 		int num;
 		uint32_t lifetime;

 		rreq = hip_get_param(i2, HIP_PARAM_RVA_REQUEST);
 		if (!rreq)
 			goto next_hmac;

 		num = hip_select_rva_types(rreq, rva_types, 4);
 		if (!num) {
 			HIP_ERROR("None of the RVA types were accepted. Abandoning connection\n");
 			rva_types[0] = 0;
			num = 1;
 		}

 		lifetime = ntohl(rreq->lifetime) > HIP_DEFAULT_RVA_LIFETIME ? 
			IP_DEFAULT_RVA_LIFETIME : ntohl(rreq->lifetime);

 		err = hip_build_param_rva(r2, lifetime, rva_types, num, 0);
 		if (err) {
 			HIP_ERROR("Building of RVA_REPLY failed\n");
 			goto out_err;
 		}

 		create_rva = 1;
 	}
 next_hmac:
#endif

 	/*********** HMAC2 ************/
	{
		struct hip_crypto_key hmac;

		host_id_public =
			hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO);

		HIP_HEXDUMP("host id for HMAC2", host_id_public,
			    hip_get_param_total_len(host_id_public));

		memcpy(&hmac, &entry->hip_hmac_out, sizeof(hmac));
		err = hip_build_param_hmac2_contents(r2, &hmac,
						     host_id_public);
		if (err) {
			HIP_ERROR("Building of hmac failed (%d)\n", err);
			goto out_err;
		}
	}

	host_id_private = hip_get_host_id(HIP_DB_LOCAL_HID, NULL, HIP_HI_DEFAULT_ALGO);
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	signature = HIP_HI_DEFAULT_ALGO == HIP_HI_RSA ? 
		HIP_MALLOC(HIP_RSA_SIGNATURE_LEN, GFP_KERNEL) : HIP_MALLOC(HIP_DSA_SIGNATURE_LEN, GFP_KERNEL);
	if (!signature) {
		HIP_ERROR("No mem\n");
		err = -ENOMEM;
		goto out_err;
	}
	if (!hip_create_signature(r2, hip_get_msg_total_len(r2),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign R2. Failing\n");
		err = -EINVAL;
		goto out_err;
	}

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(r2, signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {
		err = hip_build_param_signature_contents(r2, signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

 	if (err) {
 		HIP_ERROR("Building of signature failed (%d)\n", err);
 		goto out_err;
 	}

 	/* Send the packet */
	err = hip_csum_send(NULL, i2_saddr, r2); // HANDLER
	
#ifdef CONFIG_HIP_RVS
	// FIXME: Should this be skipped if an error occurs? (tkoponen)
	if (create_rva) {
		HIP_RVA *rva;

		rva = hip_ha_to_rva(entry, GFP_KERNEL);
		if (!rva) {
			/* RVA could not be created... notify the initiator */
			err = -ENOSYS;
			goto out_err;
		}

		err = hip_rva_insert(rva);
		if (err) 
			HIP_ERROR("Error while inserting RVA into hash table\n");
		
		hip_put_rva(rva);
	}
#endif
 out_err:
	if (host_id_public)
		HIP_FREE(host_id_public);
	if (host_id_private)
		HIP_FREE(host_id_private);
	if (r2)
		HIP_FREE(r2);
	if (clear && entry) {/* Hmm, check */
		HIP_ERROR("TODO: about to do hip_put_ha, should this happen here ?\n");
		hip_put_ha(entry);
	}
	return err;
}


/**
 * hip_handle_i2 - handle incoming I2 packet
 * @skb: sk_buff where the HIP packet is in
 * @ha: HIP HA corresponding to the peer
 *
 * This function is the actual point from where the processing of I2
 * is started and corresponding R2 is created.
 *
 * On success (I2 payloads are checked and R2 is created and sent) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_i2(struct hip_common *i2,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,		  
		  hip_ha_t *ha)
{
	int err = 0;
	struct hip_context *ctx = NULL;
 	struct hip_tlv_common *param;
	char *tmp_enc = NULL, *enc = NULL;
	struct hip_host_id *host_id_in_enc = NULL;
	struct hip_r1_counter *r1cntr;
 	struct hip_lhi lhi;
	struct hip_spi *hspi = NULL;
	hip_ha_t *entry = ha;
	hip_transform_suite_t esp_tfm, hip_tfm;
	uint32_t spi_in, spi_out;
	uint16_t crypto_len;
 	char *iv;
 	struct in6_addr hit;
	struct hip_spi_in_item spi_in_data;
 	HIP_DEBUG("\n");

	/* assume already locked ha, if ha is not NULL */

	ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	ctx->input = i2;

	/* Check packet validity */
	/* We MUST check that the responder HIT is one of ours. */
	/* check the generation counter */
	/* We do not support generation counter (our precreated R1s suck) */

	r1cntr = hip_get_param(ctx->input, HIP_PARAM_R1_COUNTER);
#if 0		
	if (!r1cntr) {
		/* policy decision... */
		HIP_DEBUG("No R1 COUNTER in I2. Default policy is to drop the packet\n");
		err = -ENOMSG;
		goto out_err;
	}

	err = hip_verify_generation(i2_saddr, 
				    i2_daddr, 
				    r1cntr->generation);
	if (err) {
		HIP_ERROR("Birthday check failed\n");
		goto out_err;
	}

#endif 

	/* check solution for cookie */
	{
		struct hip_solution *sol;

		sol = hip_get_param(ctx->input, HIP_PARAM_SOLUTION);
		if (!sol) {
			HIP_ERROR("Invalid I2: SOLUTION parameter missing\n");
			err = -EINVAL;
			goto out_err;
		}

		if (!hip_verify_cookie(i2_saddr,
				       i2_daddr, 
				       i2, sol)) {
			HIP_ERROR("Cookie solution rejected\n");
			err = -ENOMSG;
			goto out_err;
		}
	}

	/* Check HIP and ESP transforms, and produce keying material  */
	ctx->dh_shared_key = NULL;
	err = hip_produce_keying_material(ctx->input, ctx);
	if (err) {
		HIP_ERROR("Unable to produce keying material. Dropping I2\n");
		goto out_err;
	}

	/* verify HMAC */
	err = hip_verify_packet_hmac(i2, &ctx->hip_hmac_in);
	if (err) {
		HIP_ERROR("HMAC validation on r1 failed\n");
		err = -ENOENT;
		goto out_err;
	}
	
	/* decrypt the HOST_ID and verify it against the sender HIT */
	enc = hip_get_param(ctx->input, HIP_PARAM_ENCRYPTED);
	if (!enc) {
		err = -ENOENT;
		HIP_ERROR("Could not find enc parameter\n");
		goto out_err;
	}

	tmp_enc = HIP_MALLOC(hip_get_param_total_len(enc), GFP_KERNEL);
	if (!tmp_enc) {
		HIP_ERROR("No memory for temporary host_id\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* little workaround...
	 * We have a function that calculates sha1 digest and then verifies the
	 * signature. But since the sha1 digest in I2 must be calculated over
	 * the encrypted data, and the signature requires that the encrypted
	 * data to be decrypted (it contains peer's host identity),
	 * we are forced to do some temporary copying...
	 * If ultimate speed is required, then calculate the digest here as
	 * usual and feed it to signature verifier. 
	 */

	memcpy(tmp_enc, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/
	_HIP_HEXDUMP("Recv. Key", &ctx->hip_enc_in.key, 24);
	param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		HIP_ERROR("Did not find HIP transform\n");
		goto out_err;
	}

	hip_tfm = hip_get_param_transform_suite_id(param, 0);
 	if (hip_tfm == 0) {
		HIP_ERROR("Bad HIP transform\n");
 		err = -EFAULT;
 		goto out_err;
 	}

	switch (hip_tfm) {
	case HIP_HIP_AES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
 		iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 16 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
		HIP_DEBUG("aes crypto len: %d", crypto_len);
		break;
	case HIP_HIP_3DES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
 		iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 8 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
		break;
	case HIP_HIP_NULL_SHA1:
		host_id_in_enc = (struct hip_host_id *)
			(tmp_enc + sizeof(struct hip_encrypted_null_sha1));
 		iv = NULL;
 		/* 4 = reserved */
 		crypto_len = hip_get_param_contents_len(enc) - 4;
		break;
	default:
		HIP_ERROR("Unknown HIP transform: %d\n", hip_tfm);
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("\n");
	err = hip_crypto_encrypted(host_id_in_enc, iv, hip_tfm,
 				   crypto_len, &ctx->hip_enc_in.key,
 				   HIP_DIRECTION_DECRYPT);
	if (err) {
		err = -EINVAL;
		HIP_ERROR("Decryption of Host ID failed\n");
		goto out_err;
	}

	if (hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID) {
		err = -EINVAL;
		HIP_ERROR("The decrypted parameter is not a host id\n");
		goto out_err;
	}

	HIP_HEXDUMP("Decrypted HOST_ID", host_id_in_enc,
		     hip_get_param_total_len(host_id_in_enc));

	/* Verify sender HIT */
 	if (hip_host_id_to_hit(host_id_in_enc, &hit,
			       HIP_HIT_TYPE_HASH126)) {
 		HIP_ERROR("Unable to verify sender's HOST_ID\n");
 		err = -1;
 		goto out_err;
 	}
 	
 	if (ipv6_addr_cmp(&hit, &i2->hits) != 0) {
 		HIP_ERROR("Sender's HIT does not match advertised public key\n");
 		err = -EINVAL;
 		goto out_err;
	}

	/* HMAC cannot be validated until we draw key material */

	/* NOTE! The original packet has the data still encrypted. But this is
	 * not a problem, since we have decrypted the data into a temporary
	 * storage and nobody uses the data in the original packet.
	 */

	/* validate signature */

	// XX CHECK: is the host_id_in_enc correct??! it points to the temp
	err = hip_verify_packet_signature(ctx->input, host_id_in_enc);
	if (err) {
		HIP_ERROR("Verification of I2 signature failed\n");
		err = -EINVAL;
		goto out_err;
	}
	_HIP_DEBUG("SIGNATURE in I2 ok\n");

	/* do the rest */
  	/* Add peer's host id to peer_id database (is there need to
  	   do this?) */
	{
		char *str;
		int len;

		if (hip_get_param_host_id_di_type_len(host_id_in_enc, &str,
						      &len) < 0)
			goto out_err;

		HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
			  str, len, hip_get_param_host_id_hostname(host_id_in_enc));
	}

 	lhi.anonymous = 0;
	ipv6_addr_copy(&lhi.hit, &ctx->input->hits);

 	err = hip_add_host_id(HIP_DB_PEER_HID, &lhi, host_id_in_enc, 
			      NULL, NULL, NULL);
 	if (err == -EEXIST) {
 		err = 0;
 		HIP_INFO("Host id already exists. Ignoring.\n");
 	} else if (err) {
 		HIP_ERROR("Could not store peer's identity\n");
 		goto out_err;
  	}

	/* Create state (if not previously done) */
	if (!entry) {
		/* we have no previous infomation on the peer, create
		 * a new HIP HA */
		entry = hip_hadb_create_state(GFP_KERNEL);
		if (!entry) {
			HIP_ERROR("Failed to create or find entry\n");
			err = -ENOMSG;
			goto out_err;
		}

		/* the rest of the code assume already locked entry,
		 * so lock the newly created entry as well */
		HIP_LOCK_HA(entry);

		ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		ipv6_addr_copy(&entry->hit_our, &i2->hitr);
		HIP_DEBUG("Inserting state\n");
		hip_hadb_insert_state(entry);
		hip_hold_ha(entry);
		/* entry unlock is done below, ok ? */
	}

	/* If we have old SAs with these HITs delete them */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);

	{
		struct hip_esp_transform *esp_tf;
		struct hip_spi_out_item spi_out_data;

		esp_tf = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM);
		if (!esp_tf) {
			err = -ENOENT;
			HIP_ERROR("Did not find ESP transform on i2\n");
			goto out_err;
		}

		hspi = hip_get_param(ctx->input, HIP_PARAM_SPI);
		if (!hspi) {
			err = -ENOENT;
			HIP_ERROR("Did not find SPI LSI on i2\n");
			goto out_err;
		}

		if (r1cntr)
			entry->birthday = r1cntr->generation;
		entry->peer_controls |= ntohs(i2->control);
		ipv6_addr_copy(&entry->hit_our, &i2->hitr);
		ipv6_addr_copy(&entry->hit_peer, &i2->hits);

		/* move this below setup_sa */
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(hspi->spi);
		err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
				       &spi_out_data);
		if (err) {
			goto out_err;
		}
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		esp_tfm = entry->esp_transform;
		if (esp_tfm == 0) {
			HIP_ERROR("Could not select proper ESP transform\n");
			goto out_err;
		}
	}

	err = hip_hadb_add_peer_addr(entry, i2_saddr,
				     0, 0, PEER_ADDR_STATE_ACTIVE);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		goto out_err;
	}

	/* Set up IPsec associations */
	spi_in = 0;
	err = hip_add_sa(&i2->hits, &i2->hitr, &spi_in, esp_tfm, 
			 &ctx->esp_in, &ctx->auth_in, 0,
			 HIP_SPI_DIRECTION_IN);
	
	if (err) {
		HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
		if (err == -EEXIST)
			HIP_ERROR("SA for SPI 0x%x already exists, this is perhaps a bug\n",
				  spi_in);
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}
	/* XXX: Check -EAGAIN */
	
	/* ok, found an unused SPI to use */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
		
	barrier();
	spi_out = ntohl(hspi->spi);
	HIP_DEBUG("setting up outbound IPsec SA, SPI=0x%x\n", spi_out);
	err = hip_add_sa(&i2->hitr, &i2->hits, &spi_out, esp_tfm, 
			 &ctx->esp_out, &ctx->auth_out, 0,
			 HIP_SPI_DIRECTION_OUT);
	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_out);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	} else if (err) {
		HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:dst (err=%d)\n", err);
		/* delete all IPsec related SPD/SA for this entry */
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}
	/* XXX: Check if err = -EAGAIN... */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x\n", spi_out);

	/* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	err = hip_hadb_add_addr_to_spi(entry, spi_out, i2_saddr, 1, 0, 1);
	_HIP_DEBUG("add spi err ret=%d\n", err);
	if (err) {
		HIP_ERROR("failed to add an address to SPI list\n");
		goto out_err;
	}

	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_ipv6_devaddr2ifindex(i2_daddr);
	if (spi_in_data.ifindex) {
		HIP_DEBUG("ifindex=%d\n", spi_in_data.ifindex);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");

	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
	if (err) {
		HIP_UNLOCK_HA(entry);
		goto out_err;
	}

	entry->default_spi_out = spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_out);

	err = hip_store_base_exchange_keys(entry, ctx, 0);
	if (err) {
		HIP_DEBUG("hip_store_base_exchange_keys failed\n");
		goto out_err;
	}

	HIP_DEBUG("Inserting state\n");
	hip_hadb_insert_state(entry);

	err = hip_create_r2(ctx, i2_saddr, i2_daddr, entry);
	HIP_DEBUG("hip_create_r2 returned %d\n", err);
	if (err) {
		HIP_ERROR("Creation of R2 failed\n");
		goto out_err;
	}

	/* change SA state from ACQ -> VALID, and wake up sleepers */
	hip_finalize_sa(&i2->hits, spi_out);
	hip_finalize_sa(&i2->hitr, spi_in);

	/* we cannot do this outside (in hip_receive_i2) since we don't have
	   the entry there and looking it up there would be unneccesary waste
	   of cycles */
	if (!ha && entry) {
		wmb();
#ifdef CONFIG_HIP_RVS
		/* XX FIX: this should be dynamic (the rvs information should
		   be stored in the HADB) instead of static */
		// SYNCH
		entry->state = HIP_STATE_ESTABLISHED;
#else
		// SYNCH
		entry->state = HIP_STATE_R2_SENT;
#endif /* CONFIG_HIP_RVS */
	}

	HIP_DEBUG("Reached %s state\n", hip_state_str(entry->state));

 out_err:
	/* ha is not NULL if hip_receive_i2() fetched the HA for us.
	 * In that case we must not release our reference to it.
	 * Otherwise, if 'ha' is NULL, then we created the HIP HA in this
	 * function and we should free the reference.
	 */
	if (!ha && entry) {
		/* unlock the entry created in this function */
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	if (tmp_enc)
		HIP_FREE(tmp_enc);
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);

	return err;
}

/**
 * hip_receive_i2 - receive I2 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an I2 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_i2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_i2(struct hip_common *i2,
		   struct in6_addr *i2_saddr,
		   struct in6_addr *i2_daddr)
{
	int state = 0;
	int err = 0;
	hip_ha_t *entry;
	uint16_t mask;

	HIP_DEBUG("\n");

	if (ipv6_addr_any(&i2->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in I2. Dropping\n");
		goto out;
	}

	mask = hip_create_control_flags(1, 1, HIP_CONTROL_SHT_ALL,
					HIP_CONTROL_DHT_ALL);
	if (!hip_controls_sane(ntohs(i2->control), mask
			       //HIP_CONTROL_CERTIFICATES | HIP_CONTROL_HIT_ANON |
			       //HIP_CONTROL_RVS_CAPABLE
			       // | HIP_CONTROL_SHT_MASK | HIP_CONTROL_DHT_MASK)) {
		               )) {
		HIP_ERROR("Received illegal controls in I2: 0x%x. Dropping\n",
			  ntohs(i2->control));
		goto out;
	}

	entry = hip_hadb_find_byhit(&i2->hits);
	if (!entry) {
		state = HIP_STATE_UNASSOCIATED;
	} else {
		barrier();
		HIP_LOCK_HA(entry);
		state = entry->state;
	}

 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
		/* possibly no state created yet */
		err = hip_handle_i2(i2, i2_saddr, i2_daddr, NULL);
		break;
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_R2_SENT:
 		err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry);
		if (!err) {
			// SYNCH
			entry->state = HIP_STATE_R2_SENT;
		}
 		break;
 	case HIP_STATE_ESTABLISHED:
 		HIP_DEBUG("Received I2 in state ESTABLISHED\n");
 		err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry);
		if (!err) {
			// SYNCH
			entry->state = HIP_STATE_R2_SENT;
		}
 		break;
 	case HIP_STATE_REKEYING:
		HIP_DEBUG("Received I2 in state REKEYING\n");
 		err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry);
		if (!err) {
			entry->state = HIP_STATE_R2_SENT;
			// SYNCH
		}
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
 out:
	return err;
}


/**
 * hip_handle_r2 - handle incoming R2 packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: HA
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(struct hip_common *r2,
		  struct in6_addr *r2_saddr,
		  struct in6_addr *r2_daddr,
		  hip_ha_t *entry)
{
	uint16_t len;
	struct hip_context *ctx = NULL;
	struct in6_addr *sender;
 	struct hip_host_id *peer_id = NULL;
 	struct hip_lhi peer_lhi;
 	struct hip_spi *hspi = NULL;
 	struct hip_sig *sig = NULL;
	struct hip_spi_out_item spi_out_data;
	int tfm, err = 0;
	uint32_t spi_recvd, spi_in;

	/* assume already locked entry */
	HIP_DEBUG("Entering handle_r2\n");

	ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_ATOMIC);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));
        ctx->input = r2;

	sender = &r2->hits;

 	peer_lhi.anonymous = 0;
 	ipv6_addr_copy(&peer_lhi.hit, &r2->hits);

 	peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi, HIP_ANY_ALGO);
 	if (!peer_id) {
 		HIP_ERROR("Unknown peer (no identity found)\n");
 		err = -EINVAL;
 		goto out_err;
 	}

        /* verify HMAC */
	err = hip_verify_packet_hmac2(r2, &entry->hip_hmac_in, peer_id);
	if (err) {
		HIP_ERROR("HMAC validation on R2 failed\n");
		goto out_err;
	}
	_HIP_DUMP_MSG(r2);

	/* signature validation */
 	sig = hip_get_param(r2, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
		HIP_ERROR("No signature found\n");
 		goto out_err;
 	}

	HIP_DUMP_MSG(r2);

 	hip_zero_msg_checksum(r2);
 	len = (u8*) sig - (u8*) r2;
 	hip_set_msg_total_len(r2, len);

 	if (!hip_verify_signature(r2, len, peer_id,
 				  (u8*)(sig + 1))) {
 		HIP_ERROR("R2 signature verification failed\n");
 		err = -EINVAL;
 		goto out_err;
 	}

        /* The rest */
 	hspi = hip_get_param(r2, HIP_PARAM_SPI);
 	if (!hspi) {
		HIP_ERROR("Parameter SPI not found\n");
 		err = -EINVAL;
 		goto out_err;
 	}

	spi_recvd = ntohl(hspi->spi);
	memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
	spi_out_data.spi = spi_recvd;
	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data);
	if (err) {
		goto out_err;
	}
	memcpy(&ctx->esp_out, &entry->esp_out, sizeof(ctx->esp_out));
	memcpy(&ctx->auth_out, &entry->auth_out, sizeof(ctx->auth_out));
	HIP_DEBUG("entry should have only one spi_in now, test\n");
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	tfm = entry->esp_transform;

	err = hip_add_sa(&r2->hitr, sender, &spi_recvd, tfm,
			 &ctx->esp_out, &ctx->auth_out, 0,
			 HIP_SPI_DIRECTION_OUT);
	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_recvd);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	} else 	if (err) {
		HIP_ERROR("hip_add_sa failed, peer:dst (err=%d)\n", err);
		HIP_ERROR("** TODO: remove inbound IPsec SA**\n");
	}
	/* XXX: Check for -EAGAIN */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x (host)\n", spi_recvd);

	/* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	err = hip_hadb_add_addr_to_spi(entry, spi_recvd, r2_saddr,
				       1, 0, 1);
	if (err)
		HIP_ERROR("hip_hadb_add_addr_to_spi err=%d not handled\n", err);
	entry->default_spi_out = spi_recvd;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_recvd);
	_HIP_DEBUG("add spi err ret=%d\n", err);

	err = hip_ipv6_devaddr2ifindex(r2_daddr);
	if (err != 0) {
		HIP_DEBUG("ifindex=%d\n", err);
		hip_hadb_set_spi_ifindex(entry, spi_in, err);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");
	err = 0;

	HIP_DEBUG("clearing the address used during the bex\n");
	ipv6_addr_copy(&entry->bex_address, &in6addr_any);

	hip_hadb_insert_state(entry);
	/* these will change SAs' state from ACQUIRE to VALID, and
	 * wake up any transport sockets waiting for a SA */
	hip_finalize_sa(&r2->hits, spi_recvd);
	hip_finalize_sa(&r2->hitr, spi_in);

 out_err:
	if (peer_id)
		HIP_FREE(peer_id);
	if (ctx)
		HIP_FREE(ctx);
	return err;
}

int hip_handle_i1(struct hip_common *i1,
		  struct in6_addr *i1_saddr,
		  struct in6_addr *i1_daddr,
		  hip_ha_t *entry)
{
	int err;
#ifdef CONFIG_HIP_RVS
  	struct hip_from *from;
#endif
	struct in6_addr *dst;
	struct in6_addr *dstip;

	dst = &i1->hits;
	dstip = NULL;

#ifdef CONFIG_HIP_RVS
	from = hip_get_param(i1, HIP_PARAM_FROM);
	if (from) {
		HIP_DEBUG("Found FROM parameter in I1\n");
		dstip = (struct in6_addr *)&from->address;
		if (entry) {
			struct in6_addr daddr;
			
			/* The entry contains wrong address mapping...
			   instead of the real IP, it has RVS's IP.
			   The RVS should probably be saved into the entry.
			   We need the RVS's IP in double-jump case.
			*/
			hip_hadb_get_peer_addr(entry, &daddr);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, dst, 0, 0, PEER_ADDR_STATE_ACTIVE);
		}
	} else {
		HIP_DEBUG("Didn't find FROM parameter in I1\n");
	}
#endif

	err = hip_xmit_r1(i1_saddr, i1_daddr, dstip, dst);
	return err;
}


/**
 * hip_receive_i1 - receive I1 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an I1 packet is
 * received. If we are in correct state we reply with an R1 packet.
 *
 * This function never writes into hip_sdb_state entries.
 *
 * Returns: zero on success, or negative error value on error.
 */
int hip_receive_i1(struct hip_common *hip_i1,
		   struct in6_addr *i1_saddr,
		   struct in6_addr *i1_daddr)
{
	int err = 0, state, mask;
	hip_ha_t *entry;
#ifdef CONFIG_HIP_RVS
 	HIP_RVA *rva;
#endif
	HIP_DEBUG("\n");

	if (ipv6_addr_any(&hip_i1->hitr)) {
		HIP_ERROR("Received NULL receiver HIT. Opportunistic HIP is not supported yet in I1. Dropping\n");
		err = -EPROTONOSUPPORT;
		goto out;
	}

	/* we support checking whether we are rvs capable even with RVS support not enabled */
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_ALL,
					HIP_CONTROL_DHT_ALL);
 	if (!hip_controls_sane(ntohs(hip_i1->control), mask)) {
 		HIP_ERROR("Received illegal controls in I1: 0x%x. Dropping\n",
 			  ntohs(hip_i1->control));
		goto out;
	}

	entry = hip_hadb_find_byhit(&hip_i1->hits);
	if (entry) {
		wmb();
		state = entry->state;
		hip_put_ha(entry);
	} else {
#ifdef CONFIG_HIP_RVS
 		HIP_DEBUG("Doing RVA check\n");
 		rva = hip_rva_find_valid(&hip_i1->hitr);
 		if (rva) {
 			/* we should now relay the I1.
 			   We have two options: Rewrite destination address or
 			   rewrite both destination and source addresses.
 			   We'll try to do the former if the destination is in the
 			   same subnet, and we'll fall back to the latter in other
 			   cases.
 			*/

 			err = hip_relay_i1(hip_i1, i1_saddr, i1_daddr, rva);
 			if (err)
 				HIP_ERROR("Relaying I1 failed\n");
 			else
 				HIP_DEBUG("Relayed I1\n");
 			return err;
 		}
#endif
		state = HIP_STATE_NONE;
	}

	HIP_DEBUG("HIP_LOCK_HA ?\n");
	HIP_DEBUG("Received I1 in state %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_NONE:
		/* entry == NULL */
	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_R2_SENT:
	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_REKEYING:
		err = hip_handle_i1(hip_i1, i1_saddr, i1_daddr, entry);
		break;
	default:
		/* should not happen */
		HIP_ERROR("DEFAULT CASE, UNIMPLEMENTED STATE HANDLING OR A BUG\n");
		err = -EINVAL;
		break;
	}

	HIP_DEBUG("HIP_UNLOCK_HA ?\n");

 out:
	return err;
}

/**
 * hip_receive_r2 - receive R2 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * Returns: 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_r2(struct hip_common *hip_common,
		   struct in6_addr *r2_saddr,
		   struct in6_addr *r2_daddr)
{
	hip_ha_t *entry = NULL;
	int err = 0;
	int state;
	uint16_t mask;

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in R2. Dropping\n");
		goto out_err;
	}

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_ALL,
					HIP_CONTROL_DHT_ALL);
	if (!hip_controls_sane(ntohs(hip_common->control), mask
			       //HIP_CONTROL_NONE | HIP_CONTROL_RVS_CAPABLE
			       //| HIP_CONTROL_SHT_MASK | HIP_CONTROL_DHT_MASK))
			       ))
	{
		HIP_ERROR("Received illegal controls in R2: 0x%x. Dropping\n", ntohs(hip_common->control));
		goto out_err;
	}

	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		HIP_ERROR("Received R2 by unknown sender\n");
		//HIP_PRINT_HIT("Sender", &hip_common->hits);
		err = -EFAULT;
		goto out_err;
	}
	HIP_LOCK_HA(entry);

	state = entry->state;

	HIP_DEBUG("Received R2 in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_I2_SENT:
 		/* The usual case. */
 		err = hip_handle_r2(hip_common, r2_saddr, r2_daddr, entry);
		if (!err) {
			entry->state = HIP_STATE_ESTABLISHED;
			// SYNCH
			HIP_DEBUG("Reached ESTABLISHED state\n");
		} else {
			HIP_ERROR("hip_handle_r2 failed (err=%d)\n", err);
 		}
 		break;

	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
 	case HIP_STATE_REKEYING:
	case HIP_STATE_UNASSOCIATED:
 	case HIP_STATE_I1_SENT:
 	default:
 		HIP_ERROR("Dropping\n");
 		err = -EFAULT;
 		break;
 	}

 out_err:
	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}


/**
 * hip_receive_notify - receive NOTIFY packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an NOTIFY packet is
 * received.
 *
 * Returns: 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_notify(struct hip_common *hip_common,
		       struct in6_addr *notify_saddr,
		       struct in6_addr *notity_daddr)
{
	hip_ha_t *entry = NULL;
	int err = 0;
	struct hip_notify *notify_param;
	uint16_t mask;

	HIP_HEXDUMP("Incoming NOTIFY", hip_common,
		    hip_get_msg_total_len(hip_common));

	mask = hip_create_control_flags(1, 1, HIP_CONTROL_SHT_ALL,
					HIP_CONTROL_DHT_ALL);
	if (!hip_controls_sane(ntohs(hip_common->control), mask)) {
		HIP_ERROR("Received illegal controls in NOTIFY: 0x%x. Dropping\n",
			  ntohs(hip_common->control));
		goto out_err;
	}

	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		HIP_ERROR("Received NOTIFY by unknown sender\n");
		err = -EFAULT;
		goto out_err;
	}
	/* lock here */
	/* todo: check state */

	/* while (notify_param = hip_get_nth_param(msg, HIP_PARAM_NOTIFY, i)) { .. */

	notify_param = hip_get_param(hip_common, HIP_PARAM_NOTIFY);
	if (notify_param) {
		HIP_DEBUG("NOTIFY parameter:\n");
		HIP_DEBUG(" msgtype=%u\n", ntohs(notify_param->msgtype));
	}

 out_err:
	if (entry) {
		/* unlock here */
		hip_put_ha(entry);
	}
	return err;
}

/**
 * hip_handle_bos - handle incoming BOS packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: HA
 *
 * This function is the actual point from where the processing of BOS
 * is started.
 *
 * On success (BOS payloads are checked) 0 is returned, otherwise < 0.
 */
int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry)
{
	int err = 0;
	struct hip_host_id *peer_host_id;
	struct hip_lhi peer_lhi;
	struct in6_addr peer_hit;
	char *str;
	int len;
  	//struct ipv6hdr *ip6hdr;
	struct in6_addr *dstip;
	char src[INET6_ADDRSTRLEN];

	HIP_DEBUG("\n");

	/* according to the section 8.6 of the base draft,
	 * we must first check signature
	 */

	peer_host_id = hip_get_param(bos, HIP_PARAM_HOST_ID);
 	if (!peer_host_id) {
 		HIP_ERROR("No HOST_ID found in BOS\n");
 		err = -ENOENT;
 		goto out_err;
 	}

	err = hip_verify_packet_signature(bos, peer_host_id);
	if (err) {
 		HIP_ERROR("Verification of BOS signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}

	HIP_DEBUG("SIGNATURE in BOS ok\n");

	/* validate HIT against received host id */	
	hip_host_id_to_hit(peer_host_id, &peer_hit, HIP_HIT_TYPE_HASH126);

	if (ipv6_addr_cmp(&peer_hit, &bos->hits) != 0) {
	        HIP_ERROR("Sender HIT does not match the advertised host_id\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Everything ok, first save host id to db */
	if (hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0)
	        goto out_err;
	HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
		  str, len, hip_get_param_host_id_hostname(peer_host_id));

 	peer_lhi.anonymous = 0;
	ipv6_addr_copy(&peer_lhi.hit, &bos->hits);
 	
 	err = hip_add_host_id(HIP_DB_PEER_HID, &peer_lhi, peer_host_id,
			      NULL, NULL, NULL);
 	if (err == -EEXIST) {
 		HIP_INFO("Host ID already exists. Ignoring.\n");
 		err = 0;
 	} else if (err) {
 		HIP_ERROR("Failed to add peer host id to the database\n");
 		goto out_err;
  	}

	/* Now save the peer IP address */
	dstip = bos_saddr;
	hip_in6_ntop(dstip, src);
	HIP_DEBUG("BOS sender IP: saddr %s\n", src);

	if (entry) {
		struct in6_addr daddr;

		HIP_DEBUG("I guess we should not even get here ..\n");

		/* The entry may contain the wrong address mapping... */
		HIP_DEBUG("Updating existing entry\n");
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, dstip) != 0) {
			HIP_DEBUG("Mapped address doesn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", dstip, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			HIP_ERROR("assuming we are doing base exchange\n");
			hip_hadb_add_peer_addr(entry, dstip, 0, 0, 0);
		}
	} else {
		struct hip_work_order * hwo;
		HIP_DEBUG("Adding new peer entry\n");
                hip_in6_ntop(&bos->hits, src);
		HIP_DEBUG("map HIT: %s\n", src);
		hip_in6_ntop(dstip, src);
		HIP_DEBUG("map IP: %s\n", src);

		hwo = hip_init_job(GFP_ATOMIC);
		if (!hwo) {
		        HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
			goto out_err;
		}			   

		HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG, HIP_WO_SUBTYPE_ADDMAP, dstip, &bos->hits, 0, 0);
		hip_insert_work_order(hwo);
	}

	HIP_INFO("BOS Successfully received\n");
 	
 out_err:
	return err;
}

/**
 * hip_receive_bos - receive BOS packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This function is called when a BOS packet is received. We add the
 * received HIT and HOST_ID to the database.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr)
{
	int err = 0;
	hip_ha_t *entry;
	int state = 0;

	HIP_DEBUG("\n");

	if (ipv6_addr_any(&bos->hits)) {
		HIP_ERROR("Received NULL sender HIT in BOS. Dropping\n");
		goto out;
	}

	if (!ipv6_addr_any(&bos->hitr)) {
		HIP_ERROR("Received non-NULL receiver HIT in BOS. Dropping\n");
		goto out;
	}

	entry = hip_hadb_find_byhit(&bos->hits);
	if (!entry) {
		state = HIP_STATE_UNASSOCIATED;
	} else {
		/* Received BOS packet from already known sender */
		/* TODO: should return right now */
		state = entry->state;
	}
	HIP_DEBUG("Received BOS packet in state %s\n", hip_state_str(state));

	if (entry)
		HIP_DEBUG("---LOCKING---\n");

 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
		/* possibly no state created yet */
		err = hip_handle_bos(bos, bos_saddr, bos_daddr, entry);
		break;
	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
 	case HIP_STATE_REKEYING:
		HIP_DEBUG("BOS not handled in state %s\n",
			  hip_state_str(state));
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

	if (entry) {
		HIP_DEBUG("---UNLOCKING---\n");
		hip_put_ha(entry);
	}
 out:
	return err;
}


/**
 * hip_verify_hmac - verify HMAC
 * @buffer: the packet data used in HMAC calculation
 * @hmac: the HMAC to be verified
 * @hmac_key: integrity key used with HMAC
 * @hmac_type: type of the HMAC digest algorithm.
 *
 * Returns: 0 if calculated HMAC is same as @hmac, otherwise < 0. On
 * error < 0 is returned.
 *
 * FIX THE PACKET LEN BEFORE CALLING THIS FUNCTION
 */
static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac,
			   void *hmac_key, int hmac_type)
{
	int err = 0;
	u8 *hmac_res = NULL;

	hmac_res = HIP_MALLOC(HIP_AH_SHA_LEN, GFP_ATOMIC);
	if (!hmac_res) {
		HIP_ERROR("HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	_HIP_HEXDUMP("HMAC data", buffer, hip_get_msg_total_len(buffer));

	if (!hip_write_hmac(hmac_type, hmac_key, buffer,
			    hip_get_msg_total_len(buffer), hmac_res)) {
		HIP_ERROR("Could not build hmac\n");
		err = -EINVAL;
		goto out_err;
	}

	_HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);

	if (memcmp(hmac_res, hmac, HIP_AH_SHA_LEN) != 0) {
		HIP_DEBUG("invalid HMAC\n");
		err = -EINVAL;
		goto out_err;
	}

 out_err:
	if (hmac_res)
		HIP_FREE(hmac_res);

	return err;
}

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
