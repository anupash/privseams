/*
 * HIP input
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 * TODO:
 * - hip_inbound: the state should be changed in hip_inbound, not in the
 *   functions that are called from hip_inbound!
 * - If a function returns a value, we MUST NOT ignore it
 * - hip_handle_i2_finish_sig, hip_handle_r2_finish: check return values of
 *   hip_setup_esp
 * - make null-cipher optional, so that the module can be loaded without it
 * - decrypt encrypted field in handle_i2
 * - check buffer overflow (ctx->htpr) issues in building of R1
 * - convert building of r1 to use only builder functions
 * - later on everything should be built/parsed using builder
 * - No hip packets should be sent or received before autosetup
 *   is finished:
 *     if (hipd_get_auto_setup_state() != HIPD_AUTO_SETUP_STATE_FINISHED)
 *       fail_somehow();
 * - verify signatures in base exchange handlers
 * - separate the tlv checking code into an own function from handle_r1?
 * - LOCKING TO REA
 * - AC/ACR: more accurate RTT timing than jiffies ?
 * - cancel sent rea timer when ACR is received
 * - IPsec code (find SPi, try to add an SA, check for errors) is copypaste
 *   code
 *
 * BUGS:
 * - possible kernel panic if module is rmmod'd and REA timer
 *   expires after that
 * - It should be signalled somehow when building of R1 is 100 %
 *   complete. Otherwise an incomplete packet could be sent for
 *   the initiator?
 * - handle_i2 trusts the source HIT in the received I2 packet: DoS?
 * - the functions in this file probably leak memory (skbs?)
 *
 */

#include "input.h"

#ifdef MAX
#undef MAX
#endif

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac, 
			   void *hmac_key, int hmac_type);

spinlock_t hip_sent_rea_info_lock = SPIN_LOCK_UNLOCKED;
spinlock_t hip_sent_ac_info_lock = SPIN_LOCK_UNLOCKED;

atomic_t hip_rea_ac_id = ATOMIC_INIT(0);
spinlock_t hip_rea_ac_id_lock = SPIN_LOCK_UNLOCKED;

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
 * Returns 1 is there are no illegal control values in @controls,
 * otherwise 0.
 */
int hip_controls_sane(u16 controls, u16 legal)
{
	u16 known;

	known = controls & 
		(HIP_CONTROL_PIGGYBACK_ALLOW |
		 HIP_CONTROL_CERTIFICATES |
		 HIP_CONTROL_ESP_64 |
		 HIP_CONTROL_HIT_ANON);

	if ((known | legal) != legal)
		return 0;

	return 1;
}

/**
 * hip_is_supported_tlv - check if implementation supports handling of given TLV
 * @tlv: TLV to be checked
 *
 * Returns 1 current implementation knows how to handle the TLV @tlv,
 * otherwise 0.
 */
int hip_is_supported_tlv(hip_tlv_type_t tlv)
{


	return 0;
}

/**
 * hip_handle_esp - handle incoming ESP packet
 * @hdr: IPv6 header of the packet
 *
 * If the packet's SPI belongs to a HIP connection, the IPv6 addresses
 * are replaced with the corresponding HITs before the packet is
 * delivered to ESP.
 */
void hip_handle_esp(struct ipv6hdr *hdr)
{
	u32 spi;
	int tlist[2];
	int k;

	if (hdr->nexthdr == IPPROTO_ESP) {
		spi = ntohl(((struct ipv6_esp_hdr*) (hdr+1))->spi);

		tlist[0] = HIP_HADB_OWN_HIT;
		tlist[1] = HIP_HADB_PEER_HIT;

		k = hip_hadb_multiget((void *)spi,tlist,2,&hdr->daddr,&hdr->saddr,
				      NULL,NULL,HIP_ARG_SPI);
		if (k < 2) {
			HIP_DEBUG("Could not copy HITs\n");
			return;
		}
	}
	return;
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

	/* this has to be modified so that other signature algorithms
	   are accepted
	*/

	if (host_id->algorithm != 3) {
		HIP_ERROR("Unsupported algorithm:%d\n", host_id->algorithm);
		goto out_err;
	}


	_HIP_HEXDUMP("Signature data (create)", buffer_start, buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1, buffer_start, buffer_length,
			     sha1_digest) < 0)
	{
		HIP_ERROR("Building of SHA1 digest failed\n");
		goto out_err;
	}

	_HIP_HEXDUMP("create digest", sha1_digest, HIP_AH_SHA_LEN);

	_HIP_HEXDUMP("dsa key", (u8 *)(host_id + 1), hip_get_param_contents_len(host_id) - 4);

	err = hip_dsa_sign(sha1_digest,(u8 *)(host_id + 1),signature);
	if (err) {
		HIP_ERROR("DSA Signing error\n");
		return 0;
	}

	_HIP_HEXDUMP("signature",signature,42);

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
 * @host_id: Pointer to either HOST_ID or HOST_ID_FQDN (as specified by the HIP
 *           draft).
 * @signature: Pointer to the signature
 *
 * Returns true (1) if ok, false (0) otherwise.
 */
int hip_verify_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature)
{
	u8 *public_key = (u8 *) (host_id + 1);
	int tmp, err;
	unsigned char sha1_digest[HIP_AH_SHA_LEN];
	size_t public_key_len;

	err = 0;

	/* check for all algorithms */

	if (host_id->algorithm != 3) {
		HIP_ERROR("Not a supported algorithm: %d\n",host_id->algorithm);
		return 0;
	}

	_HIP_HEXDUMP("Signature data (verify)",buffer_start,buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1,buffer_start,buffer_length,sha1_digest)) 
	{
		HIP_ERROR("Could not calculate SHA1 digest\n");
		goto out_err;
	}

	_HIP_HEXDUMP("Verify hexdump", sha1_digest, HIP_AH_SHA_LEN);

	public_key_len = hip_get_param_contents_len(host_id) - 4;

	_HIP_HEXDUMP("verify key", public_key, public_key_len);

	_HIP_HEXDUMP("Verify hexdump sig **", signature, 42);

	tmp = hip_dsa_verify(sha1_digest, public_key, signature);

	switch(tmp) 
	{
	case 0:
		HIP_INFO("Signature: [CORRECT]\n");
		break;
	case 1:
		HIP_INFO("Signature: [INCORRECT]\n");
		HIP_HEXDUMP("digest",sha1_digest,20);
		HIP_HEXDUMP("signature",signature,42);
		HIP_HEXDUMP("public key",public_key,public_key_len);
		// break; // uncomment if you don't care about the correctness of the DSA signature
	default:
		HIP_ERROR("Signature verification failed: %d\n", tmp);
		goto out_err;
	}

	err = 1;

 out_err:
	return err;
}

/**
 * hip_calculate_shared_secret - Creates a shared secret based on the
 * public key of the peer (passed as an argument) and own DH private key
 * (created beforehand).
 * @dhf: Peer's Diffie-Hellman public key
 * @buffer: Buffer that holds enough space for the shared secret.
 *
 * Returns the length of the shared secret in octets if successful,
 * or -1 if an error occured.
 */
int hip_calculate_shared_secret(struct hip_dh_fixed *dhf, u8* buffer, 
				int bufsize)
{
	signed int len;
	int err;

	if (dh_table[dhf->group_id] == NULL) {
		HIP_ERROR("Unsupported DH group: %d\n",dhf->group_id);
		return -1;
	}

	len = hip_get_param_contents_len(dhf) - 1;

	_HIP_HEXDUMP("PEER DH key:",(dhf + 1),len);

	err = hip_gen_dh_shared_key(dh_table[dhf->group_id], (u8*)(dhf+1), len,
				    buffer, bufsize);
	if (err < 0) {
		HIP_ERROR("Could not create shared secret\n");
		return -1;
	}
	
	return err;
}

/**
 * hip_produce_keying_material - Create shared secret and produce keying material 
 * @msg: the HIP packet received from the peer
 *
 * The initial ESP keys are drawn out of the keying material.
 *
 *
 * Returns zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx)
{
	u8 *dh_shared_key = NULL;
	int hip_transf_length;
	int esp_transf_length;
	int hmac_transf_length;
	int auth_transf_length;
	int hip_tfm;
	int esp_tfm;
	
	int dh_shared_len = 1024;
	int err = 0;

	struct keymat_keymat km;
	char keymat[192];
	struct hip_tlv_common *param = NULL;

	/* 1024 should be enough for shared secret. The length of the 
	 * shared secret actually depends on the DH Group.
	 */
	dh_shared_key = kmalloc(dh_shared_len, GFP_KERNEL); /* 1024 -> hip_get_dh_size ? */
	if (dh_shared_key == NULL) {
		HIP_ERROR("No memory\n");
		err = -ENOMEM;
		goto out_err;
	}

	memset(dh_shared_key, 0, dh_shared_len); /* 1024 -> hip_get_dh_size ? */

	param = hip_get_param(msg, HIP_PARAM_DH_FIXED);
	if (!param) {
		err = -ENOENT;
		HIP_ERROR("No Diffie-Hellman param found\n");
		goto out_err;
	}

	dh_shared_len = hip_calculate_shared_secret((struct hip_dh_fixed *) param, 
						    dh_shared_key, dh_shared_len);
	if (dh_shared_len < 0) {
		HIP_ERROR("Calculation of shared secret failed\n");
		err = -EINVAL;
		goto out_err;
	}

	HIP_HEXDUMP("DH SHARED KEY", dh_shared_key, dh_shared_len);

	_HIP_HEXDUMP("hits", &msg->hits, 16);
	_HIP_HEXDUMP("hitr", &msg->hitr, 16);

	hip_make_keymat(dh_shared_key, dh_shared_len, 
			&km, &keymat, sizeof(keymat),
			&msg->hits, 
			&msg->hitr);
	_HIP_HEXDUMP("KEYMAT", &keymat, sizeof(keymat));

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

	/* Draw HIP initiator */

	memcpy(&ctx->hip_i.key,
	       hip_keymat_draw(&km, &keymat, hip_transf_length),
	       hip_transf_length);
	
	HIP_HEXDUMP("DRAWN INITIATOR", &ctx->hip_i.key,
		     hip_transf_length);
	
	/* Draw hmac key */

	memcpy(&ctx->hip_hmaci.key,
	       hip_keymat_draw(&km, &keymat, hmac_transf_length),
	       hmac_transf_length);

	HIP_HEXDUMP("HMAC KEY i", &ctx->hip_hmaci.key,hmac_transf_length);

	/* Draw HIP responder. Discard the result. */
	hip_keymat_draw(&km, &keymat, hip_transf_length);

	memcpy(&ctx->hip_hmacr.key,
	       hip_keymat_draw(&km, &keymat, hmac_transf_length),
	       hmac_transf_length);

	HIP_HEXDUMP("INIT HMAC r", &ctx->hip_hmacr.key,
		    auth_transf_length);

	/* Draw ESP ini enc */
	memcpy(&ctx->hip_espi.key,
	       hip_keymat_draw(&km, &keymat, esp_transf_length),
	       esp_transf_length);
	HIP_HEXDUMP("INIT ENC", &ctx->hip_espi.key,
		     esp_transf_length);

	/* Draw ESP ini auth */
	memcpy(&ctx->hip_authi.key,
	       hip_keymat_draw(&km, &keymat, auth_transf_length),
	       auth_transf_length);
	HIP_HEXDUMP("INIT AUTH i", &ctx->hip_authi.key,
		     auth_transf_length);

	/* Draw ESP res enc */
	memcpy(&ctx->hip_espr.key,
	       hip_keymat_draw(&km, &keymat, esp_transf_length),
	       esp_transf_length);
	HIP_HEXDUMP("RESP ENC", &ctx->hip_espr.key,
		     esp_transf_length);

	/* Draw ESP res auth */
	memcpy(&ctx->hip_authr.key,
	       hip_keymat_draw(&km, &keymat, auth_transf_length),
	       auth_transf_length);
	HIP_HEXDUMP("RESP AUTH", &ctx->hip_authr.key,
		     auth_transf_length);

 out_err:
	if (dh_shared_key)
		kfree(dh_shared_key);
	return err;

}


/*****************************************************************************
 *                           PACKET/PROTOCOL HANDLING                        *
 *****************************************************************************/


/**
 * hip_create_i2 - Create I2 packet and send it
 * @ctx: Context that includes the incoming R1 packet
 * @solved_puzzle: Value that solves the puzzle
 *
 * Returns: zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle)
{
	int err = 0;
	uint32_t spi_our = 0;
	int dh_size = 0;
	int written;
	hip_transform_suite_t transform_hip_suite, transform_esp_suite; 
	struct hip_host_id *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	struct hip_host_id *host_id_in_enc = NULL;
	struct hip_encrypted *enc_in_msg = NULL;
	struct in6_addr daddr;
	u8 *dh_data = NULL;
	struct hip_spi_lsi *spi_lsi;
	struct hip_common *i2 = NULL;
	struct hip_param *param;
	struct hip_birthday_cookie *bc = NULL;
	struct hip_dh_fixed *dh_req;
	int state;
	u8 signature[HIP_DSA_SIGNATURE_LEN];

	HIP_DEBUG("\n");

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
	dh_data = kmalloc(dh_size, GFP_KERNEL);
	if (!dh_data) {
		HIP_ERROR("Failed to alloc memory for dh_data\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* Get a localhost identity, allocate memory for the public key part
	   and extract the public key from the private key. The public key is
	   needed in the ESP-ENC below. */

	host_id_pub = hip_get_any_localhost_public_key();
	if (host_id_pub == NULL) {
		err = -EINVAL;
		HIP_ERROR("No localhost public key found\n");
		goto out_err;
	}

	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		err = -EINVAL;
		HIP_ERROR("No localhost private key found\n");
		goto out_err;
	}

	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	hip_delete_esp(&ctx->input->hitr,&ctx->input->hits);

	hip_build_network_hdr(i2, HIP_I2, 0,
			      &(ctx->input->hitr),
			      &(ctx->input->hits));

	/********** SPI_LSI **********/

	/* SPI and LSI are set below where IPsec is set up */
	err = hip_build_param_spi_lsi(i2, 0, 0);
	if (err) {
		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
		goto out_err;
	}

	/********** Birthday cookie **********/

	bc = hip_get_param(ctx->input,
			   HIP_PARAM_BIRTHDAY_COOKIE_R1);
	if (!bc) {
		err = -ENOENT;
		goto out_err;
	}

	err = hip_build_param_cookie(i2, 1,
		     hip_get_current_birthday(),
		     hip_get_param_i_val((struct hip_birthday_cookie *) bc),
		     ntoh64(solved_puzzle));
	if (err) {
		HIP_ERROR("Building of birtday cookie failed (%d)\n", err);
		goto out_err;
	}
	
	/********** Diffie-Hellman *********/

 	dh_req = hip_get_param(ctx->input, HIP_PARAM_DH_FIXED);
 
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
	
	err = hip_build_param_dh_fixed_contents(i2,dh_req->group_id, dh_data,
						written);
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
	err = hip_build_param_transform(i2,
					HIP_PARAM_HIP_TRANSFORM,
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
	err = hip_build_param_transform(i2,
					HIP_PARAM_ESP_TRANSFORM,
					&transform_esp_suite, 1);
	if (err) {
		HIP_ERROR("Building of ESP transform failed\n");
		goto out_err;
	}

	/************ Encrypted ***********/
	
	err = hip_build_param_encrypted(i2, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of param encrypted failed (%d)\n",
 			  err);
 		goto out_err;
 	}

 	enc_in_msg = hip_get_param(i2,
 				   HIP_PARAM_ENCRYPTED);
 	HIP_ASSERT(enc_in_msg); /* Builder internal error. */

 	host_id_in_enc = (struct hip_host_id *) (enc_in_msg + 1);

	err = hip_crypto_encrypted((char*) host_id_in_enc,
				   enc_in_msg->iv,
				   /* hip transform was selected above */
				   transform_hip_suite,
				   hip_get_param_total_len(host_id_in_enc),
				   &ctx->hip_i.key,
				   HIP_DIRECTION_ENCRYPT);
	if (err) {
		HIP_ERROR("Building of param encrypted failed %d\n", err);
		goto out_err;
	}

        /* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

	while (1) {
		int err;
		/* TODO: move this to hip_handle_r1 */

 		/* &ctx->entry->hit_our and &ctx->entry->hit_peer are already
 		 * set before hip_handle_r1 was called
 		 * &ctx->hip_espr.key and &ctx->hip_authr.key are already set
 		 * by hip_produce_keying_material called in hip_handle_r1 */

		/* Try to find a suitable random SPI */
		do {
			get_random_bytes(&spi_our, sizeof(uint32_t));
		} while (spi_our < 256); /* RFC 2406 section 2.1 */

		HIP_DEBUG("trying to set up inbound IPsec with SPI=0x%x\n", 
			  spi_our);

		err = hip_setup_esp(&ctx->input->hitr, 
				    &ctx->input->hits,
				    spi_our,
				    transform_esp_suite,
				    &ctx->hip_espr.key,
				    &ctx->hip_authr.key);
		if (err == -EEXIST) {
			HIP_DEBUG("SA already exists for the SPI=0x%x\n", 
				  spi_our);
			continue;
		} else if (err) {
			HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
			/* hip_delete_spd/hip_delete_sa ? */
			goto out_err;
		}

		HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x\n", spi_our);
		break;
	}

	/* update SPI_LSI parameter because it has not been filled with SPI
	 * and LSI values yet */
 	spi_lsi = hip_get_param(i2, HIP_PARAM_SPI_LSI);
 	HIP_ASSERT(spi_lsi); /* Builder internal error */
 	hip_set_param_spi_value(spi_lsi, spi_our);
 	hip_set_param_lsi_value(spi_lsi, 0x01000000 |
 		 (ntohl(ctx->input->hitr.in6_u.u6_addr32[3]) & 0x00ffffff));
 
	/* Do not modify the packet after this point or signature
	 * will not validate */

	/********** Signature **********/

        /* Should have been fetched during making of hip_encrypted */
	HIP_ASSERT(host_id_private);

	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */

	if (!hip_create_signature(i2, hip_get_msg_total_len(i2), 
				  host_id_private, signature)) 
	{
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Only DSA supported currently */
	HIP_ASSERT(hip_get_host_id_algo(host_id_private) == HIP_HI_DSA);

	err = hip_build_param_signature_contents(i2,
					signature,
					HIP_DSA_SIGNATURE_LEN,
					HIP_SIG_DSA);
	if (err) {
		HIP_ERROR("Building of signature failed (%d)\n", err);
		goto out_err;
	}

      	/********** I2 packet complete **********/

	/* jlu XXX: WRITE: The only place in R1 handlers where entry
	   is being written to */
	{
		struct hip_hadb_state *entry;
		struct hip_birthday_cookie *bc;
		int fl;

		bc = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_R1);
		if (!bc) {
			err = -ENOENT;
			goto out_err;
		}
		
		hip_hadb_acquire_ex_db_access(&fl);
		
		/* Now we have an exclusive access to hadb... let's hurry */

		entry = hip_hadb_access_db(&ctx->input->hits,HIP_ARG_HIT);
		if (!entry) {
			hip_hadb_release_ex_db_access(fl);
			HIP_ERROR("Did not find state information\n");
			goto out_err;
		}

		entry->spi_our = hip_get_param_spi_value(spi_lsi);
		entry->lsi_our = hip_get_param_lsi_value(spi_lsi);
		entry->birthday = ntoh64(bc->birthday);
		entry->esp_transform = transform_esp_suite;

		/* Store the keys until we receive R2 */
		hip_store_base_exchange_keys(entry,ctx,1);

		hip_hadb_release_ex_db_access(fl);
	}

	/* todo: Also store the keys that will be given to ESP later */

	HIP_DEBUG("sending I2\n");

	err = hip_hadb_get_peer_address(&ctx->input->hits,&daddr,
					HIP_ARG_HIT);
	if (err) {
		HIP_DEBUG("hip_sdb_get_peer_address failed, err = %d\n", err);
		goto out_err;
	}

	/* state E1: Receive R1, process. If successful,
	   send I2 and go to E2. */
	err = hip_csum_send(NULL, &daddr, i2);
	if (err) {
		HIP_ERROR("sending of I2 failed, err=%d\n", err);
		goto out_err;
	}

	state = HIP_STATE_WAIT_FINISH;
	hip_hadb_set_info(&ctx->input->hits,&state,
			  HIP_HADB_STATE|HIP_ARG_HIT);
	HIP_DEBUG("moved to state WAIT_FINISH\n");

 out_err:
	if (host_id_private)
		kfree(host_id_private);
	if (host_id_pub)
		kfree(host_id_pub);
	if (i2)
		kfree(i2);
	if (dh_data)
		kfree(dh_data);
		
	return err;
}


/**
 * hip_handle_r1 - handle incoming R1 packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: corresponding sdb entry of the peer
 *
 * This function is the actual point from where the processing of R1
 * is started and corresponding I2 is created.
 *
 * On success (R1 payloads are checked and daemon is called) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r1(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *r1 = NULL;
	struct hip_context *ctx = NULL;
	struct hip_birthday_cookie *bc;
	uint64_t solved_puzzle;
	struct hip_host_id *peer_host_id; /* Host ID FQDN not supported yet */
	u8 origlen;
	struct in6_addr tmpaddr;
	int s;
	struct hip_sig2 *sig2 = NULL;
	struct hip_lhi peer_lhi;
	int64_t birthday;

	HIP_DEBUG("Received R1\n");

	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		HIP_ERROR("Could not allocate memory for context\n");
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	r1 = (struct hip_common*) skb->h.raw;
	ctx->input = r1;

	/* If R1 was sent without our HIT as a receiver, we'll dig
	 * our HIT now
	 */
	if (ipv6_addr_any(&ctx->input->hitr)) {
		/* fill own HIT */
		hip_copy_any_localhost_hit(&ctx->input->hitr);
	}


 	bc = hip_get_param(r1, HIP_PARAM_BIRTHDAY_COOKIE_R1);
 	if (!bc) {
 		err = -ENOENT;
 		HIP_ERROR("Birthday cookie missing from R1\n");
		goto out_err;
	}
	  
	hip_hadb_get_birthday_by_hit(&ctx->input->hits,
				     &birthday);

	/* Do the obvious quick-discard tests: Birthday, ... */
	if (!hip_birthday_success(birthday, ntoh64(bc->birthday))) {
		HIP_ERROR("Received birthday with old date. NOT Dropping\n");	
		/* err = -EINVAL; */
		/* goto out_err; */
	}

	/* Validate signature. First prepare the packet for SHA1 digest */
	sig2 = hip_get_param(r1, HIP_PARAM_HIP_SIGNATURE2);
	if (!sig2) {
		HIP_ERROR("No signature2 found in R1\n");
		err = -ENOENT;
		goto out_err;
	}
	
	s = (((u8 *)sig2 - ((u8 *) r1)));

 	ipv6_addr_copy(&tmpaddr, &r1->hitr);
 	memset(&r1->hitr, 0, sizeof(struct in6_addr));
		
	origlen = hip_get_msg_total_len(r1);
	hip_set_msg_total_len(r1, s);
	r1->checksum = 0;

	peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID_FQDN);

 	if (peer_host_id) {
 		HIP_ERROR("Host_id_fqdn not supported yet)\n");
 		err = -EAFNOSUPPORT;
 		goto out_err;
 	}
 	
 	peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID);
 	if (!peer_host_id) {
 		HIP_ERROR("No host id found in R1\n");
 		err = -ENOENT;
 		goto out_err;
 	}

	_HIP_HEXDUMP("Digest", r1, s);

	if (!hip_verify_signature(r1, s, peer_host_id,
				  (u8 *)(sig2 + 1))) {
		HIP_ERROR("Signature verification failed\n");
		err = -EINVAL;
		goto out_err;
	}
	
 	ipv6_addr_copy(&r1->hitr, &tmpaddr);
 	hip_set_msg_total_len(r1, origlen);
 	/* the checksum is not restored because it was already checked in
 	   hip_inbound */

	/* signature is ok, now save the host id to db */
 	peer_lhi.anonymous = 0;
	ipv6_addr_copy(&peer_lhi.hit, &r1->hits);
 	
 	err = hip_add_host_id(HIP_DB_PEER_HID, &peer_lhi, peer_host_id);
 	if (err == -EEXIST) {
 		HIP_INFO("Host id already exists. Ignoring.\n");
 		err = 0;
 	} else if (err) {
 		HIP_ERROR("Failed to add peer host id to the database\n");
 		goto out_err;
  	}

	/* calculate shared secret and create keying material */

	err = hip_produce_keying_material(r1, ctx);
	if (err) {
		HIP_ERROR("Could not produce keying material\n");
		err = -EINVAL;
		goto out_err;
	}

	/* keying material ready */

	if (!hip_solve_puzzle(bc, r1 ,&solved_puzzle,
			      HIP_SOLVE_PUZZLE)) {
		HIP_ERROR("Solving of puzzle failed\n");
		err = -EINVAL;
		goto out_err;
	}
	
	/* Puzzle solved. We should be ready to create I2.
	 * I2 requires the value that solved the puzzle so we'll give it.
	 */
	
	HIP_INFO("R1 Successfully received\n");
 	err = hip_create_i2(ctx, solved_puzzle);
 	if (err) {
 		HIP_ERROR("Creation of I2 failed (%d)\n", err);
 		goto out_err;
 	}
 	
 out_err:
	if (ctx)
		kfree(ctx);
	return err;
}

/**
 * hip_receive_r1 - receive an R1 packet
 * @skb: sk_buff that contains the HIP packet
 * @hip_common: pointer to the HIP header
 *
 * This is the initial function which is called when an R1 packet is
 * received. First we check if we have sent the corresponding I1. If
 * yes, then the received R1 is handled in hip_handle_r1. In
 * established state we also handle the R1. Otherwise the packet is
 * dropped and not handled in any way.
 *
 * Always frees the skb
 */
int hip_receive_r1(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	int state;
	int err = 0;

	hip_common = (struct hip_common*) (skb)->h.raw;

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

	_HIP_HEXDUMP("searching", &hip_common->hits, sizeof(struct in6_addr));

	if (hip_hadb_get_state_by_hit(&hip_common->hits,&state) == 0) {
		err = -EFAULT;
		HIP_ERROR("Received R1 with no local state. Dropping\n");
		goto out_drop;
	}

	HIP_DEBUG("entry->state is %d\n", state);
	switch(state) {
	case HIP_STATE_INITIATING:
		/* E1. The normal case. Process, send I2, goto E2. */
		err = hip_handle_r1(skb);
		if (err < 0)
			HIP_ERROR("Handling of R1 failed\n");
		break;
	case HIP_STATE_WAIT_FINISH:
		/* E2. Drop and stay. */
		HIP_ERROR("Received R1 in state E2. Dropping\n");
		break;
	case HIP_STATE_ESTABLISHED:
		/* E3. jlu XXX: TBD. Birthday, I2, goto E2. */
		HIP_DEBUG("Received R1 in E3. Birthday not implemented. Not dropping\n");
		/* jlu XXX: Birthday check here. */
		/* Birthday is checked in hip_handle_r1 (but ignored for now) */
		err = hip_handle_r1(skb);
		if (!err) {
			/* if fail, start at E3 */
 			HIP_ERROR("hip_handle_r1 failed (%d)\n", err);
 		} else {
 			/* TODO: draft-08: Successful: prepare to drop old SA
 			   and cycle at E3. Note that handle_r1 changes
 			   the state. This may not be reasonable! */
 		}
 		break;
 	case HIP_STATE_ESTABLISHED_REKEY:
 		/* TODO: process with SA and birthday check */
		err = hip_handle_r1(skb);
 		if (err) {
 			HIP_ERROR("hip_handle_r1 failed (%d)\n", err);
 		} else {
 			/* TODO: draft-08 If successful, send I2, prepare to
 			   drop old SA and go to E3. Is this reasonable? */
 		}
 
		break;
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received. Receiver is confused about its own state. Dropping\n");
		break;
	}
	
 out_drop:
	kfree_skb(skb);
	return err;
}

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @ctx: Context of processed I2 packet.
 *
 * Returns: zero on success, or negative on error.
 */
int hip_create_r2(struct hip_context *ctx)
{
	struct in6_addr tmp_hitr;
	uint32_t spi_our,spi_peer;
	uint32_t lsi;
	int esptfm, ok;
 	struct hip_host_id *host_id_private;
	struct hip_tlv_common *param;
 	struct hip_common *r2 = NULL;
	struct hip_common *i2;
 	int err = 0;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];

	i2 = ctx->input;
	ok = hip_hadb_exists_entry(&i2->hits,HIP_ARG_HIT);
	if (!ok) {
		/* we have no previous infomation on the peer, create
		 * a new HIP SA */
		HIP_STATE *entry;
		entry = hip_hadb_create_entry();
		if (!entry) {
			HIP_ERROR("Failed to create or find entry\n");
			err = -ENOMSG;
			goto out_err;
		}
		ipv6_addr_copy(&entry->hit_peer,&i2->hits);
		hip_hadb_insert_entry(entry);
	} else {
		HIP_DEBUG("HIP SA already exists, reinitialize SA\n");
		/* we get here when e.g. peer has lost its state and
		 * restarts the base exchange */

		/* todo ?: draft: Reboot and SA timeout restart of HIP */
		/* hip_sdb_entry_init(entry); manual deletion
		 * ? (next pointer must not change) */

		/* TODO: move some of the entry-> stuff from below here */
	}

	/* why? */
	ipv6_addr_copy(&tmp_hitr, &ctx->input->hitr);

	/* If we have old SAs and SPDs with these HITs delete them
	 * ignoring the return value */
	hip_delete_esp(&i2->hitr,&i2->hits);

 	param = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_I2);
 	if (!param) {
 		err = -ENOENT;
 		goto out_err;
 	}

	{
		struct hip_hadb_state *entry;
		struct hip_spi_lsi *spi_lsi;
		struct hip_esp_transform *esp_tf;
		int flags;

		esp_tf = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM);
		if (!esp_tf) {
			err = -ENOENT;
			goto out_err;
		}

		spi_lsi = hip_get_param(ctx->input, HIP_PARAM_SPI_LSI);
		if (!spi_lsi) {
			err = -ENOENT;
			goto out_err;
		}

		hip_hadb_acquire_ex_db_access(&flags);

		entry = hip_hadb_access_db(&i2->hits, HIP_ARG_HIT);
		if (!entry) {
			hip_hadb_release_ex_db_access(flags);
			HIP_ERROR("Internal error\n");
			goto out_err;
		}

		/* jlu XXX: WRITE Entry not written to before this */
		entry->peer_controls = ntohs(i2->control);
		entry->birthday = ntoh64(((struct hip_birthday_cookie *)param)->birthday);
		/* todo: check if this is really our HIT? */
		ipv6_addr_copy(&entry->hit_our, &tmp_hitr);
		ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		entry->spi_peer = ntohl(spi_lsi->spi);
		entry->lsi_peer = ntohl(spi_lsi->lsi);
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		esptfm = entry->esp_transform;

		hip_hadb_release_ex_db_access(flags);

		if (entry->esp_transform == 0) {
			HIP_ERROR("Could not select proper ESP transform\n");
			goto out_err;
		}
	}

	hip_hadb_delete_peer_address_list(&i2->hits,HIP_ARG_HIT);
	/* todo: what are the default values for initial address ?
	   some flags to indicate that this address if the initial
	   address ? */
	err = hip_hadb_add_peer_address(&i2->hits, 
					&(ctx->skb_in->nh.ipv6h->saddr), 0, 0,
					HIP_ARG_HIT);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		goto out_err;
	}

	/* Set up IPsec associations */
	while (1) {
		/* TODO: maximum number of tries even though the
		 * probability is really small ? */

		/* Try to find an unused SPI. draft says that "The SPI
		 * selection SHOULD be random", we support this. Also
		 * check first that we do not violate RFC 2406 section
		 * 2.1 */
		do {
			get_random_bytes(&spi_our, sizeof(uint32_t));
		} while (spi_our < 256);

		HIP_DEBUG("trying to set up inbound IPsec with SPI=0x%x\n", spi_our);
		err = hip_setup_esp(&i2->hitr, &i2->hits,
				    spi_our,
				    esptfm,
				    &ctx->hip_espi.key,
				    &ctx->hip_authi.key);
		if (err == -EEXIST) {
			HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_our);
			continue;
		} else if (err) {
			HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
			hip_delete_esp(&i2->hitr,&i2->hits);
			goto out_err;
		}

		HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x\n", spi_our);
		/* ok, found an unused SPI to use */
		break;
	}

	hip_hadb_get_peer_spi_by_hit(&i2->hits,&spi_peer);
	
	HIP_DEBUG("setting up outbound IPsec SA, SPI=0x%x\n", spi_peer);
	err = hip_setup_esp(&i2->hits, &i2->hitr,
			    spi_peer,
			    esptfm,
			    &ctx->hip_espr.key,
			    &ctx->hip_authr.key);
	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_peer);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	} else if (err) {
		HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:dst (err=%d)\n", err);
		/* delete all IPsec related SPD/SA for this entry */
		hip_delete_esp(&i2->hitr,&i2->hits);
		goto out_err;
	}

	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x\n", spi_peer);

	{
		struct hip_hadb_state *entry;
		int fl;

		hip_hadb_acquire_ex_db_access(&fl);

		entry = hip_hadb_access_db(&i2->hits,HIP_ARG_HIT);
		if (!entry) {
			hip_hadb_release_ex_db_access(fl);
			goto out_err;
		}
		/* this is a delayed "insertation" from some 20 lines above */
		entry->spi_our = spi_our;
		entry->state = HIP_STATE_ESTABLISHED;

		hip_store_base_exchange_keys(entry, ctx, 0);

		hip_hadb_release_ex_db_access(fl);
	}

	HIP_DEBUG("Reached ESTABLISHED state\n");
	/* jlu XXX: WRITE: Entry not touched after this */

	/* Build and send R2 */
	r2 =  hip_msg_alloc();
	if (!r2) {
		err = -ENOMEM;
		HIP_ERROR("No memory for R2\n");
		goto out_err;
	}

	/* just swap the addresses to use the I2's destination HIT as
	 * the R2's source HIT */
	hip_build_network_hdr(r2, HIP_R2, 0,
			      &ctx->input->hitr, &ctx->input->hits);

 	/********** SPI_LSI **********/
 
	/* LSI: 1.x.y.z */
	lsi = 0x01000000 | (ntohl(ctx->input->hitr.s6_addr32[3]) 
			    & 0x00ffffff);

	hip_hadb_set_info(&ctx->input->hits, &lsi,
			  HIP_HADB_OWN_LSI|HIP_ARG_HIT);
	err = hip_build_param_spi_lsi(r2, lsi, spi_our);
 	if (err) {
 		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
 		goto out_err;


	}

	/*********** HMAC ************/

	{
		struct hip_crypto_key hmac;

		if (!hip_hadb_get_info(&ctx->input->hits, &hmac,
				       HIP_HADB_OWN_HMAC|HIP_ARG_HIT)) {
			err = -ENOENT;
			goto out_err;
		}
		
		err = hip_build_param_hmac_contents(r2, &hmac);
		if (err) {
			HIP_ERROR("Building of hmac failed (%d)\n", err);
			goto out_err;
		}
	}


	/********** SIGNATURE *********/

	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(r2, hip_get_msg_total_len(r2),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign R2. Failing\n");
		err = -EINVAL;
		goto out_err;
	}
	    
	err = hip_build_param_signature_contents(r2, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of signature failed (%d)\n", err);
 		goto out_err;
 	}
 	
 	/* Send the packet */
	    
	HIP_DEBUG("sending R2\n");
	err = hip_csum_send(NULL, &(ctx->skb_in->nh.ipv6h->saddr), r2);
	if (err) {
		HIP_ERROR("csum_send failed\n");
	}

 out_err:
	if (r2)
		kfree(r2);
	return err;
}


/**
 * hip_handle_i2 - handle incoming I2 packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: corresponding sdb entry of the peer
 *
 * This function is the actual point from where the processing of I2
 * is started and corresponding R2 is created.
 *
 * On success (I2 payloads are checked and R2 is created and sent) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_i2(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *i2 = NULL;
	struct hip_context *ctx = NULL;
	struct hip_encrypted *tmp_host_id = NULL;
 	struct hip_tlv_common *param;
 	struct hip_birthday_cookie *bc;
 	struct in6_addr *src;
 	struct in6_addr *dst;
 	struct hip_encrypted *enc = NULL;
 	struct hip_sig *sig;
 	struct hip_lhi lhi;
 	struct hip_host_id *host_id_in_enc = NULL;
 	int len;
	int64_t birthday;
 
 	HIP_DEBUG("\n");


	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	ctx->skb_in = skb;
	i2 = (struct hip_common*) skb->h.raw;
	ctx->input = (struct hip_common*) skb->h.raw;

	/* Check packet validity */

 	enc = hip_get_param(ctx->input, HIP_PARAM_ENCRYPTED);
 	if (!enc) {
 		err = -ENOENT;
 		goto out_err;
 	}
 
 	tmp_host_id = kmalloc(hip_get_param_total_len(enc),
 			      GFP_KERNEL);
 	if (!tmp_host_id) {
 		HIP_ERROR("No memory for temporary host_id\n");
 		err = -ENOMEM;
  		goto out_err;
  	}


	/* Birthday check
	   draft: 5.3 Reboot and SA timeout restart of HIP: The I2
	   packet MUST have a Birthday greater than the current SA's
	   Birthday. */

 	bc = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_I2);
 	if (!bc) {
 		err = -ENOENT;
 		goto out_err;
 	}

	hip_hadb_get_birthday_by_hit(&i2->hits,&birthday);
	if (!hip_birthday_success(birthday,
				  ntoh64(bc->birthday))) {
		HIP_ERROR("Failed birthday. Did not drop\n");
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("Birthday ok\n");

	/* validate cookie */

	src = &skb->nh.ipv6h->saddr;
	dst = &skb->nh.ipv6h->daddr;

	if (!hip_verify_cookie(src, dst, i2, bc)) {
		HIP_ERROR("Birthday cookie checks failed\n");
		err = -ENOMSG;
		goto out_err;
	}

	/* produce keying material */

 	err = hip_produce_keying_material(ctx->input, ctx);
 	if (err) {
 		HIP_ERROR("Unable to produce keying material. Dropping I2\n");
 		goto out_err;
 	}

	/* little workaround...
	 * We have a function that calculates sha1 digest and then verifies the
	 * signature. But since the sha1 digest in I2 must be calculated over
	 * the encrypted data, and the signature requires that the encrypted
	 * data to be decrypted (it contains peer's host identity (DSA key)),
	 * we are forced to do some temporary copying...
	 * If ultimate speed is required, then calculate the digest here as
	 * usual and feed it to signature verifier. 
	 */

	memcpy(tmp_host_id, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/

	_HIP_HEXDUMP("Recv. Key", &ctx->hip_i.key, 24);

	param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		goto out_err;
	}

        /* Get the encapsulated host id in the encrypted parameter */
	host_id_in_enc = (struct hip_host_id *) (tmp_host_id + 1);

	err = hip_crypto_encrypted(host_id_in_enc,
				   tmp_host_id->iv,
				   hip_get_param_transform_suite_id(param, 0),
				   hip_get_param_total_len(tmp_host_id),
				   &ctx->hip_i.key,
				   HIP_DIRECTION_DECRYPT);
	if (err) {
		err = -EINVAL;
		goto out_err;
	}

	_HIP_HEXDUMP("Encrypted after decrypt", host_id_in_enc,
		     hip_get_param_total_len(tmp_host_id));

	/* NOTE! The original packet has the data still encrypted. But this is
	 * not a problem, since we have decrypted the data into a temporary
	 * storage and nobody uses the data in the original packet.
	 */

	/* validate signature */

 	sig = hip_get_param(ctx->input, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
 		goto out_err;
 	}

 	len = ((u8 *) sig) - ((u8 *) ctx->input);
 	hip_zero_msg_checksum(ctx->input);
 	hip_set_msg_total_len(ctx->input, len);

 	if (len < 0) {
 		err = -ENOENT;
 		goto out_err;
 	}

 	_HIP_HEXDUMP("host id dump", tmp_host_id, hip_get_param_total_len(enc));

 	if (!hip_verify_signature(ctx->input, len, host_id_in_enc,
 				  (u8 *) (sig + 1))) {
 		HIP_ERROR("Verification of I2 signature failed\n");
 		err = -EINVAL;
 		goto out_err;
  	}

  	/* Add peer's host id to peer_id database (is there need to
  	   do this?) */
 	lhi.anonymous = 0;
	ipv6_addr_copy(&lhi.hit, &ctx->input->hits);

 	err = hip_add_host_id(HIP_DB_PEER_HID, &lhi, host_id_in_enc);
 	if (err == -EEXIST) {
 		err = 0;
 		HIP_INFO("Host id already exists. Ignoring.\n");
 	} else if (err) {
 		HIP_ERROR("Could not store peer's identity\n");
 		goto out_err;
  	}

	/* I2 Handled, create and send R2 */
	err = hip_create_r2(ctx);
	HIP_DEBUG("hip_handle_r2 returned %d\n", err);
	if (err) {
		HIP_ERROR("Creation of R2 failed\n");
	}

 out_err:
	if (tmp_host_id)
		kfree(tmp_host_id);
	if (ctx)
		kfree(ctx);
	return err;
}

/**
 * hip_receive_i2 - receive I2 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an I2 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_i2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_i2(struct sk_buff *skb) 
{
	struct hip_common *i2;
	int state;
	int err = 0;

	i2 = (struct hip_common*) (skb)->h.raw;

	HIP_DEBUG("\n");

	if (ipv6_addr_any(&i2->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in I2. Dropping\n");
		goto out;
	}

	state = 0;

	{
		int flags;
		struct hip_hadb_state *entry;

		hip_hadb_acquire_ex_db_access(&flags);
		
		entry = hip_hadb_access_db(&i2->hits, HIP_ARG_HIT);
		if (!entry) {
			err = hip_add_peer_info_nolock(&i2->hits, &skb->nh.ipv6h->saddr);
			if (err) {
				hip_hadb_release_ex_db_access(flags);
				HIP_ERROR("Could not create new state\n");
				goto out;
			}

			entry = hip_hadb_access_db(&i2->hits, HIP_ARG_HIT);
			if (!entry) {
				hip_hadb_release_ex_db_access(flags);
				HIP_ERROR("Internal error - call ghostbusters\n");
				err = -ENOENT;
				goto out;
			}
		}

		state = entry->state;
		hip_hadb_release_ex_db_access(flags);
	}

 	switch(state) {
 	case HIP_STATE_START:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_INITIATING:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_WAIT_FINISH:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_ESTABLISHED:
 		/* jlu XXX: 
 		   TBD: Do birthday check,
 		   TBD: Drop old SA,
 		   Done: Send R2 
 		*/
 		HIP_DEBUG("Received I2 in state E3. Did not do birthday\n");
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_ESTABLISHED_REKEY:
 		/* XX TODO: check birthday */
 		err = hip_handle_i2(skb);
 		if (err < 0) {
 			/* XX TODO: prepare to drop old SA and go to E3 */
		}
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

 out:
	kfree_skb(skb);

	return err;
}


/**
 * hip_handle_r2 - handle incoming R2 packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: corresponding sdb entry of the peer
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(struct sk_buff *skb)
{
	int err = 0;
	uint16_t len;
	struct hip_context *ctx = NULL;
	struct in6_addr *sender;
 	struct hip_hmac *hmac = NULL;
 	struct hip_host_id *peer_id = NULL;
 	struct hip_lhi peer_lhi;
 	struct hip_spi_lsi *spi_lsi = NULL;
 	struct hip_sig *sig = NULL;
	struct hip_crypto_key hmac_key;
	struct hip_common *r2 = NULL;

	HIP_DEBUG("Entering handle_r2\n");

	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));
	ctx->skb_in = skb;
        ctx->input = (struct hip_common*) skb->h.raw;
	r2 = ctx->input;

	sender = &r2->hits;

	// jlu XXX: Should check birthday.
	// jlu XXX: Should check if whole packet was processed...

	// set checksum to zero as in Jokela draft before sha1 hashing

	/* verify HMAC */

 	hmac = hip_get_param(r2, HIP_PARAM_HMAC);
 	if (!hmac) {
 		err = -ENOENT;
 		goto out_err;
 	}
 
 	len = (u8 *) hmac - (u8*) r2;
 	
 	hip_set_msg_total_len(r2, len);
 	
 	_HIP_HEXDUMP("HMACced data", r2, len);
 	
	if (!hip_hadb_get_info(sender,&hmac_key,
			       HIP_HADB_PEER_HMAC|HIP_ARG_HIT)) {
		HIP_ERROR("No peer HMAC key found\n");
		goto out_err;
	}

 	err = hip_verify_hmac(r2,
 			      hmac->hmac_data,
 			      hmac_key.key,
 			      HIP_DIGEST_SHA1_HMAC);
 	if (err != 0) {
 		HIP_ERROR("HMAC validation on R2 failed\n");
 		goto out_err;
  	}

	/* signature validation */

 	sig = hip_get_param(r2, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
 		goto out_err;
 	}
 	
 	hip_zero_msg_checksum(r2);
 	len = (u8*) sig - (u8*) r2;
 	hip_set_msg_total_len(r2, len);
 	
 	peer_lhi.anonymous = 0;
 	ipv6_addr_copy(&peer_lhi.hit, &r2->hits);
 	
 	peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
 	if (!peer_id) {
 		HIP_ERROR("Unknown peer (no identity found)\n");
 		err = -EINVAL;
 		goto out_err;
 	}
 	
 	if (!hip_verify_signature(r2, len, peer_id,
 				  (u8*)(sig + 1))) {
 		HIP_ERROR("R2 signature verification failed\n");
 		err = -EINVAL;
 		goto out_err;
 	}

        /* The rest */

 	spi_lsi = hip_get_param(r2, HIP_PARAM_SPI_LSI);
 	if (!spi_lsi) {
 		err = -EINVAL;
 		goto out_err;
 	}

	/* jlu XXX: WRITE: The only place in R2 handlers where entry
	 * is written to */
	{
		int tmp_list[4];
		int tfm;
		int tmp_lsi;
		uint32_t spi_recvd;

		spi_recvd = ntohl(spi_lsi->spi);
		tmp_lsi = ntohl(spi_lsi->lsi);

		tmp_list[0] = HIP_HADB_PEER_SPI;
		tmp_list[1] = HIP_HADB_PEER_LSI;

		hip_hadb_multiset(sender,tmp_list,2,&spi_recvd,&tmp_lsi,NULL,
				  NULL,HIP_ARG_HIT);

        /* Set up outbound IPsec SA (inbound SA was already set up
	 * earlier when I2 was sent) */
		tmp_list[0] = HIP_HADB_ESP_TRANSFORM;
		tmp_list[1] = HIP_HADB_OWN_ESP;
		tmp_list[2] = HIP_HADB_OWN_AUTH;

		hip_hadb_multiget(sender,tmp_list,3,&tfm,&ctx->hip_espi,
				  &ctx->hip_authi,NULL,HIP_ARG_HIT);

		err = hip_setup_esp(sender, &r2->hitr, spi_recvd, tfm,
				    &ctx->hip_espi.key,
				    &ctx->hip_authi.key);
		if (err == -EEXIST) {
			HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_recvd);
			HIP_DEBUG("TODO: what to do ? currently ignored\n");
		} else 	if (err) {
			HIP_ERROR("hip_setup_esp failed, peer:dst (err=%d)\n", err);
			HIP_ERROR("** TODO: remove inbound IPsec SA**\n");
		}

		tfm = HIP_STATE_ESTABLISHED;
		hip_hadb_set_info(sender,&tfm,HIP_HADB_STATE|HIP_ARG_HIT);
		HIP_DEBUG("Reached ESTABLISHED state\n");
	}

 out_err:
	if (ctx)
		kfree(ctx);
	return err;
}

/**
 * hip_receive_i1 - receive I1 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an I1 packet is
 * received. If we are in correct state we reply with an R1 packet.
 *
 * This function never writes into hip_sdb_state entries.
 *
 * Returns: zero on success, or negative error value on error.
 */
int hip_receive_i1(struct sk_buff *skb) 
{
	struct hip_i1 *hip_i1 = (struct hip_i1*) skb->h.raw;
	struct hip_common *r1;
	int ok = 0;
	int err = 0;
	int state;

	HIP_DEBUG("\n");

	r1 = (struct hip_common*) (skb)->h.raw;
	if (ipv6_addr_any(&r1->hitr)) {
		HIP_ERROR("Received NULL receiver HIT. Opportunistic HIP is not supported yet in I1. Dropping\n");
		err = -EPROTONOSUPPORT;
		goto out;
	}

	if (!hip_controls_sane(ntohs(hip_i1->control),
			       HIP_CONTROL_PIGGYBACK_ALLOW)) {
		HIP_ERROR("Received illegal controls in I1. Dropping\n");
		goto out;
	}

	state = HIP_STATE_NONE;
	hip_hadb_get_state_by_hit(&r1->hits,&state);
	

	switch(state) {
	case HIP_STATE_NONE:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Received I1 in no state. Sent R1\n");
		break;
	case HIP_STATE_START:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Received I1 in state E0. Sent R1\n");
		break;
	case HIP_STATE_INITIATING:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Received I1 in state E1. Sent R1\n");
		break;
	case HIP_STATE_WAIT_FINISH:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Received I1 in state E2. Sent R1\n");
		break;
	case HIP_STATE_ESTABLISHED:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Special: Received I1 in state E3. Sent R1\n");
		break;
	case HIP_STATE_ESTABLISHED_REKEY:
		ok = hip_send_r1(skb);
		HIP_DEBUG("Received I1 in state E3. Sent R1.\n");
		break;
	}

	// jlu XXX: UNLOCK. Can release entry.

 out:
	kfree_skb(skb);
	
	return ok;
}

/**
 * hip_receive_r2 - receive R2 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_r2(struct sk_buff *skb) 
{
	struct hip_common *hip_common;
	int err = 0;
	int state;

	hip_common = (struct hip_common *)skb->h.raw;

	HIP_DEBUG("\n");

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in R2. Dropping\n");
		goto out_err;
	}

	hip_hadb_get_state_by_hit(&hip_common->hits,&state);

 	switch(state) {
 	case HIP_STATE_INITIATING:
 		HIP_ERROR("Received R2 in E1. Dropping\n");
 		err = -EFAULT;
 		break;
 	case HIP_STATE_WAIT_FINISH:
 		/* The usual case. */
 		err = hip_handle_r2(skb);
 		if (err != 0) {
			HIP_ERROR("hip_handle_r2 failed(%d)\n", err);
 		}
 		break;
 	case HIP_STATE_ESTABLISHED:
 		HIP_ERROR("Received R2 in E3. Dropping\n");
 		err = -EFAULT;
 		break;
 	case HIP_STATE_ESTABLISHED_REKEY:
 		HIP_ERROR("Received R2 in E4. Dropping.\n");
 		err = -EFAULT;
 		break;
 	default:
 		/* Cannot happen. */
 		HIP_ERROR("Received R2. The state machine is confused. Dropping\n");
 		err = -EFAULT;
 		break;
 	}
	
 out_err:
	kfree_skb(skb);
	return err;
}

/**
 * hip_get_next_atomic_val_16 - get the next number of given atomic variable
 * @a: the atomic variable
 * @lock: atomic operations are protected 
 *
 * @a is truncated to 16 bits, so this function retuns values from the
 * range of 0-65535.
 *
 * Returns the new value of @a.
 */
uint16_t hip_get_next_atomic_val_16(atomic_t *a, spinlock_t *lock)
{
	uint16_t val;
	unsigned long flags = 0;

	_HIP_DEBUG("entering\n");
	spin_lock_irqsave(lock, flags);
	atomic_inc(a);
	atomic_clear_mask(~0xffff, a);
	val = atomic_read(a);
	spin_unlock_irqrestore(lock, flags);

	return val;
}

/**
 * hip_get_new_ac_id - get a new AC ID number
 *
 * Returns the next value of AC ID to use.
 */
uint16_t hip_get_new_ac_id(void) {
	uint16_t id;

	id = hip_get_next_atomic_val_16(&hip_rea_ac_id, &hip_rea_ac_id_lock);
	_HIP_DEBUG("got ac id %u\n", id);
	return id;
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

	hmac_res = kmalloc(HIP_AH_SHA_LEN, GFP_KERNEL);
	if (!hmac_res) {
		HIP_ERROR("kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	_HIP_HEXDUMP("HMAC data", buffer, hip_get_msg_total_len(buffer));

	if (!hip_write_hmac(hmac_type, hmac_key, buffer,
			    hip_get_msg_total_len(buffer), hmac_res))
	{
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
		kfree(hmac_res);

	return err;
}

/**
 * hip_rea_check_received_rea_id - check if REA was sent to the HIT
 * @rea_id: REA ID in host byte order
 * @hit: HIT where REA was sent
 *
 * Returns 1: if we have sent a REA packet containing REA ID @rea_id to
 * HIT @hit, 0 otherwise.
 */
int hip_rea_check_received_rea_id(uint16_t rea_id, struct in6_addr *hit) {
	int err = 0;
	struct list_head *pos, *n;
	struct hip_sent_rea_info *sent_rea;
	int i = 1;
	unsigned long flags = 0;

	spin_lock_irqsave(&hip_sent_rea_info_lock, flags);
	HIP_DEBUG("rea_id=%u\n", rea_id);

	list_for_each_safe(pos, n, &hip_sent_rea_info_pkts) {
		sent_rea = list_entry(pos, struct hip_sent_rea_info, list);
		_HIP_DEBUG("check %d: rea_id=%u (net=%u)\n",
			  i, sent_rea->rea_id, htohn(sent_rea->rea_id));
		if (sent_rea->rea_id == rea_id &&
		    !ipv6_addr_cmp(&sent_rea->hit, hit)) {
			err = 1;
			goto out;
		}
		i++;
	}
	HIP_ERROR("REA ID %u not found\n", rea_id);
 out:
	spin_unlock_irqrestore(&hip_sent_rea_info_lock, flags);
	return err;
}

/**
 * hip_rea_check_received_ac_id - check if AC was sent to IPv6 address
 * @rea_id: REA ID in host byte order
 * @ac_id: AC ID in host byte order
 * @src_ip: IPv6 address where AC was sent to
 * @ip: where @src_ip is copied to
 * @lifetime: where lifetime of address @src_ip is copied to
 * @interface: where Interface ID of address @src_ip is copied to
 * @rtt_sent: where the time when AC was sent is copied to
 *
 * Returns: 1 if we have sent an AC packet containing @rea_id as its
 * REA ID and @ac_id as its AC ID to @src_ip, @src_ip is copied to
 * @ip, address lifetime, Interface ID associated with @src_ip and the
 * time when AC was sent are assigned to @lifetime, @interface_id and
 * @rtt_sent (if they are non-NULL). Otherwise 0 is returned.
 */
int hip_rea_check_received_ac_id(uint16_t rea_id, uint16_t ac_id,
				 struct in6_addr *src_ip, struct in6_addr *ip,
				 uint32_t *lifetime, uint32_t *interface_id,
				 unsigned long *rtt_sent) {
	int err = 0;
	struct list_head *pos, *n;
	struct hip_sent_ac_info *sent_ac;
	unsigned long flags = 0;

	spin_lock_irqsave(&hip_sent_ac_info_lock, flags);
	HIP_DEBUG("rea_id=%u ac_id=%u\n", rea_id, ac_id);

	list_for_each_safe(pos, n, &hip_sent_ac_info_pkts) {
		char addrstr[INET6_ADDRSTRLEN];

		sent_ac = list_entry(pos, struct hip_sent_ac_info, list);
		hip_in6_ntop(&sent_ac->ip, addrstr);
		if (sent_ac->rea_id == rea_id && sent_ac->ac_id == ac_id &&
		    !ipv6_addr_cmp(&sent_ac->ip, src_ip)) {
			ipv6_addr_copy(ip, &sent_ac->ip);
			if (lifetime)
				*lifetime = sent_ac->lifetime;
			if (interface_id)
				*interface_id = sent_ac->interface_id;
			if (rtt_sent)
				*rtt_sent = sent_ac->rtt_sent;
			err = 1;
			goto out;
		}
	}

	HIP_ERROR("Not found (AC ID=%u, REA ID=%u)\n", ac_id, rea_id);
 out:
	spin_unlock_irqrestore(&hip_sent_ac_info_lock, flags);
	return err;
}


/**
 * hip_receive_ac_or_acr - handle incoming AC or ACR packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 * @pkt_type: %HIP_AC for AC packets and %HIP_ACR for ACR packets
 *
 * Returns: 0 if the packet was processed successfully, otherwise
 * nonzero.
 */
int hip_receive_ac_or_acr(struct sk_buff *skb, int pkt_type)
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_ac_info *ac_info;
	struct hip_hmac *hmac;
	struct hip_common *hip_common;

	unsigned long recv_time = jiffies;
	char *pkt_descr;

	HIP_DEBUG("\n");

	hip_common = (struct hip_common *)(skb)->h.raw;

	if (!(pkt_type == HIP_AC || pkt_type == HIP_ACR)) {
	  HIP_ERROR("Illegal pkt_type %d\n", pkt_type);
	  err = -EINVAL;
	  goto out_err;
	}
	pkt_descr = pkt_type == HIP_AC ? "AC" : "ACR";

	_HIP_HEXDUMP(pkt_descr, hip_common, hip_get_msg_total_len(hip_common));
	_HIP_HEXDUMP("pkt v6 saddr", &skb->nh.ipv6h->saddr, sizeof(struct in6_addr));
	_HIP_HEXDUMP("pkt v6 daddr", &skb->nh.ipv6h->daddr, sizeof(struct in6_addr));

	if (!hip_hadb_exists_entry(&hip_common->hits,HIP_ARG_HIT)) {
		err = -ENOMSG;
		HIP_ERROR("Received %s but no state with peer. Dropping\n", pkt_descr);
		goto out_err;
	}

	/* todo: use hip_tlv_sane */
	msg = (struct hip_common *) skb->h.raw;

	ac_info = hip_get_param(msg, HIP_PARAM_AC_INFO);
	if (!ac_info) {
		HIP_ERROR("%s contained no AC_INFO parameter\n", pkt_descr);
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("AC_INFO found\n");

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (!hmac) {
		HIP_ERROR("%s contained no HMAC parameter\n", pkt_descr);
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("HMAC found\n");

        /* verify HMAC */
        {
                int len;
		struct hip_crypto_key tmpkey;

                len = (u8 *)hmac - (u8*)msg;
                hip_set_msg_total_len(msg, len);

                _HIP_HEXDUMP("HMACced data", msg, len);
                _HIP_HEXDUMP("HMAC key", entry->hmac_peer.key, HIP_AH_SHA_LEN);

		if (!hip_hadb_get_info(&msg->hits,&tmpkey,
				       HIP_HADB_PEER_HMAC|HIP_ARG_HIT)) {
			HIP_ERROR("No HMAC key found\n");
			goto out_err;
		}

                err = hip_verify_hmac(msg, hmac->hmac_data,
                                      tmpkey.key, HIP_DIGEST_SHA1_HMAC);
                if (err) {
                        HIP_ERROR("HMAC validation on %s failed\n", pkt_descr);
                        goto out_err;
                }

        }
        HIP_DEBUG("HMAC ok\n");

	if (pkt_type == HIP_AC) {
		/* AC handling specific functions */

		/* check if we have sent the corresponding REA
		 * (draft-nikander-hip-mm-00.txt sec 5.3) */
		if (!hip_rea_check_received_rea_id(ntohs(ac_info->rea_id), &msg->hits)) {
			HIP_ERROR("Found no corresponding REA ID for received AC (%u)\n",
				  ntohs(ac_info->rea_id));
			err = -ENOMSG;
			goto out_err;
		}
		HIP_DEBUG("Received REA ID matches with sent REA ID\n");
		/* todo: delete the sent REA from the sent REA list if
		   we have received AC for every address listed in the sent REA */

		HIP_DEBUG("send ACR\n");
		/* todo: should we use AC's dst address as src address
		   or let the kernel choose it ? */
		err = hip_send_ac_or_acr(HIP_ACR, &hip_common->hitr, &hip_common->hits,
					 &skb->nh.ipv6h->daddr, &skb->nh.ipv6h->saddr,
					 ntohs(ac_info->ac_id), ntohs(ac_info->rea_id),
					 ac_info->rtt, 0, 0);
	} else {
		/* ACR handling specific functions */
		struct in6_addr addr;
		uint32_t interface_id, lifetime;
		unsigned long rtt_sent;
		/* check if we have sent the corresponding REA and AC */

		/* check: do we have to care about the source IPv6 address
		 * from where the packet came ? */
		if (!hip_rea_check_received_ac_id(ntohs(ac_info->rea_id),
						  ntohs(ac_info->ac_id),
						  &skb->nh.ipv6h->saddr,
						  &addr, &lifetime,
						  &interface_id, &rtt_sent)) {
			HIP_ERROR("Found no corresponding REA ID (%u) and AC ID (%u) for received ACR\n",
				  ntohs(ac_info->rea_id),
				  ntohs(ac_info->ac_id));
			err = -ENOMSG;
			goto out_err;
		}
		HIP_DEBUG("Received REA ID and AC ID matches, received ACR is valid\n");
		HIP_DEBUG("calculated RTT: %lu jiffies\n", recv_time-rtt_sent);
		/* kludge */
		if (rtt_sent != ac_info->rtt) {
			_HIP_DEBUG("paranoia, sender has changed RTT of AC: original=0x%lx received=0x%lx\n",
				  rtt_sent, ac_info->rtt);
			/* anyway, we couldn't care less because we
			   don't use the RTT field of the incoming AC
			   packet */
		} else {
			HIP_DEBUG("test: received RTT was same as sent RTT\n");
		}
		_HIP_HEXDUMP("remembered saddr", &addr, sizeof(struct in6_addr));

		err = hip_hadb_add_peer_address(&msg->hits, &addr, interface_id, 
						lifetime, HIP_ARG_HIT);
		if (err) {
			HIP_ERROR("error while adding a new peer address item\n");
			goto out_err;
		}

		/* ***** todo: CANCEL SENT REA TIMER ***** */
		hip_ac_delete_sent_list_one(0, ntohs(ac_info->rea_id), ntohs(ac_info->ac_id));
	}

	HIP_ASSERT(!err);
	return err;

 out_err:
	if (skb)
		kfree_skb(skb);
	return err;
}

/**
 * hip_handle_rea_finish - finish handling of REA
 * @rea_info: pointer to REA_INFO in the packet 
 * @entry: XXXXXX corresponding sdb entry of the peer
 * @dst_hit: peer's HIT
 * @our_hit: our HIT
 *
 * This functions finishes the handling of the incoming REA packet
 * after the HMAC and signature verification. AC packets are sent to all
 * addresses listed in the REA_INFO payload except to the addresses we
 * already know of (we assume that the address is still valid).
 *
 * TODO:Currently this function handles only one REA_INFO payload. We
 * should resend an AC packet if some address is moved to a different
 * Interface ID.
 *
 * Returns 0 if the packet was processed successfully, otherwise
 * nonzero.
 */
int hip_handle_rea_finish(struct hip_rea_info *rea_info,
			  struct in6_addr *dst_hit, struct in6_addr *our_hit)
{
	int err = 0;
	int i;
	unsigned int addrlist_len, n_addrs;
	void *p;

	HIP_DEBUG("\n");
	hip_print_hit("dst_hit", dst_hit);

	/* todo: convert to struct list_head */
	addrlist_len = hip_get_param_total_len(rea_info) -
	  sizeof(struct hip_rea_info_addr_item);
	n_addrs = addrlist_len / sizeof(struct hip_rea_info_addr_item);
	_HIP_DEBUG("addlistlen=%d naddrs=%d\n", addrlist_len, n_addrs);
	HIP_DEBUG("REA-in contains %d addresses\n", n_addrs);
	if (addrlist_len > 0 &&
	    (addrlist_len % sizeof(struct hip_rea_info_addr_item)))
		HIP_DEBUG("bug: addlistlen=%d not divisible exactly by %d\n",
			  addrlist_len, sizeof(struct hip_rea_info_addr_item));

	/* delete all occurrences of peer's interface if REA does not
	   contain any addresses (experimental, not in spec) */
	if (n_addrs == 0) {
		HIP_DEBUG("delete all peer addresses belonging to interface %u\n",
			  rea_info->interface_id);
		hip_hadb_delete_peer_addr_iface((void *)dst_hit, rea_info->interface_id,
						HIP_ARG_HIT);
		goto out;
	}

	p = (void*)rea_info+sizeof(struct hip_rea_info);
	hip_hadb_delete_peer_addr_not_in_list((void *)dst_hit, p, n_addrs, rea_info->interface_id,
					      HIP_ARG_HIT);

	HIP_DEBUG("start sending all ACs\n");

	/* send AC to listed addresses */
	p = (void*)rea_info+sizeof(struct hip_rea_info);
	for (i = 0; i < n_addrs; i++, p += sizeof(struct hip_rea_info_addr_item)) {
		struct hip_rea_info_addr_item *addr = (struct hip_rea_info_addr_item *) p;
		char addrstr[INET6_ADDRSTRLEN];
		uint32_t current_time, prev_if;

		hip_in6_ntop(&addr->address, addrstr);
		HIP_DEBUG("item %d: lifetime=0x%x address=%s\n",
			  i+1, ntohl(addr->lifetime), addrstr);

		if (hip_hadb_get_peer_address_info(&dst_hit, &addr->address, &prev_if, 
						   NULL, NULL, HIP_ARG_HIT)) 
		{
			/* Hmm..I think we still have to send REA if interface changes, check */
			HIP_DEBUG("do not resend AC to already know address\n");
			if (prev_if != rea_info->interface_id) {
				HIP_DEBUG("address' iface changed -> update info\n");
				/* todo: update lifetime too ? */
				err = hip_hadb_set_peer_address_info(&dst_hit, &addr->address,
								     &rea_info->interface_id, NULL,
								     HIP_ARG_HIT);
				if (!err) {
					HIP_DEBUG("hip_sdb_set_peer_address_info failed\n");
					err = 0;
				}
			}

			/* move the known address to the top of the list so we use the
			   latest address received, ** kludge ** */

			/* todo: write some address update function and remove these two lines */

			/* remove soon */
 			hip_hadb_delete_peer_address_list_one(&dst_hit, &addr->address,
							      HIP_ARG_HIT);
			err = hip_hadb_add_peer_address(&dst_hit, &addr->address,
							rea_info->interface_id, addr->lifetime,
							HIP_ARG_HIT);
			_HIP_DEBUG("known address moved to the end of the peer address list\n");
			/* (testing) continue; */
		}
		HIP_DEBUG("is not known address, send AC\n");

		if (ntohl(addr->reserved) != 0)
			HIP_DEBUG("reserved in REA_INFO not zero (0x%x), ignored\n", ntohl(addr->reserved));

		current_time = jiffies; /* for testing, see todo */
		_HIP_DEBUG("current_time=0x%x/%u\n", current_time, current_time);

		//err = hip_send_ac_or_acr(HIP_AC, our_hit, NULL, &addr->address, hip_get_new_ac_id(),
		err = hip_send_ac_or_acr(HIP_AC, our_hit, dst_hit, NULL, &addr->address,
					 hip_get_new_ac_id(), ntohs(rea_info->rea_id),
					 current_time, rea_info->interface_id,
					 addr->lifetime /* conversion ? */);
		if (err)
			HIP_DEBUG("hip_send_ac_or_acr ret err=%d\n", err);
	}

 out:
	return err;
}

/**
 * hip_handle_rea - handle incoming REA packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: XXXXXXXXXXXX corresponding sdb entry of the peer
 *
 * This function is the actual point from where the processing of REA
 * is started.
 *
 * On success (HMAC and signature are validated, and
 * hip_handle_rea_finish is called successfully) 0 is returned,
 * otherwise < 0.
 */
int hip_handle_rea(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_rea_info *rea_info;
	struct hip_sig *sig;
	struct hip_hmac *hmac;
	uint32_t spi;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;

	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));
	_HIP_DUMP_MSG(msg);

	/* todo: validate tlvs */
	/* todo: handle multiple REA_INFOs, currently only the first
	   is handled  */

	rea_info = hip_get_param(msg, HIP_PARAM_REA_INFO);
	if (!rea_info) {
		HIP_ERROR("REA contained no REA_INFO parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("REA_INFO found\n");

	sig = (struct hip_sig *) hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE);
        if (!sig) {
                HIP_ERROR("no HIP_SIGNATURE found\n");
                err = -ENOMSG;
                goto out_err;
        }
	HIP_DEBUG("SIGNATURE found\n");

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (!hmac) {
		HIP_ERROR("REA contained no HMAC parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("HMAC found\n");

	_HIP_HEXDUMP("packet HMAC", hmac, sizeof(struct hip_hmac));
	_HIP_HEXDUMP("packet hmac data calc", msg,
		     (void *)hmac-(void *)msg);

	HIP_DEBUG("REA_INFO: REA ID: %u\n", ntohs(rea_info->rea_id));
	HIP_DEBUG("REA_INFO: Interface ID (as is): 0x%x/(dec %u)\n",
		  rea_info->interface_id, rea_info->interface_id);
	HIP_DEBUG("REA_INFO: Current SPI reverse: 0x%x\n",
		  ntohl(rea_info->current_spi_rev));
	HIP_DEBUG("REA_INFO: Current SPI: 0x%x\n",
		  ntohl(rea_info->current_spi));
	HIP_DEBUG("REA_INFO: New SPI: 0x%x\n", ntohl(rea_info->new_spi));
	HIP_DEBUG("REA_INFO: Keymaterial index: %u\n",
		  ntohs(rea_info->keymat_index));

        /* verify HMAC */
        {
                int len;
		struct hip_crypto_key tmpkey;

                len = (u8 *)hmac - (u8*)msg;
                hip_set_msg_total_len(msg, len);

                _HIP_HEXDUMP("HMACced data", msg, len);
//                _HIP_HEXDUMP("HMAC key", entry->hmac_peer.key, HIP_AH_SHA_LEN);

		if (!hip_hadb_get_info(&msg->hits, &tmpkey,
				       HIP_HADB_PEER_HMAC|HIP_ARG_HIT)) {
			HIP_ERROR("No HMAC key found\n");
			goto out_err;
		}

                err = hip_verify_hmac(msg, hmac->hmac_data,
                                      tmpkey.key, HIP_DIGEST_SHA1_HMAC);
                if (err) {
                        HIP_ERROR("HMAC validation on REA failed\n");
                        goto out_err;
                }

        }
        HIP_DEBUG("HMAC ok\n");

        /* verify signature */
        /* copypaste from hip_handle_r2 */
        {
                int len;
                struct hip_host_id *peer_id;
                struct hip_lhi peer_lhi;

                len = (u8 *)sig - (u8*)msg;
                hip_zero_msg_checksum(msg);
                hip_set_msg_total_len(msg, len);

                peer_lhi.anonymous = 0;
                memcpy(&peer_lhi.hit, &msg->hits, sizeof(struct in6_addr));

                peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
                if (!peer_id) {
                        HIP_ERROR("Unknown peer (no identity found)\n");
                        err = -EINVAL;
                        goto out_err;
                }

                if (!hip_verify_signature(msg, len, peer_id,
					  (u8 *)(sig + 1))) {
                        HIP_ERROR("Verification of REA signature failed\n");
                        err = -EINVAL;
                        goto out_err;
                }
        }
        HIP_DEBUG("Signature ok\n");

	/* check SPI value */
	spi = ntohl(rea_info->current_spi);
	if (!hip_hadb_exists_entry((void *)spi, HIP_ARG_SPI)) {
		HIP_ERROR("Current peer SPI 0x%x not known", spi);
		goto out_err;
	}
	HIP_DEBUG("Current SPI field ok\n");

	err = hip_handle_rea_finish(rea_info, &msg->hits, &msg->hitr);
	if (err)
		HIP_DEBUG("hip_handle_rea_finish ret err=%d\n", err);

 out_err:
	/* skb is freed by hip_receive_rea */
	return err;
}

/**
 * hip_receive_rea - receive REA packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when a REA packet is
 * received. REA is handled in hip_handle_rea() only if we are in
 * established state with the peer.
 *
 * Returns 0 is successful, otherwise < 0.
 */
int hip_receive_rea(struct sk_buff *skb) 
{
	struct hip_common *hip_common;
	int state = 0;
	int err = 0;

	HIP_DEBUG("\n");

	hip_common = (struct hip_common *)skb->h.raw;

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in REA. Dropping\n");
		err = -EINVAL;
		goto out_err;
	}

	hip_hadb_get_state_by_hit(&hip_common->hits, &state);

	switch(state) {
	case HIP_STATE_ESTABLISHED:
		HIP_DEBUG("Received REA in E3\n");
		err = hip_handle_rea(skb);
		if (err) {
			HIP_ERROR("REA handler failed\n");
			goto out_err;
		}
		break;
	default:
		HIP_ERROR("Received REA without established state. Dropping\n");
		err = -EINVAL;
		break;
	}

	_HIP_ASSERT(!err); /* might happen if we have restarted hipmod etc */
	return err;

 out_err:
	if (skb)
		kfree_skb(skb);
	return err;
}

/**
 * hip_check_network_header - validate an incoming HIP header
 * @hip_common: pointer to the HIP header
 *
 * Returns: zero if the HIP message header was ok, or negative error value on
 *          failure
 */
int hip_verify_network_header(struct hip_common *hip_common,
			      struct sk_buff **skb)
{
	int err = 0;
	uint16_t csum;

	HIP_DEBUG("skb len=%d, v6hdr payload_len=%d/hip hdr pkt total len=%d\n",
		  (*skb)->len, ntohs((*skb)->nh.ipv6h->payload_len),
		  (hip_common->payload_len+1)*8);

	if ( ntohs((*skb)->nh.ipv6h->payload_len) !=
	     (hip_common->payload_len+1)*8 )  {
		HIP_ERROR("Invalid HIP packet length (IPv6 hdr payload_len=%d/HIP pkt len=%d). Dropping\n",
			  ntohs((*skb)->nh.ipv6h->payload_len),
			  (hip_common->payload_len+1)*8);
		err = -EINVAL;
		goto out_err;
	}

	/* Currently no support for piggybacking */
	if (hip_common->payload_proto != IPPROTO_NONE) {
		HIP_ERROR("Protocol in packet was not IPPROTO_NONE. Dropping\n");
		err = -EOPNOTSUPP;
		goto out_err;
	}

	if ((hip_common->ver_res & HIP_VER_MASK) != HIP_VER_RES) {
		HIP_ERROR("Invalid version in received packet. Dropping\n");
		err = -EPROTOTYPE;
		goto out_err;
	}


	if (!hip_is_hit(&hip_common->hits)) {
		HIP_ERROR("Received a non-HIT in HIT-source. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

	if (!hip_is_hit(&hip_common->hitr) &&
	    !ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

        /* Check checksum. */
	/* jlu XXX: We should not write into received skbuffs! */
	csum = hip_common->checksum;
	hip_zero_msg_checksum(hip_common);
	/* Interop with Julien: no htons here */
	if (hip_csum_verify(*skb) != csum) {
	       HIP_ERROR("HIP checksum failed (0x%x). Should have been: 0x%x\n", 
			 csum, ntohs(hip_csum_verify(*skb)) );
		err = -EBADMSG;
	}

 out_err:
	return err;
}

/**
 * hip_inbound - entry point for processing of an incoming HIP packet
 * @skb: sk_buff containing the HIP packet
 * @unused:
 *
 * This function if the entry point for all incoming HIP packet. First
 * we try to parse and validate the HIP header, and if it is valid the
 * packet type is determined and control is passed to corresponding
 * handler function which processes the packet.
 *
 * We must free the skb by ourselves, if an error occures!
 *
 * Return 0, if packet accepted
 *       <0, if error
 *       >0, if other protocol payload (piggybacking)
 */
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff)
{
	struct hip_common *hip_common;
	struct hip_work_order *hwo;
	int err = 0;

	/* See if there is at least the HIP header in the packet */
	if (!pskb_may_pull(*skb, sizeof(struct hip_common))) {
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
	}

	hip_common = (struct hip_common*) (*skb)->h.raw;
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);

	_HIP_DEBUG_SKB((*skb)->nh.ipv6h, skb);

	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     (hip_common->payload_len+1) << 3);

	err = hip_verify_network_header(hip_common, skb);
	if (err) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
	}

	err = hip_check_network_msg(hip_common);
	if (err) {
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("No memory, dropping packet\n");
		err = -ENOMEM;
		goto out_err;
	}

	_HIP_DEBUG("Entering switch\n");
	hwo->type = HIP_WO_TYPE_INCOMING;
	hwo->arg1 = *skb;

	switch(hip_get_msg_type(hip_common)) {
	case HIP_I1:
		HIP_DEBUG("Received HIP I1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I1;
		break;
	case HIP_R1:
		HIP_DEBUG("Received HIP R1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R1;
		break;
	case HIP_I2:
		HIP_DEBUG("Received HIP I2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I2;
		break;
	case HIP_R2:
		HIP_DEBUG("Received HIP R2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R2;
		break;
	case HIP_REA:
		HIP_DEBUG("Received HIP REA packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_REA;
		break;
	case HIP_AC:
		HIP_DEBUG("Received HIP AC packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_AC;
		break;
	case HIP_ACR:
		HIP_DEBUG("Received HIP ACR packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_ACR;
		break;
	default:
		HIP_ERROR("Received HIP packet of unknown/unimplemented type %d\n",
			  hip_common->type_hdr);
		kfree_skb(*skb);  /* sic */
		kfree(hwo);
		/*  KRISUXXX: return value? */
		return -1;
		break;
	}

	hip_insert_work_order(hwo);

 out_err:
	/* We must not use kfree_skb here... (worker thread releases) */

	return 0;
}
