#include "update.h"
#include "hip.h"
#include "security.h"
#include "input.h"

atomic_t hip_update_id = ATOMIC_INIT(0);
spinlock_t hip_update_id_lock = SPIN_LOCK_UNLOCKED;

/**
 * hip_get_new_update_id - Get a new UPDATE ID number
 *
 * Returns: the next UPDATE ID value to use in host byte order
 */
static uint16_t hip_get_new_update_id(void) {
	uint16_t id = hip_get_next_atomic_val_16(&hip_update_id, &hip_update_id_lock);
	_HIP_DEBUG("got UPDATE ID %u\n", id);
	return id;
}

/**
 * hip_handle_update_initial - handle incoming initial UPDATE packet
 * @msg: the HIP packet
 * @state: the state in which we are with the peer
 *
 * This function handles cases 8 and 10 in draft-09 section "8.10
 * Processing UPDATE packets".
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_initial(struct hip_common *msg, struct in6_addr *src_ip, int state /*, int is_reply*/)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	int esp_transform;
	struct hip_crypto_key espkey_our, authkey_our;
	struct hip_crypto_key espkey_peer, authkey_peer;

	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	int getlist[3];
	void *setlist[3];
	uint32_t our_prev_spi, peer_prev_spi;
	uint32_t our_new_spi = 0;  /* inbound IPsec SA SPI */
	uint32_t peer_new_spi = 0; /* outbound IPsec SA SPI */
	uint32_t spi_gl, spi_lg;
	struct hip_common *update_packet = NULL;
	uint16_t our_current_keymat_index; /* current or prev ? */
	struct in6_addr daddr;
	struct hip_dh_fixed *dh;
	struct hip_crypto_key hmac;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	int need_to_generate_key, dh_key_generated, new_keymat_generated;
	//	uint16_t kmindex_pre; /* test */
	int we_are_HITg;

	HIP_DEBUG("state=%s\n", hip_state_str(state));

	nes = hip_get_param(msg, HIP_PARAM_NES);

	/* draft-09 8.10.1 Processing an initial UPDATE packet */

	/* 1. If the system is in state ESTABLISHED, it consults its
	 * policy to see if it needs to generate a new Diffie-Hellman
	 * key, and generates a new key if needed. If the system is in
	 * state REKEYING, it may already have generated a new
	 * Diffie-Hellman key, and SHOULD use it. */
	if (state == HIP_STATE_ESTABLISHED) {
		_HIP_DEBUG("8.10.1 case 1 TODO: need to rekey here ?\n");
		if (need_to_generate_key) {
			_HIP_DEBUG("would generate new D-H keys\n");
			/* generate_dh_key(); */
			dh_key_generated = 1;
		} else {
			dh_key_generated = 0;
		}
	}

#if 0
	if (state == HIP_STATE_REKEYING) {
			dh_key_generated = 1; ?
	}
#endif
	_HIP_DEBUG("dh_key_generated=%d\n", dh_key_generated);

	/* 2. If either the received UPDATE contains a new
	 * Diffie-Hellman key, the system has a new Diffie-Hellman key
	 * from the previous step, or both, the system generates new
	 * KEYMAT. If there is only one new Diffie-Hellman key, the
	 * other old key is used. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		_HIP_DEBUG("would generate new keymat\n");
		/* generate_new_keymat(); */
		new_keymat_generated = 1;
	} else {
		new_keymat_generated = 0;
	}

	_HIP_DEBUG("new_keymat_generated=%d\n", new_keymat_generated);

	/* 3. If the system generated new KEYMAT in the previous step,
	 * it sets Keymat Index to zero, independent on whether the
	 * received UPDATE included a Diffie-Hellman key or not. */
	if (new_keymat_generated) {
		our_current_keymat_index = 0;
	} else {
		/* check */
		if (!hip_hadb_get_keymat_index_by_hit(hits, &our_current_keymat_index)) {
			HIP_ERROR("Could not get our_current_keymat_index\n");
			err = -EINVAL;
			goto out_err;
		}
	}

#if 1
	if (!hip_hadb_get_keymat_index_by_hit(hits, &our_current_keymat_index)) {
		HIP_ERROR("Could not get our_current_keymat_index\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("our_current_keymat_index=%d\n", our_current_keymat_index);
#endif

	/* 4. The system draws keys for new incoming and outgoing ESP
	 * SAs, starting from the Keymat Index, and prepares new
	 * incoming and outgoing ESP SAs.  The SPI for the outgoing SA
	 * is the new SPI value from the received UPDATE. The SPI for
	 * the incoming SA is locally generated, and SHOULD be random.
	 * The system MUST NOT start using the new outgoing SA before
	 * it receives traffic on the new incoming SA. */

	{
		/* E X P E R I M E N T A L */

//		uint16_t ki;
		unsigned long int flags = 0;
		struct hip_hadb_state *entry;
		int esp_transf_length;
		int auth_transf_length;
		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		hip_hadb_acquire_ex_db_access(&flags); /* need rw */
		entry = hip_hadb_access_db(hits, HIP_ARG_HIT);
		if (!entry) {
			HIP_ERROR("entry not found\n");
			goto qwe;
		}

		esp_transform = entry->esp_transform; /* test */
		esp_transf_length = hip_enc_key_length(esp_transform);
		auth_transf_length = hip_auth_key_length_esp(esp_transform);
		HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

		calc_index_new = entry->keymat_calc_index;
		keymat_offset_new = 0x7fff & ntohs(nes->keymat_index);
		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);

		we_are_HITg = hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer);
		if (we_are_HITg)
			HIP_DEBUG("we are: HITg\n");
		else
			HIP_DEBUG("we are: HITl\n");

		/* if testing keymat_offset_new += random */

		/* SA-gl */

		err = hip_keymat_get_new(entry, &espkey_gl.key, esp_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("enckey_gl hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		HIP_HEXDUMP("ENC KEY gl", &espkey_gl.key, esp_transf_length);

		keymat_offset_new += esp_transf_length;
		err = hip_keymat_get_new(entry, &authkey_gl.key, auth_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("authkey_gl hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		HIP_HEXDUMP("AUTH KEY gl", &authkey_gl.key, auth_transf_length);

		/* SA-lg */

		keymat_offset_new += auth_transf_length;
		err = hip_keymat_get_new(entry, &espkey_lg.key, esp_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("enckey_lg hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		HIP_HEXDUMP("ENC KEY lg", &espkey_lg.key, esp_transf_length);

		keymat_offset_new += esp_transf_length;
		err = hip_keymat_get_new(entry, &authkey_lg.key, auth_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("authkey_lg hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		HIP_HEXDUMP("AUTH KEY lg", &authkey_lg.key, auth_transf_length);

		keymat_offset_new += auth_transf_length;

		/* update entry keymat later */
		err = hip_update_entry_keymat(entry, NULL, keymat_offset_new, calc_index_new, Kn);
	qwe:
		hip_hadb_release_ex_db_access(flags);
		if (err)
			goto out_err;
	}


	/* oikein ?: set up new incoming IPsec SA */
	/* The system MUST NOT start using the new outgoing SA
	   before it receives traffic on the new incoming SA. */
	HIP_DEBUG("Try to set up new incoming SA\n");
	err = hip_setup_sa(hitr /*src*/, hits /*dst*/,
			   &peer_new_spi, esp_transform,
			   we_are_HITg ? &espkey_lg : &espkey_gl,
			   we_are_HITg ? &authkey_lg : &authkey_gl,
			   0);
#if 0
	/* kludge: fix hip_setup_spi_and_sa parameters */
	err = hip_setup_spi_and_sa(hitr /*src*/, hits /*dst*/,
//	err = hip_setup_spi_and_sa(hits /*src*/, hitr /*dst*/,
//				   &our_new_spi, esp_transform,
				   &peer_new_spi, esp_transform,
				   we_are_HITg ? &espkey_lg : &espkey_gl,
				   we_are_HITg ? &authkey_lg : &authkey_gl,
				   //&espkey_peer, &authkey_peer,
				   0);
//#else
	err = hip_setup_spi_and_sa(we_are_HITg ? hitr : hits,
				   we_are_HITg ? hits : hitr,
//				   &our_new_spi, esp_transform,
				   &spi_gl, esp_transform,
				   &espkey_gl, &authkey_gl,
				   //&espkey_peer, &authkey_peer,
				   0);
#endif
	if (err) {
		if (we_are_HITg)
			HIP_ERROR("Error while setting up new SPI for SA-gl (err=%d)\n", err);
		else
			HIP_ERROR("Error while setting up new SPI for SA-lg (err=%d)\n", err);
		goto out_err;
	}

	_HIP_DEBUG("Set up new outgoing HITg->HITl SA SPI=0x%x\n", our_new_spi);
	if (we_are_HITg)
		HIP_DEBUG("Set up new incoming HITg->HITl SA SPI=0x%x\n", peer_new_spi);
	else
		HIP_DEBUG("Set up new incoming HITl->HITg SA SPI=0x%x\n", peer_new_spi);

	/* remember previous our SPI before new SPI is set to hadb */
	if (hip_hadb_get_info(hits, &peer_prev_spi,
			      HIP_HADB_PEER_SPI|HIP_ARG_HIT) != 1) {
		/* swap interpretation of HIP_HADB_PEER_SPI and OWN_SPI */
		HIP_ERROR("prev peer spi, get info (err=%d)\n", err);
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("updated incoming SPI, peer_new_spi=0x%x\n", peer_new_spi);

	/* oikein: set up new outgoing IPsec SA */
	/* check: shouldn't do this yet, but this is just a test */
	our_new_spi = ntohl(nes->new_spi);
	err = hip_setup_sa(hits /*dst*/, hitr /*src*/,
			   &our_new_spi, esp_transform,
			   we_are_HITg ? &espkey_gl : &espkey_lg,
			   we_are_HITg ? &authkey_gl : &authkey_lg,
			   1);
#if 0
	err = hip_setup_ipsec(hits /*dst*/, hitr /*src*/,
//			      peer_new_spi, esp_transform,
			      our_new_spi, esp_transform,
			      we_are_HITg ? &espkey_gl : &espkey_lg,
			      we_are_HITg ? &authkey_gl : &authkey_lg,
			      1);
//#else
	err = hip_setup_ipsec(we_are_HITg ? hits : hitr,
			      we_are_HITg ? hitr : hits,
			      peer_new_spi, esp_transform,
			      &espkey_lg, &authkey_lg,
			      1);
#endif
	if (err) {
		HIP_ERROR("Setting up new outbound HITl->HITg IPsec SA-lg failed (%d)\n", err);
		goto out_err;
	}
	if (we_are_HITg)
		HIP_DEBUG("Set up new outgoing HITg->HITl IPsec SA-lg, SPI=0x%x\n", our_new_spi);
	else
		HIP_DEBUG("Set up new outgoing HITl->HITg IPsec SA-lg, SPI=0x%x\n", our_new_spi);

	/* update our SPI in hadb */
	if (hip_hadb_set_info(hits, &our_new_spi,
//	if (hip_hadb_set_info(hits, &peer_new_spi,
			      HIP_HADB_OWN_SPI|HIP_ARG_HIT) != 1) {
		/* swap interpretation of HIP_HADB_PEER_SPI and OWN_SPI */
		HIP_ERROR("Updating hadb entry failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("updated outbound SPI, our_new_spi=0x%x\n", our_new_spi);
	err = 0;


	/* test code */
	/* store peer's new SPI in hadb, it is changed when data is received from the new SPI */
//	if (hip_hadb_set_info(hits, &peer_new_spi,
	if (hip_hadb_set_info(hits, &our_new_spi,
			      HIP_HADB_PEER_NEW_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Could not store New SPI value to hadb (our_new_spi)\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("Stored peer's New SPI to our_new_spi for future use\n");


	/* MUST NOT DO THIS, BUT THIS IS JUST TEST CODE. */
//	if (hip_hadb_set_info(hits, &peer_new_spi,
	if (hip_hadb_set_info(hits, &our_new_spi,
			      HIP_HADB_PEER_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Updating hadb entry failed (%d), our new spi\n", err);
		goto out_err;
	}
	HIP_DEBUG("TESTING: ALREADY SET PEER OUTBOUND SPI TO 0x%x\n", our_new_spi);
	err = 0;

#if 0
	/* set to dying/drop old IPsec SA ? */
	HIP_DEBUG("HACK: REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", our_prev_spi);
	err = hip_delete_sa(our_prev_spi, hitr, hits);
	HIP_DEBUG("delete_sa retval=%d\n", err );
	err = 0;

	/* set to dying/drop old IPsec SA ? */
	peer_prev_spi = htonl(nes->old_spi);
	HIP_DEBUG("HACK: REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", peer_prev_spi);
	err = hip_delete_sa(peer_prev_spi, hits, hitr);
	HIP_DEBUG("delete_sa retval=%d\n", err );
	err = 0;
#endif

	/* 5. The system prepares a reply UPDATE packet, with the R-bit one in
	 * the NES TLV, Keymat Index being the one used above, UPDATE ID
	 * being equal to the one in the received UPDATE, old SPI being the
	 * current incoming SPI, and new SPI being the newly generated
	 * incoming SPI.  If the system generated a new Diffie-Hellman key
	 * above, the new key is included in the packet in the
	 * Diffie-Hellman payload.  Note that if the system is in state
	 * REKEYING, the new Diffie-Hellman key was probably generated and
	 * sent already earlier, in which case it MUST NOT be included into
	 * the reply packet. */
	
	/* create and send reply UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_DEBUG("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, hitr, hits);
	err = hip_build_param_nes(update_packet, 1,
				  our_current_keymat_index, ntohs(nes->update_id),
				  our_prev_spi, our_new_spi);
	if (err) {
		HIP_ERROR("Building of NES failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	if (!hip_hadb_get_info(hits, &hmac,
			       HIP_HADB_OWN_HMAC|HIP_ARG_HIT)) {
		HIP_ERROR("No own HMAC key found\n");
		err = -ENOENT;
		goto out_err;
	}
	err = hip_build_param_hmac_contents(update_packet, &hmac);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("HMAC added\n");

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get our host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(update_packet, hip_get_msg_total_len(update_packet),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign UPDATE. Failing\n");
		err = -EINVAL;
		goto out_err;
	}
	    
	err = hip_build_param_signature_contents(update_packet, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	HIP_DEBUG("SIGNATURE added\n");

	/* send reply UPDATE */
        err = hip_hadb_get_peer_address(hits, &daddr, HIP_ARG_HIT);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

        HIP_DEBUG("Sending reply UPDATE packet\n");
	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
                /* goto out_err; ? */
	}

 out_err:
	if (update_packet)
		kfree(update_packet);
	/* TODO: REMOVE IPSEC SAs */
	if (err && our_new_spi)
		hip_delete_sa(our_new_spi, hits);
	return err;
}


/**
 * hip_handle_update_reply - handle incoming reply UPDATE packet
 * @msg: the HIP packet
 * @state: the state in which we are with the peer
 *
 * This function handles case 9 in draft-09 section "8.10
 * Processing UPDATE packets".
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_reply(struct hip_common *msg, struct in6_addr *src_ip, int state /*, int is_reply*/)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	struct hip_common *update_packet = NULL;
	struct hip_dh_fixed *dh;
	int getlist[3];
	void *setlist[3];
	int esp_transform;
	struct hip_crypto_key espkey_own, authkey_own;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	int need_to_generate_key, dh_key_generated, new_keymat_generated;
	uint16_t current_keymat_index;
	uint32_t our_new_spi = 0;  /* inbound IPsec SA SPI */
	uint32_t peer_new_spi = 0; /* outbound IPsec SA SPI */
	uint32_t peer_prev_spi;
	int hadb_state;
	int we_are_HITg;

	/* draft-09 8.10.2 Processing a reply UPDATE packet */

	HIP_DEBUG("state=%s\n", hip_state_str(state));

	nes = hip_get_param(msg, HIP_PARAM_NES);

	/* 1. If either the received UPDATE contains a new
	 * Diffie-Hellman key, the system has a new Diffie-Hellman key
	 * from initiating rekey, or both, the system generates new
	 * KEYMAT. If there is only one new Diffie-Hellman key, the
	 * old key is used as the other key. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/* generate_new_keymat(); */
		new_keymat_generated = 1;
	} else {
		new_keymat_generated = 0;
	}

	HIP_DEBUG("new_keymat_generated=%d\n", new_keymat_generated);

	/* 2. If the system generated new KEYMAT in the previous step,
	 * it sets Keymat Index to zero, independent on whether the
	 * received UPDATE included a Diffie-Hellman key or not. */
	if (new_keymat_generated) {
		current_keymat_index = 0;
	} else {
		if (!hip_hadb_get_keymat_index_by_hit(hits, &current_keymat_index)) {
			HIP_ERROR("Could not get current_keymat_index\n");
			err = -EINVAL;
			goto out_err;
		}
	}

	HIP_DEBUG("current_keymat_index=%u\n", current_keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	 * SAs, starting from the Keymat Index, and prepares new
	 * incoming and outgoing ESP SAs. The SPI for the outgoing SA
	 * is the new SPI value from the UPDATE.  The SPI for the
	 * incoming SA was generated when rekey was initiated. */

	{
		/* E X P E R I M E N T A L */
		//uint16_t ki = 0x7fff & ntohs(nes->keymat_index);
		unsigned long int flags = 0;
		struct hip_hadb_state *entry;
		int esp_transf_length;
		int auth_transf_length;
		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		hip_hadb_acquire_ex_db_access(&flags); /* need rw */
		entry = hip_hadb_access_db(hits, HIP_ARG_HIT);
		if (!entry) {
			HIP_ERROR("entry not found\n");
			goto qwe;
		}

		we_are_HITg = hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer);
		if (we_are_HITg)
			HIP_DEBUG("we are: HITg\n");
		else
			HIP_DEBUG("we are: HITl\n");


		esp_transform = entry->esp_transform; /* test */
		esp_transf_length = hip_enc_key_length(esp_transform);
		auth_transf_length = hip_auth_key_length_esp(esp_transform);
		HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

		calc_index_new = entry->keymat_calc_index;

		keymat_offset_new = 0x7fff & ntohs(nes->keymat_index);
		if (keymat_offset_new > current_keymat_index) {
			HIP_DEBUG("using keymat index from reply update packet\n");
			current_keymat_index = keymat_offset_new;
		}

		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);

		/* SA-gl */
//		err = hip_keymat_get_new(entry, &espkey_own.key, esp_transf_length, entry->dh_shared_key,
		err = hip_keymat_get_new(entry, &espkey_gl.key, esp_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("enckey_gl hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (!err)
			HIP_HEXDUMP("ENC KEY gl", &espkey_gl.key, esp_transf_length);

		keymat_offset_new += esp_transf_length;
//		err = hip_keymat_get_new(entry, &authkey_own.key, auth_transf_length, entry->dh_shared_key,
		err = hip_keymat_get_new(entry, &authkey_gl.key, auth_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("authkey_gl hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (!err)
			HIP_HEXDUMP("AUTH KEY gl", &authkey_gl.key, auth_transf_length);

		keymat_offset_new += auth_transf_length;

		/* SA-lg */
//		err = hip_keymat_get_new(entry, &espkey_own.key, esp_transf_length, entry->dh_shared_key,
		err = hip_keymat_get_new(entry, &espkey_lg.key, esp_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("enckey_lg hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (!err)
			HIP_HEXDUMP("ENC KEY lg", &espkey_lg.key, esp_transf_length);

		keymat_offset_new += esp_transf_length;
//		err = hip_keymat_get_new(entry, &authkey_own.key, auth_transf_length, entry->dh_shared_key,
		err = hip_keymat_get_new(entry, &authkey_lg.key, auth_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("authkey_lg hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (!err)
			HIP_HEXDUMP("AUTH KEY lg", &authkey_lg.key, auth_transf_length);

		keymat_offset_new += auth_transf_length;

		/* update entry keymat later */
		err = hip_update_entry_keymat(entry, NULL, keymat_offset_new, calc_index_new, Kn);
	qwe:
		//HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);
		hip_hadb_release_ex_db_access(flags);
		if (err)
			goto out_err;
	}


	/* set up new outbound IPsec SA */
	peer_new_spi = ntohl(nes->new_spi);
	err = hip_setup_sa(hits /*dst*/, hitr /*src*/,
			   &peer_new_spi, esp_transform,
			   we_are_HITg ? &espkey_gl : &espkey_lg,
			   we_are_HITg ? &authkey_gl : &authkey_lg,
			   1);
#if 0
	err = hip_setup_ipsec(hits /*dst*/, hitr /*src*/,
			      peer_new_spi, esp_transform,
			      we_are_HITg ? &espkey_gl : &espkey_lg,
			      we_are_HITg ? &authkey_gl : &authkey_lg,
			      1);
//			      &espkey_own, &authkey_own, 1);
//#else
	err = hip_setup_spi_and_sa(we_are_HITg ? hitr : hits,
				   we_are_HITg ? hits : hitr,
				   &peer_new_spi, esp_transform,
				   &espkey_gl, &authkey_gl,
				   //&espkey_peer, &authkey_peer,
				   1);
#endif
	if (err) {
		HIP_ERROR("Setting up new outbound IPsec failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("Set up new outbound IPsec SA, SPI=0x%x\n", peer_new_spi);

#if 0
	if (!hip_hadb_get_info(hits, &prev_peer_spi,
			       HIP_HADB_PEER_SPI|HIP_ARG_HIT)) {
		HIP_ERROR("No prev peer SPI found\n");
		err = -ENOENT;
		goto out_err;
	}
	/* set to dying/drop old IPsec SA ? */
	HIP_DEBUG("HACK: REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_peer_spi);
	err = hip_delete_sa(prev_peer_spi, hits, hitr);
	HIP_DEBUG("delete_sa retval=%d\n", err);
	err = 0;
#endif

	/* update peer SPI in hadb */
	if (hip_hadb_set_info(hits, &peer_new_spi, HIP_HADB_PEER_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Updating hadb entry failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("updated outbound SPI, peer_new_spi=0x%x\n", peer_new_spi);
	err = 0;

	/* use the new inbound IPsec SA created when rekeying started */
	if (hip_hadb_get_info(hits, &our_new_spi,
			      HIP_HADB_OWN_NEW_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("No own new SPI found\n");
		err = -ENOENT;
		goto out_err;
	}
	HIP_DEBUG("switching to new updated inbound SPI=0x%x, new_spi_our\n", our_new_spi);
	if (hip_hadb_set_info(hits, &our_new_spi,
			      HIP_HADB_OWN_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Could not set our SPI value to hadb\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("switch ok\n");

	/* Go back to ESTABLISHED state */
	HIP_DEBUG("Went back to ESTABLISHED state\n");
	hadb_state = HIP_STATE_ESTABLISHED;
	hip_hadb_set_info(hits, &hadb_state, HIP_HADB_STATE|HIP_ARG_HIT);

 out_err:
	if (update_packet)
		kfree(update_packet);
	/* TODO: REMOVE IPSEC SAs */
	return err;
}

/**
 * hip_receive_update - receive UPDATE packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an UPDATE packet
 * is received. The validity of the packet is checked and then this
 * function acts according to whether this packet is a reply or not.
 *
 * Returns: 0 if successful (HMAC and signature (if needed) are
 * validated, and the rest of the packet is handled if current state
 * allows it), otherwise < 0.
 */
int hip_receive_update(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *msg;
	struct in6_addr *hits;
	struct hip_nes *nes;
	int state = 0;
	uint16_t pkt_update_id; /* UPDATE ID in packet */
	uint16_t update_id_in;  /* stored incoming UPDATE ID */
	int is_reply;           /* the R bit in NES */
	uint16_t keymat_index;
	struct hip_dh_fixed *dh;
	struct in6_addr *src_ip;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;
	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));

	src_ip = &(skb->nh.ipv6h->saddr);
	hits = &msg->hits;

	if (!hip_hadb_get_state_by_hit(hits, &state)) {
		HIP_ERROR("Could not find state for HIT\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("Received UPDATE in state %s\n", hip_state_str(state));

	nes = hip_get_param(msg, HIP_PARAM_NES);
	if (!nes) {
		HIP_ERROR("UPDATE contained no NES parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("NES found\n");

	is_reply = ntohs(nes->keymat_index) & 0x8000 ? 1 : 0;
	keymat_index = 0x7fff & ntohs(nes->keymat_index);
	pkt_update_id = ntohs(nes->update_id);

	HIP_DEBUG("NES: is reply packet: %s\n", is_reply ? "yes" : "no");
	HIP_DEBUG("NES: Keymaterial Index: %u\n", keymat_index);
	HIP_DEBUG("NES: UPDATE ID: %u\n", pkt_update_id);
	HIP_DEBUG("NES: Old SPI: 0x%x\n", ntohl(nes->old_spi));
	HIP_DEBUG("NES: New SPI: 0x%x\n", ntohl(nes->new_spi));

	/* draft-09: 8.10 Processing UPDATE packets checks */

	/* 1. If the system is in state ESTABLISHED and the UPDATE has
	 * the R-bit set in the NES TLV, the packet is silently
	 * dropped. */
	if (is_reply && state == HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Received UPDATE packet is a reply and state is ESTABLISHED. Dropping\n");
		err = 0; /* ok case */
		goto out_err;
	}

 	/* 2. If the UPDATE ID in the received UPDATE is smaller than
	 * the stored incoming UPDATE ID, the packet MUST BE
	 * dropped. */
	if (!hip_hadb_get_update_id_in_by_hit(hits, &update_id_in)) {
		HIP_ERROR("Could not find previous incoming UPDATE ID value for HIT\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
	if (!is_reply && pkt_update_id < update_id_in) {

		HIP_DEBUG("Not a reply and received UPDATE ID (%u) < stored incoming UPDATE ID (%u). Dropping\n",
			  pkt_update_id, update_id_in);
		err = -EINVAL;
		goto out_err;
	} else if (pkt_update_id == update_id_in) {
		HIP_DEBUG("Retransmitted UPDATE packet (?), continuing\n");
		/* todo: ignore this packet or process anyway ? */
	}

	/* 3. The system MUST verify the HMAC in the UPDATE packet.
	 * If the verification fails, the packet MUST be dropped. */

        /* verify HMAC */
	err = hip_verify_packet_hmac(msg);
	if (err) {
		HIP_ERROR("HMAC validation on UPDATE failed\n");
		goto out_err;
	}
        HIP_DEBUG("UPDATE HMAC ok\n");

	/* 4. If the received UPDATE contains a Diffie-Hellman
	 * parameter, the received Keymat Index MUST be zero. If this
	 * test fails, the packet SHOULD be dropped and the system
	 * SHOULD log an error message.*/
	HIP_DEBUG("packet keymat_index=%u\n", keymat_index);
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		if (keymat_index != 0) {
			/* SHOULD -> we currently drop */
			HIP_ERROR("UPDATE contains Diffie-Hellman parameter with non-zero"
				  "keymat value %u in NES. Dropping\n",
				  keymat_index);
			err = -EINVAL;
			goto out_err;
		}
	} else 	{
		uint16_t current_keymat_index;

		HIP_DEBUG("packet does not contain DH\n");

		/* 5. If the received UPDATE does not contain a
		   Diffie-Hellman parameter, the received Keymat Index
		   MUST be larger or equal to the index of the next
		   byte to be drawn from the current KEYMAT. If this
		   test fails, the packet SHOULD be dropped and the
		   system SHOULD log an error message.*/
		if (!hip_hadb_get_keymat_index_by_hit(hits, &current_keymat_index)) {
			HIP_ERROR("Could not get current_keymat_index\n");
			err = -EINVAL;
			goto out_err;
		}
		HIP_DEBUG("current_keymat_index=%d\n", current_keymat_index);

		/* test only incoming keymat index instead of this ? */
		if (current_keymat_index == 0x7fff) { /* max value of keymat index */
			HIP_ERROR("current keymat index would overflow from 0x7fff to 0, bug ? Dropping\n");
			err = -EINVAL;
			goto out_err;
		}

		if (keymat_index < current_keymat_index) {
			HIP_DEBUG("Received UPDATE KEYMAT Index (%u) < stored KEYMAT Index (%u). Dropping\n",
				  keymat_index, current_keymat_index);
			err = -EINVAL;
			goto out_err;
		}
	}

	/* 6. The system MAY verify the SIGNATURE in the UPDATE
	 * packet. If the verification fails, the packet SHOULD be
	 * dropped and an error message logged. */

	/* MAY -> we currently do */

        /* Verify SIGNATURE */
	{
		struct hip_lhi peer_lhi;
		struct hip_host_id *peer_id;

                peer_lhi.anonymous = 0;
                memcpy(&peer_lhi.hit, &msg->hits, sizeof(struct in6_addr));
                peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
                if (!peer_id) {
                        HIP_ERROR("Unknown peer (no identity found)\n");
                        err = -EINVAL;
                        goto out_err;
                }

		err = hip_verify_packet_signature(msg, peer_id);
		if (err) {
			HIP_ERROR("Verification of UPDATE signature failed\n");
			err = -EINVAL;
			goto out_err;
		}
	}
 
        HIP_DEBUG("SIGNATURE ok\n");

	/* 7. The system MUST record the UPDATE ID in the received
	 * packet, for replay protection. */

	if (!is_reply) {
//		getlist[0] = HIP_HADB_OWN_UPDATE_ID_IN;
//		if (!hip_hadb_set_update_id_in_by_hit(hits, tmp_list, &pkt_update_id)) {
		if (!hip_hadb_set_info(hits, &pkt_update_id, HIP_HADB_OWN_UPDATE_ID_IN|HIP_ARG_HIT)) {
			HIP_ERROR("Could not set incoming UPDATE ID value (%u) for HIT\n", pkt_update_id);
			err = -EINVAL;
			goto out_err;
		}
		HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}

	/* todo: check that Old SPI value exists ? */
	/* cases 8-10: */

	switch(state) {
	case HIP_STATE_ESTABLISHED:
		if (!is_reply) {
			HIP_DEBUG("case 8: established and is not reply\n");
			err = hip_handle_update_initial(msg, src_ip, state);
		}
		break;
	case HIP_STATE_REKEYING:
		if (is_reply) {
			HIP_DEBUG("case 9: rekeying and is reply\n");
			err = hip_handle_update_reply(msg, src_ip, state);
		} else {
			HIP_DEBUG("case 10: rekeying and is not reply\n");
			err = hip_handle_update_initial(msg, src_ip, state);
		}
		break;
	default:
		HIP_ERROR("Received UPDATE in illegal state %s. Dropping\n", hip_state_str(state));
		err = -EINVAL;
		goto out_err;
		break;
	}

	if (err) {
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);
		goto out_err;
	}

 out_err:
	return err;
}


int hip_send_update(struct hip_hadb_state *entry)
{
	int err = 0;
	uint16_t update_id_out;
	uint32_t new_spi = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr daddr;
	struct hip_crypto_key hmac;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	//int tmp_list[3];
	struct hip_crypto_key espkey_new, authkey_new;
	//uint16_t orig_keymat_index = entry->current_keymat_index;
	int esp_transform;
	int esp_transf_length;
	int auth_transf_length;

	HIP_DEBUG("\n");

	if (!entry) {
		HIP_ERROR("null entry\n");
		err = -EINVAL;
		goto out_err;
	}

	hip_print_hit("send UPDATE to", &entry->hit_peer);

#if 0
	/* get new keymat */
	{
		/* E X P E R I M E N T A L */

	  //		uint16_t ki = entry->current_keymat_index;

		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		esp_transform = entry->esp_transform;
		HIP_DEBUG("esp_transform=%d\n", esp_transform);
		esp_transf_length = hip_enc_key_length(esp_transform);
		auth_transf_length = hip_auth_key_length_esp(esp_transform);

		calc_index_new = entry->keymat_calc_index;
		keymat_offset_new = entry->current_keymat_index;;
		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);

		HIP_DEBUG("enckeylen=%d authkeylen=%d calc_index_new=%u keymat_offset_new=%u\n",
			  esp_transf_length, auth_transf_length, calc_index_new, keymat_offset_new);

		if (esp_transf_length < 0 || auth_transf_length < 0) {
			err = -EINVAL;
			HIP_DEBUG("enc_key_length failed\n");
			goto qwe;
		}

		if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer)) {
		  //			keymat_offset_new += esp_transf_length + auth_transf_length;
			HIP_DEBUG("we are: HITg\n");
			HIP_DEBUG("skip SA-gl keys, keymat_offset_new=%u\n", keymat_offset_new);
		} else
			HIP_DEBUG("we are: HITl\n");

		err = hip_keymat_get_new(entry, &espkey_new.key, esp_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("enckey hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer))
			HIP_HEXDUMP("new SA-gl outgoing ENC KEY", &espkey_new.key, esp_transf_length);
		else
			HIP_HEXDUMP("new SA-lg outgoing ENC KEY", &espkey_new.key, esp_transf_length);

		keymat_offset_new += esp_transf_length;
		err = hip_keymat_get_new(entry, &authkey_new.key, auth_transf_length, entry->dh_shared_key,
					 entry->dh_shared_key_len, &keymat_offset_new, &calc_index_new, Kn);
		HIP_DEBUG("authkey hip_keymat_get_new ret err=%d keymat_offset_new=%u calc_index_new=%u\n",
			  err, keymat_offset_new, calc_index_new);
		if (err)
			goto qwe;

		if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer))
			HIP_HEXDUMP("new SA-lg outgoing AUTH KEY", &authkey_new.key, auth_transf_length);
		else
			HIP_HEXDUMP("new SA-gl outgoing AUTH KEY", &authkey_new.key, auth_transf_length);

		err = hip_update_entry_keymat(entry, NULL, keymat_offset_new, calc_index_new, Kn);
	qwe:
		if (err)
			goto out_err;
	}
#endif
	HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);
#if 0
	esp_transform = entry->esp_transform;
	HIP_DEBUG("esp_transform=%d\n", esp_transform);
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);
#endif
	/* we can not know yet from where we should start to draw keys
	   from the keymat, so we just set the keys to some value and fill in
	   the keys later */
	get_random_bytes(&espkey_new.key, HIP_MAX_KEY_LEN);
	get_random_bytes(&authkey_new.key, HIP_MAX_KEY_LEN);
	HIP_HEXDUMP("random espkey", &espkey_new.key, HIP_MAX_KEY_LEN);
	HIP_HEXDUMP("random authkey", &authkey_new.key, HIP_MAX_KEY_LEN);

	/* The specifications does not say that new SA should be done
	 * here, but it is needed because of the New SPI value */
	/* get a New SPI to use and prepare IPsec SA */
	new_spi = 0;
	err = hip_setup_sa(&entry->hit_our, &entry->hit_peer,
			   &new_spi, entry->esp_transform,
			   &espkey_new.key, &authkey_new.key, 0); /* sa state is larval */

#if 0
	err = hip_setup_spi_and_sa(&entry->hit_our, &entry->hit_peer,
				   &new_spi, entry->esp_transform,
				   &espkey_new.key, &authkey_new.key, 0); /* sa state is larval */
#endif
	/* todo: if hip_setup_spi_and_sa failed due to
	   sadb_key_to_auth random keys could be weak, try again a
	   couple of times ? */
	if (err) {
		HIP_ERROR("Error while setting up New SPI (err=%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("New SPI=0x%x\n", new_spi);

#if 1
	if (hip_hadb_set_info(&entry->hit_peer, &new_spi,
			      HIP_HADB_OWN_NEW_SPI|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Could not set New SPI value to hadb, our_new_spi\n");
		err = -EINVAL;
		goto out_err;
	}
#endif
	HIP_DEBUG("stored New SPI for future use\n");
	HIP_DEBUG("** TODO: update entry keys **\n");

	/* start building UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, &entry->hit_our, &entry->hit_peer);

	update_id_out = hip_get_new_update_id();
	HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) {
		/* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}

	/* todo: move below */
	if (hip_hadb_set_info(&entry->hit_peer, &update_id_out,
			      HIP_HADB_OWN_UPDATE_ID_OUT|HIP_ARG_HIT) != 1) {
		HIP_ERROR("Could not set outgoing UPDATE ID value (%u) for HIT\n", update_id_out);
		err = -EINVAL;
		goto out_err;
	}
        HIP_DEBUG("Stored peer's outgoing UPDATE ID %u\n", update_id_out);

	err = hip_build_param_nes(update_packet, 0, entry->current_keymat_index,
				  update_id_out, entry->spi_our, new_spi); 
	if (err) {
		HIP_ERROR("Building of NES param failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	if (!hip_hadb_get_info(&entry->hit_peer, &hmac,
			       HIP_HADB_OWN_HMAC|HIP_ARG_HIT)) {
		HIP_ERROR("could not get own HMAC\n");
		err = -ENOENT;
		goto out_err;
	}
	err = hip_build_param_hmac_contents(update_packet, &hmac);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("HMAC added\n");

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(update_packet, hip_get_msg_total_len(update_packet),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign UPDATE. Failing\n");
		err = -EINVAL;
		goto out_err;
	}
	    
	err = hip_build_param_signature_contents(update_packet, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	HIP_DEBUG("SIGNATURE added\n");

	/* todo: start SA timer, ipsec_sa_mod_timer ? */
	/* todo: add UPDATE to sent list */

	/* send UPDATE */
        HIP_DEBUG("Sending UPDATE packet\n");
        err = hip_hadb_get_peer_address(&entry->hit_peer, &daddr, HIP_ARG_HIT);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");

	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
                /* goto out_err; ? */
		/* fall back to established state ? */
	}

	/* todo: start retransmission timer */
	goto out;

 out_err:
	/* delete IPsec SA on failure */
/*	if (new_spi)
		hip_delete_sa(new_spi, &entry->hit_our, &entry->hit_peer);
*/
 out:
	if (update_packet)
		kfree(update_packet);

	return err;
}

/**
 * hip_send_update_all - send UPDATE packet to every peer
 *
 * UPDATE is sent to the peer only if the peer is in established
 * state. Note that we can not guarantee that the UPDATE actually reaches
 * the peer (unless the UPDATE is retransmitted some times, which we
 * currently don't do), due to the unreliable nature of IP we just
 * hope the UPDATE reaches the peer.
 *
 * TODO: retransmission timers
 */
void hip_send_update_all(void)
{
	/******* TEST FUNCTION, MAYBE (?) WE DON'T NEED TO SEND UPDATE
	 * FOR EVERY PEER SIMULTANEOUSLY .. *******/

	struct hip_hadb_state *entry;
	unsigned long int flags = 0;

	HIP_DEBUG("\n");

	hip_hadb_acquire_ex_db_access(&flags);
	list_for_each_entry(entry, &hip_hadb.db_head, next) {
		if (entry->state == HIP_STATE_ESTABLISHED) {
			(void) hip_send_update(entry);
		} else
		  HIP_DEBUG("REKEYING and not in ESTABLISHED state with the peer, skipping\n");
	}

	hip_hadb_release_ex_db_access(flags);
	return;
}
