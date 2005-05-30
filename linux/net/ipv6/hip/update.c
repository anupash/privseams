/*
 * Licence: GNU/GPL
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include "update.h"
#include "hadb.h"

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#ifndef __KERNEL__
/**
 * hip_print_hit - print a HIT
 * @str: string to be printed before the HIT
 * @hit: the HIT to be printed
 */
static inline void hip_print_hit(const char *str, const struct in6_addr *hit)
{
	char dst[INET6_ADDRSTRLEN];

	hip_in6_ntop(hit, dst);
	HIP_DEBUG("%s: %s\n", str, dst);
	return;
}
#endif

/** hip_update_get_sa_keys - Get keys needed by UPDATE
 * @entry: corresponding hadb entry of the peer
 * @keymat_offset_new: value-result parameter for keymat index used
 * @calc_index_new: value-result parameter for the one byte index used
 * @Kn_out: value-result parameter for keymat 
 * @espkey_gl: HIP-gl encryption key
 * @authkey_gl: HIP-gl integrity (HMAC)
 * @espkey_lg: HIP-lg encryption key
 * @authkey_lg: HIP-lg integrity (HMAC)
 *
 * Returns: 0 on success (all encryption and integrity keys are
 * successfully stored and @keymat_offset_new, @calc_index_new, and
 * @Kn_out contain updated values). On error < 0 is returned.
 */
int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl, struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg, struct hip_crypto_key *authkey_lg)
{
       	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t k = *keymat_offset_new, Kn_pos;
	uint8_t c = *calc_index_new;
	int err = 0, esp_transform, esp_transf_length = 0, auth_transf_length = 0;

	_HIP_DEBUG("k=%u c=%u\n", k, c);

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

	HIP_IFEL(*keymat_offset_new + 2*(esp_transf_length+auth_transf_length) > 0xffff, -EINVAL,
		 "Can not draw requested amount of new KEYMAT, keymat index=%u, requested amount=%d\n",
		 *keymat_offset_new, 2*(esp_transf_length+auth_transf_length));
	memcpy(Kn, Kn_out, HIP_AH_SHA_LEN);

	/* SA-gl */
	Kn_pos = entry->current_keymat_index - (entry->current_keymat_index % HIP_AH_SHA_LEN);
	HIP_IFE(hip_keymat_get_new(espkey_gl->key, esp_transf_length, entry->dh_shared_key,
				   entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("ENC KEY gl", espkey_gl->key, esp_transf_length);
	k += esp_transf_length;

	HIP_IFE(hip_keymat_get_new(authkey_gl->key, auth_transf_length, entry->dh_shared_key,
				   entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("AUTH KEY gl", authkey_gl->key, auth_transf_length);
	k += auth_transf_length;

	/* SA-lg */
	HIP_IFE(hip_keymat_get_new(espkey_lg->key, esp_transf_length, entry->dh_shared_key,
				   entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("ENC KEY lg", espkey_lg->key, esp_transf_length);
	k += esp_transf_length;
	HIP_IFE(hip_keymat_get_new(authkey_lg->key, auth_transf_length, entry->dh_shared_key,
				   entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("AUTH KEY lg", authkey_lg->key, auth_transf_length);
	k += auth_transf_length;

	_HIP_DEBUG("at end: k=%u c=%u\n", k, c);
	*keymat_offset_new = k;
	*calc_index_new = c;
	memcpy(Kn_out, Kn, HIP_AH_SHA_LEN);
 out_err:
	return err;
}

/** hip_update_test_rea_addr - test if IPv6 address is to be added into REA.
 * @addr: the IPv6 address to be tested
 *
 * Currently the following address types are ignored: unspecified
 * (any), loopback, link local, site local, and other not unicast
 * addresses.
 *
 * Returns 1 if address is ok to be used as a peer address, otherwise 0.
*/
int hip_update_test_rea_addr(struct in6_addr *addr)
{
#ifdef __KERNEL__
	int addr_type = ipv6_addr_type(addr);
	return !(addr_type == IPV6_ADDR_ANY ||
		 addr_type & IPV6_ADDR_LOOPBACK ||
		 addr_type & IPV6_ADDR_LINKLOCAL ||
		 addr_type & IPV6_ADDR_SITELOCAL ||
		 !(addr_type & IPV6_ADDR_UNICAST));
#else
	return !(IN6_IS_ADDR_UNSPECIFIED(addr) ||
		 IN6_IS_ADDR_LOOPBACK(addr) ||
		 IN6_IS_ADDR_LINKLOCAL(addr) ||
		 IN6_IS_ADDR_SITELOCAL(addr) ||
		 IN6_IS_ADDR_MULTICAST(addr));
#endif
}

/** hip_update_handle_rea_parameter - Process REA parameters in the UPDATE
 * @entry: corresponding hadb entry of the peer
 * @rea: the REA parameter in the packet
 *
 * ietf-mm-02 7.2 Handling received REAs
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if the REA parameter was processed successfully,
 * otherwise < 0.
 */
int hip_update_handle_rea_parameter(hip_ha_t *entry, struct hip_rea *rea)
{
	int err = 0; /* set to -Esomething ?*/
	uint32_t spi;
	struct hip_rea_info_addr_item *rea_address_item;
	int i, n_addrs;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *a, *tmp;

	spi = ntohl(rea->spi);
	HIP_DEBUG("REA SPI=0x%x\n", spi);

	if ((hip_get_param_total_len(rea) - sizeof(struct hip_rea)) %
	    sizeof(struct hip_rea_info_addr_item))
		HIP_ERROR("addr item list len modulo not zero, (len=%d)\n",
			  ntohs(rea->length));

	n_addrs = (hip_get_param_total_len(rea) - sizeof(struct hip_rea)) /
		sizeof(struct hip_rea_info_addr_item);
	HIP_ASSERT(n_addrs >= 0);

	HIP_DEBUG("REA has %d address(es), rea param len=%d\n",
		  n_addrs, hip_get_param_total_len(rea));

	/* 1. The host checks if the SPI listed is a new one. If it
	   is a new one, it creates a new SPI that contains no addresses. */
	/* If following exits, its a bug: outbound SPI must have been
	   already created by the corresponding NES in the same UPDATE
	   packet */
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, spi)), -1,
		 "Bug: outbound SPI 0x%x does not exist\n", spi);

	_HIP_DEBUG("Clearing old preferred flags of the SPI\n");
	list_for_each_entry_safe(a, tmp, &spi_out->peer_addr_list, list) {
		a->is_preferred = 0;
	}

	rea_address_item = (void *)rea + sizeof(struct hip_rea);
	for(i = 0; i < n_addrs; i++, rea_address_item++) {
		struct in6_addr *rea_address = &rea_address_item->address;
		uint32_t lifetime = ntohl(rea_address_item->lifetime);
		int is_preferred = ntohl(rea_address_item->reserved) == 1 << 31;

		hip_print_hit("REA address", rea_address);
		HIP_DEBUG(" addr %d: is_pref=%s reserved=0x%x lifetime=0x%x\n", i+1,
			   is_preferred ? "yes" : "no", ntohl(rea_address_item->reserved),
			  lifetime);
		/* 2. check that the address is a legal unicast or anycast address */
		if (!hip_update_test_rea_addr(rea_address))
			continue;

		if (i > 0) {
			/* preferred address allowed only for the first address */
			if (is_preferred)
				HIP_ERROR("bug, preferred flag set to other than the first address\n");
			is_preferred = 0;
		}
		/* 3. check if the address is already bound to the SPI + add/update address */
		HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, rea_address, 0,
						 lifetime, is_preferred), -1);
	}

	/* 4. Mark all addresses on the SPI that were NOT listed in the REA
	   parameter as DEPRECATED. */
	_HIP_DEBUG("deprecating not listed address from the SPI list\n");

	list_for_each_entry_safe(a, tmp, &spi_out->peer_addr_list, list) {
		int spi_addr_is_in_rea = 0;

		rea_address_item = (void *)rea+sizeof(struct hip_rea);
		for(i = 0; i < n_addrs; i++, rea_address_item++) {
			struct in6_addr *rea_address = &rea_address_item->address;

			if (!ipv6_addr_cmp(&a->address, rea_address)) {
				spi_addr_is_in_rea = 1;
				break;
			}

		}
		if (!spi_addr_is_in_rea) {
			/* deprecate the address */
			hip_print_hit("deprecating address", &a->address);
			a->address_state = PEER_ADDR_STATE_DEPRECATED;
		}
	}

	if (n_addrs == 0) /* our own extension, use some other SPI */
		(void)hip_hadb_relookup_default_out(entry);
	/* relookup always ? */

 out_err:
	return err;
}


/**
 * hip_handle_update_established - handle incoming UPDATE packet received in ESTABLISHED state
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 * @dst_ip: destination IPv6 address where the UPDATE was received
 *
 * This function handles case 7 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_established(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	struct hip_seq *seq;
	struct hip_rea *rea;
	struct hip_dh_fixed *dh;
	uint32_t update_id_out = 0;
	uint32_t prev_spi_in = 0, new_spi_in = 0;
	uint16_t keymat_index = 0, mask;
	struct hip_common *update_packet = NULL;
 	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */
	int err = 0, nes_i = 1, need_to_generate_key = 0, dh_key_generated = 0;
	
	HIP_DEBUG("\n");
	
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1, 
		 "No SEQ parameter in packet\n");

	/* 8.11.1  Processing an UPDATE packet in state ESTABLISHED */

	/* 1.  The system consults its policy to see if it needs to generate a
	   new Diffie-Hellman key, and generates a new key if needed. */
	_HIP_DEBUG("8.11.1 case 1 TODO: need to rekey here ?\n");
	if (need_to_generate_key) {
		_HIP_DEBUG("would generate new D-H keys\n");
		/* generate_dh_key(); */
		dh_key_generated = 1;
		/* todo: The system records any newly generated or
		   received Diffie-Hellman keys, for use in KEYMAT generation upon
		   leaving the REKEYING state. */
	} else {
		dh_key_generated = 0;
	}

	_HIP_DEBUG("dh_key_generated=%d\n", dh_key_generated);

	/* 4. The system creates a UPDATE packet, which contains an SEQ
	   parameter (with the current value of Update ID), NES parameter
	   and the optional DIFFIE_HELLMAN parameter. The UPDATE packet also
	   includes the ACK of the Update ID found in the received UPDATE
	   SEQ parameter. */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM, "Update_packet alloc failed\n");
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1, HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/*  3. The system increments its outgoing Update ID by one. */
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
        /* Todo: handle this case */
	HIP_IFEL(!update_id_out, -EINVAL, 
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");

	/* test: handle multiple NES, not tested well yet */
 handle_nes:
	if (!(nes = hip_get_nth_param(msg, HIP_PARAM_NES, nes_i))) {
		HIP_DEBUG("no more NES params found\n");
		goto nes_params_handled;
	}
	HIP_DEBUG("Found NES parameter [%d]\n", nes_i);

	/* 2. If the system generated new Diffie-Hellman key in the previous
	   step, or it received a DIFFIE_HELLMAN parameter, it sets NES
	   Keymat Index to zero. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/* todo: generate_new_keymat(); */
		keymat_index = 0;
	} else {
		/* Otherwise, the NES Keymat Index MUST be larger or
		   equal to the index of the next byte to be drawn from the
		   current KEYMAT. */
		HIP_IFEL(ntohs(nes->keymat_index) < entry->current_keymat_index, -1,
			 "NES Keymat Index (%u) < current KEYMAT %u\n",
			 ntohs(nes->keymat_index), entry->current_keymat_index);

		/* In this case, it is RECOMMENDED that the host use the
		   Keymat Index requested by the peer in the received NES. */

		/* here we could set the keymat index to use, but we
		 * follow the recommendation */
		_HIP_DEBUG("Using Keymat Index from NES\n");
		keymat_index = ntohs(nes->keymat_index);
	}

	/* Set up new incoming IPsec SA, (Old SPI value to put in NES tlv) */
	HIP_IFE(!(prev_spi_in = hip_get_spi_to_update_in_established(entry, dst_ip)), -1);
	HIP_IFEL(!(new_spi_in = hip_acquire_spi(hits, hitr)), -1, 
		 "Error while acquiring a SPI\n");

	HIP_DEBUG("Acquired inbound SPI 0x%x\n", new_spi_in);
	hip_update_set_new_spi_in(entry, prev_spi_in, new_spi_in, ntohl(nes->old_spi));

	/* draft-hip-mm test */
	if (nes->old_spi == nes->new_spi) {
		struct hip_spi_out_item spi_out_data;

		_HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(nes->new_spi);
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data), -1); 
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created yet)\n",
			  ntohl(nes->new_spi));
	}

	/* testing REA parameters in UPDATE */
	rea = hip_get_nth_param(msg, HIP_PARAM_REA, nes_i);
	if (rea) {
		HIP_DEBUG("Found REA parameter [%d]\n", nes_i);
		if (rea->spi != nes->new_spi) {
			HIP_ERROR("SPI 0x%x in REA is not equal to the New SPI 0x%x in NES\n",
				  ntohl(rea->spi), ntohl(nes->new_spi));
		} else {
			err = hip_update_handle_rea_parameter(entry, rea);
			_HIP_DEBUG("rea param handling ret %d\n", err);
			err = 0;
		}
	}

	/* associate Old SPI with Update ID, NES received, store
	 * received NES and proposed keymat index value used in the reply NES */
	hip_update_set_status(entry, prev_spi_in,
			      0x1 | 0x2 | 0x4 | 0x8, update_id_out, 0x2,
			      nes, keymat_index);

	nes_i++;
	goto handle_nes;

 nes_params_handled:

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING.  The system stores any received NES and DIFFIE_HELLMAN
	   parameters. */
	HIP_IFEL(hip_build_param_nes(update_packet, keymat_index,
				     prev_spi_in, new_spi_in), -1, 
		 "Building of NES failed\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ failed\n");

	/* ACK the received UPDATE SEQ */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1, 
		 "Building of ACK failed\n");

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out),
		 -1, "Building of HMAC failed\n");
	
	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), 
		 -EINVAL, "Could not sign UPDATE. Failing\n");

#if 0
        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);
#endif
	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING. */
	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");
        err = hip_hadb_update_xfrm(entry);
        if (err) {
                HIP_ERROR("XFRM synchronization failed\n");
                err = -EFAULT;
                goto out_err;
        }

	err = hip_csum_send(NULL, src_ip, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
		/* fallback to established ? */
                /* goto out_err; ? */
	}

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	if (err) {
		hip_set_spi_update_status(entry, prev_spi_in, 0);
		/* SA remove not tested yet */
		if (new_spi_in) {
			//hip_delete_sa(new_spi_in, hitr);
			hip_hadb_delete_inbound_spi(entry, new_spi_in);
		}
	}

	return err;
}

int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi);


/** hip_update_finish_rekeying - finish handling of REKEYING state
 * @msg: the HIP packet
 * @entry: hadb entry corresponding to the peer
 * @nes: the NES param to be handled in the received UPDATE
 * 
 * Performs items described in 8.11.3 Leaving REKEYING state of he
 * base draft-01.
 *
 * Parameters in @nes are host byte order.
 * @entry must be is locked when this function is called.
 *
 * On success new IPsec SAs are created. Old SAs are deleted if the
 * UPDATE was not the multihoming case.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_update_finish_rekeying(struct hip_common *msg, hip_ha_t *entry,
			       struct hip_nes *nes)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	uint8_t calc_index_new;
	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t keymat_index;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	uint32_t prev_spi_in = 0, prev_spi_out = 0;
	int we_are_HITg = 0, esp_transform = -1, esp_transf_length = 0, auth_transf_length = 0;
	struct hip_spi_in_item spi_in_data;
	struct hip_ack *ack;
	uint16_t kmindex_saved;

	HIP_DEBUG("\n");
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	HIP_DEBUG("handled NES: Old SPI: 0x%x\n", nes->old_spi);
	HIP_DEBUG("handled NES: New SPI: 0x%x\n", nes->new_spi);
	HIP_DEBUG("handled NES: Keymat Index: %u\n", nes->keymat_index);

	prev_spi_out = nes->old_spi;
	new_spi_out = nes->new_spi;
	
	HIP_ASSERT(prev_spi_out != 0 && new_spi_out != 0);

	prev_spi_in = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));

	/* use the new inbound IPsec SA created when rekeying started */
	HIP_IFEL(!(new_spi_in = hip_update_get_new_spi_in(entry, ntohl(ack->peer_update_id))), -1,
		 "Did not find related New SPI for peer Update ID %u\n", ntohl(ack->peer_update_id));
	HIP_DEBUG("prev_spi_in=0x%x new_spi_in=0x%x prev_spi_out=0x%x new_spi_out=0x%x\n",
		  prev_spi_in, new_spi_in, prev_spi_out, new_spi_out);

	HIP_IFEL(!(kmindex_saved = hip_update_get_spi_keymat_index(entry, ntohl(ack->peer_update_id))),
		 -1, "Saved kmindex is 0\n");

	_HIP_DEBUG("saved kmindex for NES is %u\n", kmindex_saved);

	/* 2. .. If the system did not generate new KEYMAT, it uses
	   the lowest Keymat Index of the two NES parameters. */
	_HIP_DEBUG("entry keymat index=%u\n", entry->current_keymat_index);
	keymat_index = kmindex_saved < nes->keymat_index ? kmindex_saved : nes->keymat_index;
	_HIP_DEBUG("lowest keymat_index=%u\n", keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	   SAs, starting from the Keymat Index, and prepares new incoming
	   and outgoing ESP SAs. */
	we_are_HITg = hip_hit_is_bigger(hitr, hits);
	HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);
	calc_index_new = entry->keymat_calc_index;
	memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
	HIP_IFE(hip_update_get_sa_keys(entry, &keymat_index, &calc_index_new, Kn,
				       &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg), -1);
	/* todo: update entry keymat later */
	hip_update_entry_keymat(entry, keymat_index, calc_index_new, Kn);

	/* set up new outbound IPsec SA */
#if 0
	HIP_IFEL(!hip_add_sa(hitr, hits, new_spi_out, esp_transform,
			     we_are_HITg ? &espkey_gl : &espkey_lg,
			     we_are_HITg ? &authkey_gl : &authkey_lg,
			     0, HIP_SPI_DIRECTION_OUT), -1,
		 "Setting up new outbound IPsec SA failed\n");
	HIP_IFEL(!hip_add_sa(hits, hitr, new_spi_in, esp_transform,
			     we_are_HITg ? &espkey_lg  : &espkey_gl,
			     we_are_HITg ? &authkey_lg : &authkey_gl,
			     1, HIP_SPI_DIRECTION_IN), -1,
		 "Setting up new inbound IPsec SA failed\n");
#endif
	HIP_DEBUG("Setting up new outbound SA, SPI=0x%x\n", new_spi_out);
	HIP_IFEL(new_spi_out != hip_add_sa(hitr, hits, new_spi_out, esp_transform,
					   we_are_HITg ? &espkey_gl : &espkey_lg,
					   we_are_HITg ? &authkey_gl : &authkey_lg,
					   0, HIP_SPI_DIRECTION_OUT), -1,
		 "Setting up new outbound IPsec SA failed\n");
	HIP_DEBUG("New outbound SA created with SPI=0x%x\n", new_spi_out);
	HIP_DEBUG("Setting up new inbound SA, SPI=0x%x\n", new_spi_in);
/*
	HIP_IFEL(new_spi_in != hip_add_sa(hits, hitr, new_spi_in, esp_transform,
					  we_are_HITg ? &espkey_lg  : &espkey_gl,
					  we_are_HITg ? &authkey_lg : &authkey_gl,
					  1, HIP_SPI_DIRECTION_IN), -1,
		 "Setting up new inbound IPsec SA failed\n");
*/
	err = hip_add_sa(hits, hitr, new_spi_in, esp_transform,
			 we_are_HITg ? &espkey_lg  : &espkey_gl,
			 we_are_HITg ? &authkey_lg : &authkey_gl,
			 1, HIP_SPI_DIRECTION_IN);
	HIP_DEBUG("err=%d\n", err);
	if (err)
		HIP_DEBUG("Setting up new inbound IPsec SA failed\n");


	HIP_DEBUG("New inbound SA created with SPI=0x%x\n", new_spi_in);

	if (prev_spi_in == new_spi_in) {
		memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
		spi_in_data.spi = new_spi_in;
		spi_in_data.ifindex = hip_hadb_get_spi_ifindex(entry, prev_spi_in);/* already set ? */
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1);
	} else
		_HIP_DEBUG("Old SPI <> New SPI, not adding a new inbound SA\n");

	/* Activate the new inbound and outbound SAs */
	//hip_finalize_sa(hitr, new_spi_in);
	//hip_finalize_sa(hits, new_spi_out);

	hip_update_switch_spi_in(entry, prev_spi_in);
	hip_update_set_new_spi_out(entry, prev_spi_out, new_spi_out); /* temporary fix */
	hip_update_switch_spi_out(entry, prev_spi_out);

	hip_set_spi_update_status(entry, new_spi_in, 0);
	hip_update_clear_status(entry, new_spi_in);

	// if (is not mm update) ?
	hip_hadb_set_default_out_addr(entry, hip_hadb_get_spi_list(entry, new_spi_out), NULL);

	/* 4.  The system cancels any timers protecting the UPDATE and
	   transitions to ESTABLISHED. */
	entry->state = HIP_STATE_ESTABLISHED;
        err = hip_hadb_update_xfrm(entry);
        if (err) {
                HIP_ERROR("XFRM synchronization failed\n");
                err = -EFAULT;
                goto out_err;
        }

	HIP_DEBUG("Went back to ESTABLISHED state\n");

	/* delete old SAs */
	if (prev_spi_out != new_spi_out) {
		HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
		err = hip_delete_sa(prev_spi_out, hits);
		HIP_DEBUG("TODO: set new spi to 0\n");
		_HIP_DEBUG("delete_sa out retval=%d\n", err);
		err = 0;
	} else
		HIP_DEBUG("prev SPI_out = new SPI_out, not deleting the outbound SA\n");

	if (prev_spi_in != new_spi_in) {
		HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
		err = hip_delete_sa(prev_spi_in, hitr);
		/* remove old HIT-SPI mapping and add a new mapping */

		/* actually should change hip_hadb_delete_inbound_spi
		 * somehow, but we do this or else delete_inbound_spi
		 * would delete both old and new SPIs */
		hip_hadb_remove_hs(prev_spi_in);
		err = hip_hadb_insert_state_spi_list(&entry->hit_peer, 
						     &entry->hit_our,
						     new_spi_in);
		if (err == -EEXIST) {
			HIP_DEBUG("HIT-SPI mapping already exists, hmm ..\n");
			err = 0;
		} else if (err) {
			HIP_ERROR("Could not add a HIT-SPI mapping for SPI 0x%x (err=%d)\n",
				  new_spi_in, err);
		}
	} else
		_HIP_DEBUG("prev SPI_in = new SPI_in, not deleting the inbound SA\n");

	/* start verifying addresses */
	HIP_DEBUG("start verifying addresses for new spi 0x%x\n", new_spi_out);
	err = hip_update_send_addr_verify(entry, msg, NULL /* ok ? */, new_spi_out);
	if (err)
		HIP_DEBUG("address verification had errors, err=%d\n", err);
	err = 0;

 out_err:
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

/**
 * hip_handle_update_rekeying - handle incoming UPDATE packet received in REKEYING state
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_rekeying(hip_ha_t *entry, struct hip_common *msg,
			       struct in6_addr *src_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_nes *nes = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct in6_addr daddr;
	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */
	uint16_t mask;

	/* 8.11.2  Processing an UPDATE packet in state REKEYING */

	HIP_DEBUG("\n");

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	nes = hip_get_param(msg, HIP_PARAM_NES);
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	if (seq && nes) {
		/* 1. If the packet contains a SEQ and NES parameters, then the system
		   generates a new UPDATE packet with an ACK of the peer's Update ID
		   as received in the SEQ parameter. .. */
		HIP_IFE(!(update_packet = hip_msg_alloc()), -ENOMEM);
		mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
						HIP_CONTROL_DHT_TYPE1);
		hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);
		HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
			 "Building of ACK param failed\n");
	}

	if (nes && ack) { /* kludge */
		uint32_t s = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));
		_HIP_DEBUG("s=0x%x\n", s);
		hip_update_set_status(entry, s, 0x4, 0, 0, nes, 0);
	}
	/* .. Additionally, if the UPDATE packet contained an ACK of the
	   outstanding Update ID, or if the ACK of the UPDATE packet that
	   contained the NES has already been received, the system stores
	   the received NES and (optional) DIFFIE_HELLMAN parameters and
	   finishes the rekeying procedure as described in Section
	   8.11.3. If the ACK of the outstanding Update ID has not been
	   received, stay in state REKEYING after storing the recived NES
	   and (optional) DIFFIE_HELLMAN. */

	if (ack) /* breaks if packet has no ack but nes exists ? */
		hip_update_handle_ack(entry, ack, nes ? 1 : 0, NULL);
//	if (nes)
//		hip_update_handle_nes(entry, puid); /* kludge */

	/* finish SAs if we have received ACK and NES */
	{
		struct hip_spi_in_item *item, *tmp;

		list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u updflags=0x%x\n",
				  item->spi, item->seq_update_id, item->update_state_flags);
			if (item->update_state_flags == 0x3) {
				err = hip_update_finish_rekeying(msg, entry, &item->stored_received_nes);
				HIP_DEBUG("update_finish handling ret err=%d\n", err);
			}
		}
		err = 0;
	}

	HIP_IFE(!update_packet, -1);

	/* Send ACK */

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");
        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);

	err = hip_csum_send(NULL, &daddr, update_packet); // HANDLER
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
		/* fallback to established ? */
                /* goto out_err; ? */
	}

 out_err:
	/* if (err)
	   TODO: REMOVE IPSEC SAs
	   move to state = ?
	*/
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);	
	return err;
}


/**
 * hip_update_send_addr_verify - send address verification UPDATE
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @spi: outbound SPI in host byte order
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *addr, *tmp;
	struct hip_common *update_packet = NULL;
	uint16_t mask;

	HIP_DEBUG("SPI=0x%x\n", spi);
	HIP_IFE(!(spi_out = hip_hadb_get_spi_list(entry, spi)), -1);

	/* Start checking the addresses */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	list_for_each_entry_safe(addr, tmp, &spi_out->peer_addr_list, list) {
		HIP_DEBUG_HIT("new addr to check", &addr->address);
		HIP_DEBUG("address state=%d\n", addr->address_state);

		if (addr->address_state == PEER_ADDR_STATE_DEPRECATED) {
			HIP_DEBUG("addr state is DEPRECATED, not verifying\n");
			continue;
		}

		if (addr->address_state == PEER_ADDR_STATE_ACTIVE) {
			HIP_DEBUG("not verifying already active address\n"); 
			if (addr->is_preferred) {
				HIP_DEBUG("TEST (maybe should not do this yet?): setting already active address and set as preferred to default addr\n");
				hip_hadb_set_default_out_addr(entry, spi_out, &addr->address);
			}
			continue;
		}
		HIP_DEBUG("building verification packet\n");
		hip_msg_init(update_packet);
		mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
						HIP_CONTROL_DHT_TYPE1);
		hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);
		HIP_IFEBL2(hip_build_param_spi(update_packet, 0x11223344), -1,
			   continue, "Building of SPI failed\n");
		entry->update_id_out++;
		addr->seq_update_id = entry->update_id_out;
		HIP_DEBUG("outgoing UPDATE ID for REA addr check=%u\n", addr->seq_update_id);
		/* todo: handle overflow if (!update_id_out) */
		HIP_IFEBL2(hip_build_param_seq(update_packet, addr->seq_update_id), -1,
			 continue, "Building of SEQ failed\n");
		/* Add HMAC */
		HIP_IFEBL2(hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out),
			  -1, continue, "Building of HMAC failed\n");
		/* Add SIGNATURE */
		HIP_IFEBL2(entry->sign(entry->our_priv, update_packet), -EINVAL,
			   continue, "Could not sign UPDATE\n");
		get_random_bytes(addr->echo_data, sizeof(addr->echo_data));
		_HIP_HEXDUMP("ECHO_REQUEST in REA addr check",
			     addr->echo_data, sizeof(addr->echo_data));
		HIP_IFEBL2(hip_build_param_echo(update_packet, addr->echo_data ,
					       sizeof(addr->echo_data), 0, 1), -1,
			  continue, "Building of ECHO_REQUEST failed\n");
		HIP_DEBUG("sending addr verify pkt\n");
		/* test: send all addr check from same address */
		err = hip_csum_send(src_ip, &addr->address, update_packet); // HANDLER
		if (err) {
			HIP_DEBUG("hip_csum_send err=%d\n", err);
			HIP_DEBUG("NOT ignored, or should we..\n");
		}
	}

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}


/** hip_handle_update_plain_rea - handle UPDATE(REA, SEQ)
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @dst_ip: destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * For each address in the REA, we reply with ACK and
 * UPDATE(SPI, SEQ, ACK, ECHO_REQUEST)
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_plain_rea(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_seq *seq;
	struct hip_rea *rea;
	uint16_t mask;

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM, 
		 "Out of memory.\n");

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/* ACK the received UPDATE SEQ */
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1, 
		 "Building of ACK failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");

	HIP_DEBUG("Sending reply UPDATE packet (for REA)\n");
	err = hip_csum_send(dst_ip, src_ip, update_packet); // HANDLER
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
	}

	rea = hip_get_param(msg, HIP_PARAM_REA);
	hip_update_handle_rea_parameter(entry, rea);
	err = hip_update_send_addr_verify(entry, msg, dst_ip, ntohl(rea->spi));

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}


/** hip_handle_update_addr_verify - handle address verification UPDATE
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @dst_ip: destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * handle UPDATE(SPI, SEQ, ACK, ECHO_REQUEST) or handle UPDATE(SPI,
 * SEQ, ECHO_REQUEST)
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo = NULL;
	uint16_t mask;

	/* Assume already locked entry */
	HIP_IFEL(!(echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST)), -1, 
		 "ECHO not found\n");
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1, 
		 "SEQ not found\n");
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/* reply with UPDATE(ACK, ECHO_RESPONSE) */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1, 
		 "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out), -1, 
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");

	/* ECHO_RESPONSE (no sign) */
	HIP_DEBUG("echo opaque data len=%d\n",
		   hip_get_param_contents_len(echo));
	HIP_IFEL(hip_build_param_echo(update_packet,
				      (void *)echo+sizeof(struct hip_tlv_common),
				      hip_get_param_contents_len(echo), 0, 0), -1,
		 "Building of ECHO_RESPONSE failed\n");

	HIP_DEBUG("Sending reply UPDATE packet (address check)\n");
	err = hip_csum_send(dst_ip, src_ip, update_packet); // HANDLER
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
	}

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}


/**
 * hip_receive_update - receive UPDATE packet
 * @msg: buffer where the HIP packet is in
 *
 * This is the initial function which is called when an UPDATE packet
 * is received. The validity of the packet is checked and then this
 * function acts according to whether this packet is a reply or not.
 *
 * Returns: 0 if successful (HMAC and signature (if needed) are
 * validated, and the rest of the packet is handled if current state
 * allows it), otherwise < 0.
 */
int hip_receive_update(struct hip_common *msg,
		       struct in6_addr *update_saddr,
		       struct in6_addr *update_daddr)
{
	int err = 0, state = 0, is_retransmission = 0, handle_upd = 0;
	struct in6_addr *hits;
	struct hip_nes *nes = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct hip_rea *rea = NULL;
	struct hip_echo_request *echo = NULL;
	struct hip_echo_response *echo_response = NULL;
	struct hip_hmac *hmac = NULL;
	struct hip_signature *signature = NULL;
	uint32_t pkt_update_id = 0; /* UPDATE ID in packet */
	uint32_t update_id_in = 0;  /* stored incoming UPDATE ID */
	uint16_t keymat_index = 0;
	struct hip_dh_fixed *dh;
	struct in6_addr *src_ip, *dst_ip;
	hip_ha_t *entry = NULL;

	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));

	HIP_DEBUG("enter\n");

	src_ip = update_saddr;
	dst_ip = update_daddr;
	hits = &msg->hits;

	HIP_IFEL(!(entry = hip_hadb_find_byhits(hits, &msg->hitr)), -1,
		 "Entry not found\n");
	HIP_LOCK_HA(entry);
	state = entry->state; /* todo: remove variable state */

	HIP_DEBUG("Received UPDATE in state %s\n", hip_state_str(state));

	/* in state R2-SENT: Receive UPDATE, go to ESTABLISHED and
	 * process from ESTABLISHED state */
	if (state == HIP_STATE_R2_SENT) {
		state = entry->state = HIP_STATE_ESTABLISHED;
		err = hip_hadb_update_xfrm(entry);
		if (err) {
			HIP_ERROR("XFRM synchronization failed\n");
			err = -EFAULT;
			goto out_err;
		}
		HIP_DEBUG("Moved from R2-SENT to ESTABLISHED\n");
	}

	if (! (state == HIP_STATE_ESTABLISHED ||
	       state == HIP_STATE_REKEYING) ) {
		HIP_DEBUG("Received UPDATE in illegal state %s. Dropping\n",
			  hip_state_str(state));
		err = -EINVAL;
		goto out_err;
	}

	nes = hip_get_param(msg, HIP_PARAM_NES);
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	rea = hip_get_param(msg, HIP_PARAM_REA);
	echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	echo_response = hip_get_param(msg, HIP_PARAM_ECHO_RESPONSE);

	if (nes) {
		HIP_DEBUG("UPDATE contains (at least one) NES parameter\n");
		keymat_index = ntohs(nes->keymat_index);
		HIP_DEBUG("NES: Keymaterial Index: %u\n", keymat_index);
		HIP_DEBUG("NES: Old SPI: 0x%x New SPI: 0x%x\n",
			  ntohl(nes->old_spi), ntohl(nes->new_spi));
	}
	if (seq) {
		pkt_update_id = ntohl(seq->update_id);
		HIP_DEBUG("SEQ: UPDATE ID: %u\n", pkt_update_id);
	}
	if (ack)
		HIP_DEBUG("ACK found: %u\n", ntohl(ack->peer_update_id));
	if (rea)
		HIP_DEBUG("REA: SPI 0x%x\n", ntohl(rea->spi));
	if (echo)
		HIP_DEBUG("ECHO_REQUEST found\n");
	if (echo_response)
		HIP_DEBUG("ECHO_RESPONSE found\n");

	/* 8.11 Processing UPDATE packets checks */
	if (seq && nes) {
		HIP_DEBUG("UPDATE has both SEQ and NES, peer host is rekeying, MUST process this UPDATE\n");
		handle_upd = 1;
	}

	if (!handle_upd && state == HIP_STATE_REKEYING && ack && !echo) {
		HIP_DEBUG("in REKEYING state and ACK and not ECHO_REQUEST, MUST process this UPDATE\n");
		handle_upd = 1;
	}

	/* mm-02 UPDATE tests */
	if (!handle_upd && rea && seq && !nes) {
		HIP_DEBUG("have REA and SEQ but no NES, process this UPDATE\n");
		handle_upd = 2;
	}

	//if (!handle_upd && /* SPI && */ seq && ack && !nes && echo) {
	if (!handle_upd && /* SPI && */ seq && !nes && echo) {
		/* ACK might have been in a separate packet */
		HIP_DEBUG("have SEQ,ECHO_REQUEST but no NES, process this UPDATE\n");
		handle_upd = 3;
	}
	if (!handle_upd && ack && echo) {
		HIP_DEBUG("have ACK and ECHO_REQUEST, process this UPDATE\n");
		handle_upd = 4;
	}

	if (!handle_upd && ack) {
		HIP_DEBUG("have only ACK, process this UPDATE\n");
		handle_upd = 5;
	}

	if (!handle_upd) {
		HIP_ERROR("NOT processing UPDATE packet\n");
		goto out_err;
	}

	update_id_in = entry->update_id_in;
	_HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
	if (seq) {
		/* 1. If the SEQ parameter is present, and the Update ID in the
		   received SEQ is smaller than the stored Update ID for the host,
		   the packet MUST BE dropped. */
		if (pkt_update_id < update_id_in) {
			HIP_DEBUG("SEQ param present and received UPDATE ID (%u) < stored incoming UPDATE ID (%u). Dropping\n",
				  pkt_update_id, update_id_in);
			err = -EINVAL;
			goto out_err;
		} else if (pkt_update_id == update_id_in) {
			/* 2. If the SEQ parameter is present, and the Update ID in the
			   received SEQ is equal to the stored Update ID for the host, the
			   packet is treated as a retransmission. */
			is_retransmission = 1;
			HIP_DEBUG("Retransmitted UPDATE packet (?), continuing\n");
			/* todo: ignore this packet or process anyway ? */
		}
	}

	HIP_DEBUG("handle_upd=%d\n", handle_upd);
	if (handle_upd > 1) {
		_HIP_DEBUG("MM-02 UPDATE\n");
	}

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (hmac) {
		/* 3. The system MUST verify the HMAC in the UPDATE packet.
		   If the verification fails, the packet MUST be dropped. */
		HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1, 
			 "HMAC validation on UPDATE failed\n");
	} else {
		HIP_DEBUG("HMAC not found, error ?\n");
	}

	/* 4. If the received UPDATE contains a Diffie-Hellman
	   parameter, the received Keymat Index MUST be zero. If this
	   test fails, the packet SHOULD be dropped and the system
	   SHOULD log an error message. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		HIP_IFEL(!nes, -1, "Packet contains DH but not NES\n");
		HIP_IFEL(keymat_index != 0, -EINVAL,
			 "UPDATE contains Diffie-Hellman parameter with non-zero"
			 "keymat value %u in NES. Dropping\n", keymat_index);
	}

	/* 5. The system MAY verify the SIGNATURE in the UPDATE
	   packet. If the verification fails, the packet SHOULD be
	   dropped and an error message logged. */
	HIP_IFEL(entry->verify(entry->peer_pub, msg), -1, 
		 "Verification of UPDATE signature failed\n");

	/* 6.  If a new SEQ parameter is being processed, the system MUST record
	   the Update ID in the received SEQ parameter, for replay
	   protection. */
	if (seq && !is_retransmission) {
		entry->update_id_in = pkt_update_id;
		_HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}

	/* check that Old SPI value exists */
	HIP_IFEL(nes && (nes->old_spi != nes->new_spi) && /* mm check */
		 !hip_update_exists_spi(entry, ntohl(nes->old_spi), HIP_SPI_DIRECTION_OUT, 0), -1,
		 "Old SPI value 0x%x in NES parameter does not belong to the current list of outbound SPIs in HA\n",
		 ntohl(nes->old_spi));

	if (handle_upd == 2) {
		/* REA, SEQ */
		err = hip_handle_update_plain_rea(entry, msg, src_ip, dst_ip);
	} else if (handle_upd == 3) {
		/* SPI, SEQ, ACK, ECHO_REQUEST */
		err = hip_handle_update_addr_verify(entry, msg, src_ip, dst_ip);
	} else if (handle_upd == 5) {
		/* ACK, ECHO_RESPONSE */
		hip_update_handle_ack(entry, ack, 0, echo_response);
	} else {
		/* base draft cases 7-8: */
		if (state == HIP_STATE_ESTABLISHED) {
			if (nes && seq) {
				HIP_DEBUG("case 7: in ESTABLISHED and has NES and SEQ\n");
				err = hip_handle_update_established(entry, msg, src_ip, dst_ip);
			} else {
				HIP_ERROR("in ESTABLISHED but no both NES and SEQ\n");
				err = -EINVAL;
			}
		} else {
			HIP_DEBUG("case 8: in REKEYING\n");
			err = hip_handle_update_rekeying(entry, msg, src_ip);
		}
	}

 out_err:
	if (err)
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);

	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}

/** hip_send_update - send initial UPDATE packet to the peer
 * @entry: hadb entry corresponding to the peer
 * @addr_list: if non-NULL, REA parameter is added to the UPDATE
 * @addr_count: number of addresses in @addr_list
 * @ifindex: if non-zero, the ifindex value of the interface which caused the event
 * @flags: TODO comment
 *
 * Returns: 0 if UPDATE was sent, otherwise < 0.
 */
int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_rea_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags)
{
	int err = 0, make_new_sa = 0, add_nes = 0, add_rea;
	uint32_t update_id_out = 0;
	uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	uint32_t new_spi_in = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr daddr;
	uint32_t nes_old_spi = 0, nes_new_spi = 0;
	uint16_t mask;

	add_rea = flags & SEND_UPDATE_REA;
	HIP_DEBUG("addr_list=0x%p addr_count=%d ifindex=%d flags=0x%x\n",
		  addr_list, addr_count, ifindex, flags);
	if (!ifindex)
		_HIP_DEBUG("base draft UPDATE\n");

	if (add_rea)
		_HIP_DEBUG("mm UPDATE, %d addresses in REA\n", addr_count);
	else
		_HIP_DEBUG("Plain UPDATE\n");

	/* Start building UPDATE packet */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM, "Out of memory.\n");
	HIP_LOCK_HA(entry);

	hip_print_hit("sending UPDATE to", &entry->hit_peer);
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask,
			      &entry->hit_our, &entry->hit_peer);
	if (add_rea) {
		/* mm stuff, per-ifindex SA */
		/* reuse old SA if we have one, else create a new SA */
		mapped_spi = hip_hadb_get_spi(entry, ifindex);
		HIP_DEBUG("mapped_spi=0x%x\n", mapped_spi);
		if (mapped_spi) {
			/* NES not needed */
			add_nes = 0;
			make_new_sa = 0;
			_HIP_DEBUG("5.1 Mobility with single SA pair, readdress with no rekeying\n");
			HIP_DEBUG("Reusing old SA\n");
			/* 5.1 Mobility with single SA pair */
		} else {
			_HIP_DEBUG("5.2 Host multihoming\n");
			make_new_sa = 1;
			_HIP_DEBUG("TODO\n");
		}
	} else {
		/* base draft UPDATE, create a new SA anyway */
		_HIP_DEBUG("base draft UPDATE, create a new SA\n");
		make_new_sa = 1;
	}

	/* If this is mm-UPDATE (ifindex should be then != 0) avoid
	 * sending empty REAs to the peer if we have not sent previous
	 * information on this ifindex/SPI yet */
	if (ifindex != 0 && mapped_spi == 0 && addr_count == 0) {
		HIP_DEBUG("NETDEV_DOWN and ifindex not advertised yet, returning\n");
		goto out;
	}

	if (make_new_sa) {
		HIP_DEBUG("make_new_sa=1 -> add_nes=1\n");
		add_nes = 1;
	}

	HIP_DEBUG("add_nes=%d make_new_sa=%d\n", add_nes, make_new_sa);

	if (make_new_sa) {
		HIP_IFEL(!(new_spi_in = hip_acquire_spi(&entry->hit_peer, &entry->hit_our)), 
			 -1, "Error while acquiring a SPI\n");
		HIP_DEBUG("Got SPI value for the SA 0x%x\n", new_spi_in);

		/* TODO: move to rekeying_finish */
		if (!mapped_spi) {
			struct hip_spi_in_item spi_in_data;

			_HIP_DEBUG("previously unknown ifindex, creating a new item to inbound spis_in\n");
			memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
			spi_in_data.spi = new_spi_in;
			spi_in_data.ifindex = ifindex;
			spi_in_data.updating = 1;
			HIP_IFEL(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1, 
				 "Add_spi failed\n");
		}
		else {
			_HIP_DEBUG("is previously mapped ifindex\n");
		}
	} else
		_HIP_DEBUG("not creating a new SA\n");

	_HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);

	if (add_rea) {
		/* REA is the first parameter of the UPDATE */
		if (mapped_spi)
			err = hip_build_param_rea(update_packet, mapped_spi,
							    addr_list, addr_count);
		else
			err = hip_build_param_rea(update_packet, new_spi_in,
							    addr_list, addr_count);
		HIP_IFEL(err, err, "Building of REA param failed\n");
	} else
		HIP_DEBUG("not adding REA\n");

	if (add_nes) {
		if (addr_list) {
			if (make_new_sa) {
				/* mm02 5.2 Host multihoming */
				HIP_DEBUG("mm-02, adding NES, Old SPI == New SPI\n");
				/* notify the peer about new interface */
				nes_old_spi = new_spi_in;
				nes_new_spi = new_spi_in;

			} else {
				HIP_DEBUG("mm-02, !makenewsa\n");
				nes_old_spi = mapped_spi;
				nes_new_spi = new_spi_in;
			}
		} else {
			HIP_DEBUG("adding NES, Old SPI <> New SPI\n");
			/* plain UPDATE or readdress with rekeying */
			/* update the SA of the interface which caused the event */
			HIP_IFEL(!(nes_old_spi = hip_hadb_get_spi(entry, ifindex)), -1,
				 "Could not find SPI to use in Old SPI\n");
			hip_set_spi_update_status(entry, nes_old_spi, 1); /* here or later ? */
			nes_new_spi = new_spi_in;
		}

		HIP_DEBUG("nes_old_spi=0x%x nes_new_spi=0x%x\n", nes_old_spi, nes_new_spi);
		HIP_IFEL(hip_build_param_nes(update_packet, entry->current_keymat_index,
					     nes_old_spi, nes_new_spi), -1,
			 "Building of NES param failed\n");
	} else {
		HIP_DEBUG("not adding NES\n");
		nes_old_spi = nes_new_spi = mapped_spi;
	}

	hip_update_set_new_spi_in(entry, nes_old_spi, nes_new_spi, 0);

	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	/* todo: handle this case */
	HIP_IFEL(!update_id_out, -EINVAL, "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ param failed\n");

	if (add_nes) {
		/* remember the update id of this update */
		hip_update_set_status(entry, nes_old_spi,
				      0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
				      entry->current_keymat_index);
	}

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL, "Could not sign UPDATE. Failing\n");

	/* Send UPDATE */
        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);
#if 0
	/* Store the last UPDATE ID value sent from us */
	entry->update_id_out = update_id_out;
        _HIP_DEBUG("Stored peer's outgoing UPDATE ID %u\n", update_id_out);
#endif

	hip_set_spi_update_status(entry, nes_old_spi, 1);

	/* if UPDATE contains only REA, then do not move state ? */
	if (add_nes) {
		entry->state = HIP_STATE_REKEYING;
		HIP_DEBUG("moved to state REKEYING\n");
	} else
		HIP_DEBUG("experimental: staying in ESTABLISHED (NES not added)\n");


        HIP_DEBUG("Sending initial UPDATE packet\n");
	err = hip_csum_send(NULL, &daddr, update_packet); // HANDLER
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		_HIP_DEBUG("NOT ignored, or should we..\n");
		entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("fallbacked to state ESTABLISHED due to error (ok ?)\n");
		goto out_err;
	}

	/* todo: 5. The system SHOULD start a timer whose timeout value should be ..*/
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");
	hip_set_spi_update_status(entry, nes_old_spi, 0);
	/* delete IPsec SA on failure */
	HIP_ERROR("TODO: delete SA\n");
 out:
        err = hip_hadb_update_xfrm(entry);
        if (err) {
                HIP_ERROR("XFRM synchronization failed\n");
                err = -EFAULT;
                goto out_err;
        }

	HIP_UNLOCK_HA(entry);
	if (update_packet)
		HIP_FREE(update_packet);
	return err;
}

/* really ugly hack ripped from rea.c, must convert to list_head asap */
struct hip_update_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

/* Internal function copied originally from rea.c */
static int hip_update_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_update_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	if (entry->hastate == HIP_HASTATE_HITOK && entry->state == HIP_STATE_ESTABLISHED) {
		hip_hadb_hold_entry(entry);
		rk->array[rk->count] = entry;
		//hip_hold_ha(entry);
		rk->count++;
	} else
		HIP_DEBUG("skipping HA entry 0x%p (state=%s)\n",
			  entry, hip_state_str(entry->state));

	return 0;
}

/**
 * hip_send_update_all - send UPDATE packet to every peer
 * @addr_list: if non-NULL, REA parameter is added to the UPDATE
 * @addr_count: number of addresses in @addr_list
 * @ifindex: if non-zero, the ifindex value of the interface which caused the event
 * @flags: flags passed to @hip_send_update
 *
 * UPDATE is sent to the peer only if the peer is in established
 * state.
 *
 * Add REA parameter if @addr_list is non-null. @ifindex tells which
 * device caused the network device event.
 */
void hip_send_update_all(struct hip_rea_info_addr_item *addr_list, int addr_count,
			 int ifindex, int flags)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_DEBUG("test: returning, ifindex=0 (fix this for non-mm UPDATE)\n");
		return;
	}

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;

	HIP_IFEL(hip_for_each_ha(hip_update_get_all_valid, &rk), 0, 
		 "for_each_ha err.\n");
	for (i = 0; i < rk.count; i++) {
		if (rk.array[i] != NULL) {
			hip_send_update(rk.array[i], addr_list, addr_count, ifindex, flags);
			hip_hadb_put_entry(rk.array[i]);
			//hip_put_ha(rk.array[i]);
		}
	}

 out_err:
	return;
}

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
