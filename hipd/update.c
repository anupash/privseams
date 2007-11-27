/*
 * Licence: GNU/GPL
 * Authors:
 * - Mika Kousa <mkousa@iki.fi>
 * - Tobias Heer <tobi@tobibox.de>
 * - Abhijit Bagri <abagri@gmail.com>
 * - Miika Komu <miika@iki.fi>
 *
 * @note Based on <a href="http://www1.ietf.org/mail-archive/web/hipsec/current/msg01745.html">Simplified state machine</a>
 */
 
#include "update.h"

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;
 

/**
 * Iterate a list of locators using a function.
 *
 * @return zero on success or non-zero on error. The list handling is interrupted if the give function returns an error.
 */
int hip_for_each_locator_addr_item(int (*func)(hip_ha_t *entry,
                                               struct hip_locator_info_addr_item *i,
                                               void *opaq),
                                   hip_ha_t *entry,
                                   struct hip_locator *locator,
                                   void *opaque)
{
	int i = 0, err = 0, n_addrs;
	struct hip_locator_info_addr_item *locator_address_item = NULL;

	n_addrs = hip_get_locator_addr_item_count(locator);
	HIP_IFEL((n_addrs < 0), -1, "Negative address count\n");
	/**
	  @todo: Here we have wrong checking, because function  
	  hip_get_locator_addr_item_count(locator) has already
	  divided the length on sizeof(struct hip_locator_info_addr_item)
	  hence we already have number of elements. Andrey

	if (n_addrs % sizeof(struct hip_locator_info_addr_item))
		HIP_ERROR(addr item list len modulo not zero, (len=%d)\n",
			  ntohs(locator->length));
	*/
	HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
		  n_addrs, hip_get_param_total_len(locator));

	HIP_IFE(!func, -1);

	locator_address_item = hip_get_locator_first_addr_item(locator);
	for (i = 0; i < n_addrs; i++, locator_address_item++) {
		HIP_IFEL(func(entry, locator_address_item, opaque), -1,
			 "Locator handler function returned error\n");
	}
	
 out_err:

	return err;
}

int hip_update_for_each_peer_addr(int (*func)(hip_ha_t *entry,
                                  struct hip_peer_addr_list_item *list_item,
                                  struct hip_spi_out_item *spi_out,
                                  void *opaq),
                                  hip_ha_t *entry,
                                  struct hip_spi_out_item *spi_out,
                                  void *opaq)
{
	hip_list_t *item, *tmp;
	struct hip_peer_addr_list_item *addr;
	int i = 0, err = 0;

	HIP_IFE(!func, -EINVAL);

	list_for_each_safe(item, tmp, spi_out->peer_addr_list, i)
	{
		addr = list_entry(item);
		HIP_IFE(func(entry, addr, spi_out, opaq), -1);
	}

 out_err:
	return err;
}

int hip_update_for_each_local_addr(int (*func)(hip_ha_t *entry,
                                   struct hip_spi_in_item *spi_in,
                                   void *opaq),
                                   hip_ha_t *entry,
                                   void *opaq)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *e;
	int i = 0, err = 0;

	HIP_IFE(!func, -EINVAL);

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		e = list_entry(item);
		HIP_IFE(func(entry, e, opaq), -1);
	}

 out_err:
	return err;
}


/** hip_update_get_sa_keys - Get keys needed by UPDATE
 * @param entry corresponding hadb entry of the peer
 * @param keymat_offset_new value-result parameter for keymat index used
 * @param calc_index_new value-result parameter for the one byte index used
 * @param Kn_out value-result parameter for keymat 
 * @param espkey_gl HIP-gl encryption key
 * @param authkey_gl HIP-gl integrity (HMAC)
 * @param espkey_lg HIP-lg encryption key
 * @param authkey_lg HIP-lg integrity (HMAC)
 *
 * @return 0 on success (all encryption and integrity keys are
 * successfully stored and @keymat_offset_new, @calc_index_new, and
 * @Kn_out contain updated values). On error < 0 is returned.
 */
int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl,
			   struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg,
			   struct hip_crypto_key *authkey_lg)
{
       	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t k = *keymat_offset_new, Kn_pos;
	uint8_t c = *calc_index_new;
	int err = 0, esp_transform, esp_transf_length = 0,
		auth_transf_length = 0;

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

	bzero(espkey_gl, sizeof(struct hip_crypto_key));
	bzero(espkey_lg, sizeof(struct hip_crypto_key));
	bzero(authkey_gl, sizeof(struct hip_crypto_key));
	bzero(authkey_lg, sizeof(struct hip_crypto_key));

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

/** hip_update_test_locator_addr - test if IPv6 address is to be added into locator.
 * @param addr the IPv6 address to be tested
 *
 * Currently the following address types are ignored: unspecified
 * (any), loopback, link local, site local, and other not unicast
 * addresses.
 *
 * Returns 1 if address is ok to be used as a peer address, otherwise 0.
*/
int hip_update_test_locator_addr(struct in6_addr *addr)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
		IPV6_TO_IPV4_MAP(addr, &sin->sin_addr);
		sin->sin_family = AF_INET;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
		memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));
		sin6->sin6_family = AF_INET6;
	}

	return filter_address((struct sockaddr *) &ss, -1);
}

int hip_update_add_peer_addr_item(hip_ha_t *entry,
		       struct hip_locator_info_addr_item *locator_address_item,
		       void *_spi)
{
	struct in6_addr *locator_address =
		&locator_address_item->address;
	uint32_t lifetime = ntohl(locator_address_item->lifetime);
   	int is_preferred = htonl(locator_address_item->reserved) == (1 << 7);
	int err = 0, i,locator_is_ipv4, local_is_ipv4;
	uint32_t spi = *((uint32_t *) _spi);
	
	HIP_DEBUG_HIT("LOCATOR address", locator_address);
	HIP_DEBUG(" address: is_pref=%s reserved=0x%x lifetime=0x%x\n",
		  is_preferred ? "yes" : "no",
		  ntohl(locator_address_item->reserved),
		  lifetime);

        /* Removed this because trying to get interfamily handovers to work --Samu */
	// Check that addresses match, we doesn't support IPv4 <-> IPv6 update communnications
        //	locator_is_ipv4 = IN6_IS_ADDR_V4MAPPED(locator_address);
	//local_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&entry->local_address);

	//if( locator_is_ipv4 != local_is_ipv4 ) {
	  // One of the addresses is IPv4 another is IPv6
	//  goto out_err;
	//}

	/* Check that the address is a legal unicast or anycast
	   address */
	if (!hip_update_test_locator_addr(locator_address)) {
		err = -1;
		HIP_DEBUG_IN6ADDR("Bad locator type", locator_address);
		goto out_err;
	}
	
	/* Check if the address is already bound to the SPI +
	   add/update address */
        if (ipv6_addr_cmp(locator_address, &entry->preferred_address) == 0) {
            HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
                                             0,
                                             lifetime, 1), -1);
        } else {
            HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
                                             0,
                                             lifetime, is_preferred), -1);
        }

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->preferred_address));
#endif

 out_err:
	return err;
}

/**
 * Compare two locators for equality
 *
 * @return non-zero when address are equal, otherwise zero
 */
int hip_update_locator_match(hip_ha_t *unused,
			     struct hip_locator_info_addr_item *item1,
			     void *_item2) {
	struct hip_locator_info_addr_item *item2 = _item2;
	return !ipv6_addr_cmp(&item1->address, &item2->address);
}

/**
 * Compare locator and addr list item for equality
 *
 * @return non-zero when address are equal, otherwise zero
 */
int hip_update_locator_item_match(hip_ha_t *unused,
			     struct hip_locator_info_addr_item *item1,
			     void *_item2) {
	struct hip_peer_addr_list_item *item2 = _item2;
	return !ipv6_addr_cmp(&item1->address, &item2->address);
}


/**
 * Check if locator list contains a given locator
 *
 * @return zero if the locator was found, otherwise non-zero
 */
int hip_update_locator_contains_item(struct hip_locator *locator,
				  struct hip_peer_addr_list_item *item)
{
	return hip_for_each_locator_addr_item(hip_update_locator_item_match,
					      NULL, locator, item);
}

int hip_update_deprecate_unlisted(hip_ha_t *entry,
				  struct hip_peer_addr_list_item *list_item,
				  struct hip_spi_out_item *spi_out,
				  void *_locator) {
    int err = 0;
    uint32_t spi_in;
    struct hip_locator *locator = (void *) _locator;
 
    if (hip_update_locator_contains_item(locator, list_item))
        goto out_err;

    HIP_DEBUG_HIT("Deprecating address", &list_item->address);
    
    list_item->address_state = PEER_ADDR_STATE_DEPRECATED;
    spi_in = hip_get_spi_to_update_in_established(entry, &entry->local_address);
    
    hip_delete_sa(entry->default_spi_out, &list_item->address, &entry->local_address, 
                  AF_INET6, 0, (int)entry->peer_udp_port);
    hip_delete_sa(spi_in, &entry->local_address, &list_item->address, 
                  AF_INET6, (int)entry->peer_udp_port, 0);
    
    list_del(list_item, entry->spis_out);
 out_err:
    return err;
}

int hip_update_set_preferred(hip_ha_t *entry,
			     struct hip_peer_addr_list_item *list_item,
			     struct hip_spi_out_item *spi_out,
			     void *pref) {
	int *preferred = pref;
	list_item->is_preferred =  *preferred;
	return 0;
}

/** hip_update_handle_locator_parameter - Process locator parameters in the UPDATE
 * @param entry corresponding hadb entry of the peer
 * @param locator the locator parameter in the packet
 *
 * @entry must be is locked when this function is called.
 *
 * @return 0 if the locator parameter was processed successfully,
 * otherwise < 0.
 */
int hip_update_handle_locator_parameter(hip_ha_t *entry,
					struct hip_locator *locator,
					struct hip_esp_info *esp_info)
{
	uint32_t old_spi = 0, new_spi = 0, i, err = 0;
	struct hip_locator_info_addr_item *locator_address_item;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *a, *tmp, addr;
	int zero = 0, n_addrs = 0, ii = 0;
        int same_af = 0, local_af = 0, comp_af = 0, tmp_af = 0;
        struct netdev_address *n;
        hip_list_t *item = NULL, *tmplist = NULL;

        old_spi = ntohl(esp_info->new_spi);
        new_spi = ntohl(esp_info->new_spi);
        HIP_DEBUG("LOCATOR SPI old=0x%x new=0x%x\n", old_spi, new_spi);
                
        /* If following does not exit, its a bug: outbound SPI must have been
           already created by the corresponding ESP_INFO in the same UPDATE
           packet */
        HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, new_spi)), -1,
                 "Bug: outbound SPI 0x%x does not exist\n", new_spi);
        
        /* Set all peer addresses to unpreferred */
        /* TODO: Compiler warning;
           warning: passing argument 1 of 'hip_update_for_each_peer_addr'
           from incompatible pointer type.

        What is the real point with this one anyway? */

#if 0
        HIP_IFE(hip_update_for_each_peer_addr(hip_update_set_preferred,
                                              entry, spi_out, &zero), -1);
#endif            
	if(locator)        
		HIP_IFEL(hip_update_for_each_peer_addr(hip_update_deprecate_unlisted,
                                               entry, spi_out, locator), -1,
                 "Depracating a peer address failed\n"); 

        /* checking did the locator have any address with the same family as
           entry->local_address, if not change local address to address that
           has same family as the address(es) in locator, if possible */

        if (!locator) {
		goto out_of_loop;
	}

	locator_address_item = hip_get_locator_first_addr_item(locator);
	local_af = IN6_IS_ADDR_V4MAPPED(&entry->local_address) ? AF_INET : AF_INET6;
	if (local_af == 0) {
		HIP_DEBUG("Local address is invalid, skipping\n");
		goto out_err;
	}

	n_addrs = hip_get_locator_addr_item_count(locator);
	for (i = 0; i < n_addrs; i++) {
                /* check if af same as in entry->local_af */
                comp_af = IN6_IS_ADDR_V4MAPPED(&locator_address_item[i].address) ? AF_INET : AF_INET6;
                if (comp_af == local_af) {
			HIP_DEBUG("LOCATOR contained same family members as local_address\n");
			same_af = 1;
			
			break;
                }
	}
	if (same_af != 0) {
		HIP_DEBUG("Did not find any address of same family\n");
		goto out_of_loop;
	}

	/* look for local address with family == comp_af */
	list_for_each_safe(item, tmplist, addresses, ii) {
		n = list_entry(item);
		tmp_af = IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)) ?
			AF_INET : AF_INET6;
		if (tmp_af == comp_af) {
			HIP_DEBUG("LOCATOR did not contain same family members "
				  "as local_address, changing local_address and "
				  "preferred_address\n");
			/* Replace the local address to match the family */
			memcpy(&entry->local_address, 
			       hip_cast_sa_addr(&n->addr),
			       sizeof(struct in6_addr));
			/* Replace the peer preferred address to match the family */
			locator_address_item = hip_get_locator_first_addr_item(locator);
			/* First should be OK, no opposite family in LOCATOR */
			memcpy(&entry->preferred_address,
			       &locator_address_item->address, 
			       sizeof(struct in6_addr));
			memcpy(&addr.address,
			       &locator_address_item->address,
			       sizeof(struct in6_addr));
			HIP_IFEL(hip_update_peer_preferred_address(entry, &addr, new_spi),-1,
				 "Setting peer preferred address failed\n");
			
			goto out_of_loop;
		}
	}

 out_of_loop:
	if(locator)
		HIP_IFEL(hip_for_each_locator_addr_item(hip_update_add_peer_addr_item,
							entry, locator, &new_spi), -1,
			 "Locator handling failed\n"); 

#if 0 /* Let's see if this is really needed -miika */
	if (n_addrs == 0) /* our own extension, use some other SPI */
		(void)hip_hadb_relookup_default_out(entry);
	/* relookup always ? */
#endif

 out_err:
	return err;
}


/**
 * Handles an incoming UPDATE packet received in ESTABLISHED state.
 * 
 * @param entry hadb entry corresponding to the peer
 * @param msg the HIP packet
 * @param src_ip source IPv6 address from where the UPDATE was sent
 * @param dst_ip destination IPv6 address where the UPDATE was received
 *
 * This function handles case 7 in section 8.11 Processing UPDATE
 * packets in state ESTABLISHED of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * @return 0 if successful, otherwise < 0.
 */
int hip_handle_update_established(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip,
				  struct in6_addr *dst_ip, 
				  hip_portpair_t *update_info)
{
        int err = -1;
#if 0 
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_esp_info *esp_info;
	struct hip_seq *seq;
	struct hip_locator *locator;
	struct hip_dh_fixed *dh;
	uint32_t update_id_out = 0;
	uint32_t prev_spi_in = 0, new_spi_in = 0;
	uint16_t keymat_index = 0, mask = 0;
	struct hip_common *update_packet = NULL;
	int esp_info_i = 1, need_to_generate_key = 0,
		dh_key_generated = 0;

	HIP_DEBUG("\n");
	
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1, 
		 "No SEQ parameter in packet\n");

	/* 1.  The system consults its policy to see if it needs to generate a
	   new Diffie-Hellman key, and generates a new key if needed. */
	if (need_to_generate_key) {
		_HIP_DEBUG("would generate new D-H keys\n");
		/* generate_dh_key(); */
		dh_key_generated = 1;
		/* todo: The system records any newly generated or received
		   Diffie-Hellman keys, for use in KEYMAT generation upon
		   leaving the REKEYING state. */
	} else {
		dh_key_generated = 0;
	}

	/* 4. The system creates a UPDATE packet, which contains an SEQ
	   parameter (with the current value of Update ID), ESP_INFO parameter
	   and the optional DIFFIE_HELLMAN parameter. The UPDATE packet also
	   includes the ACK of the Update ID found in the received UPDATE
	   SEQ parameter. */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");
	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, hitr, hits);

	/*  3. The system increments its outgoing Update ID by one. */
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
        /** @todo handle this case. */
	HIP_IFEL(!update_id_out, -EINVAL, 
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");

	/* test: handle multiple ESP_INFO, not tested well yet */
 handle_esp_info:
	if (!(esp_info = hip_get_nth_param(msg, HIP_PARAM_ESP_INFO,
					   esp_info_i))) {
		HIP_DEBUG("no more ESP_INFO params found\n");
		goto esp_info_params_handled;
	}
	HIP_DEBUG("Found ESP_INFO parameter [%d]\n", esp_info_i);

	/* 2. If the system generated new Diffie-Hellman key in the previous
	   step, or it received a DIFFIE_HELLMAN parameter, it sets ESP_INFO
	   Keymat Index to zero. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/** @todo generate_new_keymat(); */
		keymat_index = 0;
	} else {
		/* Otherwise, the ESP_INFO Keymat Index MUST be larger or
		   equal to the index of the next byte to be drawn from the
		   current KEYMAT. */
		HIP_IFEL(ntohs(esp_info->keymat_index) <
			 entry->current_keymat_index, -1,
			 "ESP_INFO Keymat Index (%u) < current KEYMAT %u\n",
			 ntohs(esp_info->keymat_index),
			 entry->current_keymat_index);

		/* In this case, it is RECOMMENDED that the host use the
		   Keymat Index requested by the peer in the received
		   ESP_INFO. Here we could set the keymat index to use, but we
		   follow the recommendation */
		_HIP_DEBUG("Using Keymat Index from ESP_INFO\n");
		keymat_index = ntohs(esp_info->keymat_index);
	}

	/* Set up new incoming IPsec SA, (Old SPI value to put in ESP_INFO) */
	HIP_IFE(!(prev_spi_in =
		  hip_get_spi_to_update_in_established(entry, dst_ip)), -1);
	
	HIP_IFEL(!(new_spi_in = hip_acquire_spi(hits, hitr)), -1, 
		 "Error while acquiring a SPI\n");
	

	HIP_DEBUG("Acquired inbound SPI 0x%x\n", new_spi_in);
	hip_update_set_new_spi_in(entry, prev_spi_in, new_spi_in,
				  ntohl(esp_info->old_spi));

	if (esp_info->old_spi == esp_info->new_spi) {
		struct hip_spi_out_item spi_out_data;

		_HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(esp_info->new_spi);
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1); 
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created yet)\n",
			  ntohl(esp_info->new_spi));
	}

	/* testing LOCATOR parameters in UPDATE */
	locator = hip_get_nth_param(msg, HIP_PARAM_LOCATOR, esp_info_i);
	if (locator && esp_info) {
		HIP_DEBUG("Found LOCATOR parameter [%d]\n", esp_info_i);
		if (esp_info->old_spi != esp_info->new_spi) {
			HIP_ERROR("SPI 0x%x in LOCATOR is not equal to the New SPI 0x%x in ESP_INFO\n",
				  ntohl(esp_info->old_spi),
				  ntohl(esp_info->new_spi));
		} else {
			err = hip_update_handle_locator_parameter(entry,
								  locator,
								  esp_info);
			_HIP_DEBUG("locator param handling ret %d\n", err);
			err = 0;
		}
	}

	/* associate Old SPI with Update ID, ESP_INFO received, store
	   received ESP_INFO and proposed keymat index value used in the
	   reply ESP_INFO */
	hip_update_set_status(entry, prev_spi_in,
			      0x1 | 0x2 | 0x4 | 0x8, update_id_out, 0x2,
			      esp_info, keymat_index);
	esp_info_i++;
	goto handle_esp_info;

 esp_info_params_handled:

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING.  The system stores any received ESP_INFO and
	   DIFFIE_HELLMAN parameters. */
	HIP_IFEL(hip_build_param_esp_info(update_packet, keymat_index,
					  prev_spi_in, new_spi_in), -1, 
		 "Building of ESP_INFO failed\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ failed\n");

	/* ACK the received UPDATE SEQ */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
		 "Building of ACK failed\n");

	/** @todo hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed\n");
	
	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), 
		 -EINVAL, "Could not sign UPDATE. Failing\n");

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING. */
	entry->update_state = HIP_UPDATE_STATE_REKEYING;
	
	/* Destination port of the received packet becomes the source
	   port of the UPDATE packet. */
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(dst_ip, src_ip,
			      (entry->nat_mode ? HIP_NAT_UDP_PORT : 0), entry->peer_udp_port,
			      update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	if (err) {
		hip_set_spi_update_status(entry, prev_spi_in, 0);
		if (new_spi_in)
			hip_hadb_delete_inbound_spi(entry, new_spi_in);
	}

#endif
	return err;
}




/** hip_update_finish_rekeying - finish handling of REKEYING state
 * @param msg the HIP packet
 * @param entry hadb entry corresponding to the peer
 * @param esp_info the ESP_INFO param to be handled in the received UPDATE
 * 
 * Performs items described in 8.11.3 Leaving REKEYING state of he
 * base draft-01.
 *
 * Parameters in @esp_info are host byte order.
 * @entry must be is locked when this function is called.
 *
 * On success new IPsec SAs are created. Old SAs are deleted if the
 * UPDATE was not the multihoming case.
 *
 * @return 0 if successful, otherwise < 0.
 */
int hip_update_finish_rekeying(struct hip_common *msg, hip_ha_t *entry,
			       struct hip_esp_info *esp_info)
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

	HIP_DEBUG("handled ESP_INFO: Old SPI: 0x%x\n", ntohl(esp_info->old_spi));
	HIP_DEBUG("handled ESP_INFO: New SPI: 0x%x\n", ntohl(esp_info->new_spi));
	HIP_DEBUG("handled ESP_INFO: Keymat Index: %u\n",
		  ntohs(esp_info->keymat_index));

	prev_spi_out = ntohl(esp_info->old_spi);
	new_spi_out = ntohl(esp_info->new_spi) ? ntohl(esp_info->new_spi) : prev_spi_out;
	
	_HIP_DEBUG("new_spi_out: 0x%x\n",
		  new_spi_out);	

	HIP_ASSERT(prev_spi_out != 0 && new_spi_out != 0);

	prev_spi_in = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));

	/* use the new inbound IPsec SA created when rekeying started */
	HIP_IFEL(!(new_spi_in = hip_update_get_new_spi_in(entry, ntohl(ack->peer_update_id))), -1,
		 "Did not find related New SPI for peer Update ID %u\n", ntohl(ack->peer_update_id));
	HIP_DEBUG("prev_spi_in=0x%x new_spi_in=0x%x prev_spi_out=0x%x new_spi_out=0x%x\n",
		  prev_spi_in, new_spi_in, prev_spi_out, new_spi_out);

	HIP_IFEL(!(kmindex_saved = hip_update_get_spi_keymat_index(entry, ntohl(ack->peer_update_id))),
		 -1, "Saved kmindex is 0\n");

	_HIP_DEBUG("saved kmindex for ESP_INFO is %u\n", kmindex_saved);

	/* 2. .. If the system did not generate new KEYMAT, it uses
	   the lowest Keymat Index of the two ESP_INFO parameters. */
	_HIP_DEBUG("entry keymat index=%u\n", entry->current_keymat_index);
	keymat_index = kmindex_saved < ntohs(esp_info->keymat_index) ? kmindex_saved : ntohs(esp_info->keymat_index);
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
	hip_update_entry_keymat(entry, keymat_index, calc_index_new,
	    keymat_index - esp_transf_length * 2 - auth_transf_length * 2, Kn);
	
	/* XFRM API doesn't support multiple SA for one SP */
	hip_delete_hit_sp_pair(hits, hitr, IPPROTO_ESP, 1);
	
	hip_delete_sa(prev_spi_out, &entry->preferred_address, &entry->local_address, AF_INET6, 0, entry->peer_udp_port);
	hip_delete_sa(prev_spi_in, &entry->local_address, &entry->preferred_address, AF_INET6, entry->peer_udp_port,0);

	/* SP and SA are always added, not updated, due to the xfrm api limitation */
	HIP_IFEL(hip_setup_hit_sp_pair(hits, hitr,
				       &entry->preferred_address, &entry->local_address,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

	/* set up new outbound IPsec SA */
	HIP_DEBUG("Setting up new outbound SA, SPI=0x%x\n", new_spi_out);

	err = hip_add_sa(&entry->preferred_address, &entry->local_address,
			 hits, hitr, 
	/* FIXME: Currently NULLing the stateless info. Send port info through entry parameter --Abi */
			 /*&esp_info->new_spi*/ &new_spi_in, esp_transform,
			 (we_are_HITg ? &espkey_lg  : &espkey_gl),
			 (we_are_HITg ? &authkey_lg : &authkey_gl),
			 1, HIP_SPI_DIRECTION_IN, 0, entry->peer_udp_port,
			 (entry->nat_mode ? HIP_NAT_UDP_PORT : 0)); //, -1,
			// 1, HIP_SPI_DIRECTION_IN, 0, 0, 0); //, -1,
	//"Setting up new outbound IPsec SA failed\n");
	HIP_DEBUG("New outbound SA created with SPI=0x%x\n", new_spi_out);
	HIP_DEBUG("Setting up new inbound SA, SPI=0x%x\n", new_spi_in);

	err = hip_add_sa(&entry->local_address, &entry->preferred_address,
			 hitr, hits,
			 &new_spi_out, esp_transform,
			 (we_are_HITg ? &espkey_gl : &espkey_lg),
			 (we_are_HITg ? &authkey_gl : &authkey_lg),
			 1, HIP_SPI_DIRECTION_OUT, 0 /*prev_spi_out == new_spi_out*/,
			 (entry->nat_mode ? HIP_NAT_UDP_PORT : 0), entry->peer_udp_port);
			 //1, HIP_SPI_DIRECTION_OUT, 0 /*prev_spi_out == new_spi_out*/, 0, 0);
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
	hip_hadb_set_default_out_addr(entry,
				      hip_hadb_get_spi_list(entry, new_spi_out), NULL);

	/* 4. The system cancels any timers protecting the UPDATE and
	   transitions to ESTABLISHED. */
	entry->state = HIP_STATE_ESTABLISHED;

	HIP_DEBUG("Went back to ESTABLISHED state\n");

	/* delete old SAs */
	if (prev_spi_out != new_spi_out) {
		HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
		/* SA is bounded to IP addresses! */
		//hip_delete_sa(prev_spi_out, hits, hitr, AF_INET6);
		HIP_DEBUG("TODO: set new spi to 0\n");
		_HIP_DEBUG("delete_sa out retval=%d\n", err);
		err = 0;
	} else
		HIP_DEBUG("prev SPI_out = new SPI_out, not deleting the outbound SA\n");

	if (prev_spi_in != new_spi_in) {
		HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
		/* SA is bounded to IP addresses! */
		/////hip_delete_sa(prev_spi_in, hitr, hits, AF_INET6);
		/* remove old HIT-SPI mapping and add a new mapping */

		/* actually should change hip_hadb_delete_inbound_spi
		 * somehow, but we do this or else delete_inbound_spi
		 * would delete both old and new SPIs */
		//hip_hadb_remove_hs(prev_spi_in);
		/*err = hip_hadb_insert_state_spi_list(&entry->hit_peer, 
						     &entry->hit_our,
						     new_spi_in);
		if (err == -EEXIST) {
			HIP_DEBUG("HIT-SPI mapping already exists, hmm ..\n");
			err = 0;
		} else if (err) {
			HIP_ERROR("Could not add a HIT-SPI mapping for SPI 0x%x (err=%d)\n",
				  new_spi_in, err);
		}*/
	} else
		_HIP_DEBUG("prev SPI_in = new SPI_in, not deleting the inbound SA\n");

	/* start verifying addresses */
	HIP_DEBUG("start verifying addresses for new spi 0x%x\n", new_spi_out);
	err = entry->hadb_update_func->hip_update_send_addr_verify(entry, msg, NULL, new_spi_out);
	if (err)
		HIP_DEBUG("address verification had errors, err=%d\n", err);
	err = 0;

 out_err:
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_update_do_finish_rekey(hip_ha_t *entry,
			       struct hip_spi_in_item *item,
			       void *_msg)
{
	struct hip_common *msg = _msg;
	int err = 0;

	_HIP_DEBUG("test item: spi_in=0x%x seq=%u updflags=0x%x\n",
		   item->spi, item->seq_update_id, item->update_state_flags);

	if (item->update_state_flags != 0x3)
		goto out_err;

	HIP_IFEL(hip_update_finish_rekeying(msg, entry,
					    &item->stored_received_esp_info),
		 -1, "Finish rekeying failed\n");

 out_err:

	HIP_DEBUG("update_finish handling ret err=%d\n", err);
	return err;
}

/**
 * hip_handle_update_rekeying - handle incoming UPDATE packet received in REKEYING state
 * @param entry hadb entry corresponding to the peer
 * @param msg the HIP packet
 * @param src_ip source IPv6 address from where the UPDATE was sent
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * @return 0 if successful, otherwise < 0.
 */
int hip_handle_update_rekeying(hip_ha_t *entry, struct hip_common *msg,
			       struct in6_addr *src_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct in6_addr daddr;
	//u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */
	uint16_t mask = 0;

	/* 8.11.2  Processing an UPDATE packet in state REKEYING */

	HIP_DEBUG("\n");

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	if (seq && esp_info) {
		/* 1. If the packet contains a SEQ and ESP_INFO parameters, then the system
		   generates a new UPDATE packet with an ACK of the peer's Update ID
		   as received in the SEQ parameter. .. */
		HIP_IFE(!(update_packet = hip_msg_alloc()), -ENOMEM);
		entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);
		HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
			 "Building of ACK param failed\n");
	}

	if (esp_info && ack) { /* kludge */
		uint32_t s = hip_update_get_prev_spi_in(entry,
							ntohl(ack->peer_update_id));
		hip_update_set_status(entry, s, 0x4, 0, 0, esp_info, 0);
	}
	/* .. Additionally, if the UPDATE packet contained an ACK of the
	   outstanding Update ID, or if the ACK of the UPDATE packet that
	   contained the ESP_INFO has already been received, the system stores
	   the received ESP_INFO and (optional) DIFFIE_HELLMAN parameters and
	   finishes the rekeying procedure as described in Section
	   8.11.3. If the ACK of the outstanding Update ID has not been
	   received, stay in state REKEYING after storing the recived ESP_INFO
	   and (optional) DIFFIE_HELLMAN. */

	if (ack) /* breaks if packet has no ack but esp_info exists ? */
		hip_update_handle_ack(entry, ack, esp_info ? 1 : 0);
	/* if (esp_info)
	   hip_update_handle_esp_info(entry, puid); kludge */

	/* finish SAs if we have received ACK and ESP_INFO */
	HIP_IFEL(hip_update_for_each_local_addr(hip_update_do_finish_rekey,
						entry, msg),
		 -1, "Rekeying failure\n");

	HIP_IFEL(!update_packet, 0, "UPDATE packet NULL\n");

	/* Send ACK */

	/** @todo hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");
        HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1,
		 "Failed to get peer address\n");

	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(&entry->local_address, &daddr,
			      (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			      entry->peer_udp_port,
			      update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");
	
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

int hip_build_verification_pkt(hip_ha_t *entry,
			       struct hip_common *update_packet, 
			       struct hip_peer_addr_list_item *addr,
			       struct in6_addr *hits,
	       		       struct in6_addr *hitr){

	int err = 0;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	HIP_DEBUG("building verification packet\n");
	hip_msg_init(update_packet);
	entry->hadb_misc_func->hip_build_network_hdr(update_packet,
						     HIP_UPDATE, mask,
						     hitr, hits);
	entry->update_id_out++;
	addr->seq_update_id = entry->update_id_out;


	_HIP_DEBUG("outgoing UPDATE ID for LOCATOR addr check=%u\n",
			   addr->seq_update_id);

	/* Reply with UPDATE(ESP_INFO, SEQ, ACK, ECHO_REQUEST) */
	
	/* ESP_INFO */
	HIP_IFEL(hip_build_param_esp_info(update_packet,
					  entry->current_keymat_index,
					  esp_info_old_spi,
					  esp_info_new_spi),
		 -1, "Building of ESP_INFO param failed\n");
	/* todo: handle overflow if (!update_id_out) */
	/* Add SEQ */
	HIP_IFEBL2(hip_build_param_seq(update_packet,
				       addr->seq_update_id), -1,
		 return , "Building of SEQ failed\n");

	/* TODO: NEED TO ADD ACK */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(addr->seq_update_id)), -1,
	  "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEBL2(hip_build_param_hmac_contents(update_packet,
						 &entry->hip_hmac_out),
			  -1, return , "Building of HMAC failed\n");
	/* Add SIGNATURE */
	HIP_IFEBL2(entry->sign(entry->our_priv, update_packet),
		   -EINVAL, return , "Could not sign UPDATE\n");
	get_random_bytes(addr->echo_data, sizeof(addr->echo_data));

	/* Add ECHO_REQUEST */
	HIP_HEXDUMP("ECHO_REQUEST in LOCATOR addr check",
			     addr->echo_data, sizeof(addr->echo_data));
	HIP_IFEBL2(hip_build_param_echo(update_packet, addr->echo_data,
						sizeof(addr->echo_data), 0, 1),
			   -1, return , "Building of ECHO_REQUEST failed\n");
	HIP_DEBUG("sending addr verify pkt\n");

 out_err:
	if (update_packet && err)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;


}

int hip_update_send_addr_verify_packet(hip_ha_t *entry,
				       struct hip_peer_addr_list_item *addr,
				       struct hip_spi_out_item *spi_out,
				       void *saddr) {
	struct in6_addr *src_ip = saddr;
	/** @todo Make this timer based:
	 * 	 If its been too long before active addresses were verfied, 
	 * 	 	verify them as well
	 * 	 else 
	 * 	 	verify only unverified addresses
	 */
	return hip_update_send_addr_verify_packet_all(entry, addr, spi_out, src_ip, 0);

}


int hip_update_send_addr_verify_packet_all(hip_ha_t *entry,
					   struct hip_peer_addr_list_item *addr,
					   struct hip_spi_out_item *spi_out,
					   struct in6_addr *src_ip,
					   int verify_active_addresses)
{
	int err = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr *hits = &entry->hit_our, *hitr = &entry->hit_peer;

	HIP_DEBUG_HIT("new addr to check", &addr->address);
	HIP_DEBUG("address state=%d\n", addr->address_state);

	if (addr->address_state == PEER_ADDR_STATE_DEPRECATED) {
		HIP_DEBUG("addr state is DEPRECATED, not verifying\n");
		goto out_err;
	}

	if ((addr->address_state == PEER_ADDR_STATE_ACTIVE)){
		
		if(verify_active_addresses){
			HIP_DEBUG("Verifying already active address. Setting as unverified\n"); 
			addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			if (addr->is_preferred) {
				HIP_DEBUG("TEST (maybe should not do this yet?): setting already active address and set as preferred to default addr\n");
				hip_hadb_set_default_out_addr(entry, spi_out,
							      &addr->address); //CHECK: Is this the correct function? -Bagri
			}
		}
		else
			goto out_err;
		//continue;
	}

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt(entry, update_packet, addr, hits,
					    hitr),
		 -1, "Building Verification Packet failed\n");
	
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(src_ip, &addr->address,
			      (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			      entry->peer_udp_port, update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");
	
 out_err:
	return err;
}

/**
 * hip_update_send_addr_verify - send address verification UPDATE
 * @param entry hadb entry corresponding to the peer
 * @param msg the HIP packet
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @param spi outbound SPI in host byte order
 *
 * @entry must be is locked when this function is called.
 *
 * @return 0 if successful, otherwise < 0.
 :*/
int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi)
{
	int err = 0;
	struct hip_spi_out_item *spi_out;
	uint16_t mask = 0;

	HIP_DEBUG("SPI=0x%x\n", spi);
	
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, spi)), -1,
		 "SPI 0x%x not in SPI list\n");

	/* TODO: Compiler warning;
		 warning: passing argument 1 of 'hip_update_for_each_peer_addr'
		 from incompatible pointer type. */
	HIP_IFEL(hip_update_for_each_peer_addr(hip_update_send_addr_verify_packet,
					       entry, spi_out, src_ip), -1,
		 "Sending addr verify failed\n");
	
 out_err:
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_update_find_address_match(hip_ha_t *entry,
				  struct hip_locator_info_addr_item *item,
				  void *opaque) {
	struct in6_addr *addr = (struct in6_addr *) opaque;

	HIP_DEBUG_IN6ADDR("addr1", addr);
	HIP_DEBUG_IN6ADDR("addr2", &item->address);

	return !ipv6_addr_cmp(addr, &item->address);
}

int hip_update_check_simple_nat(struct in6_addr *peer_ip,
				struct hip_locator *locator) {
	int err = 0, found;
	struct hip_locator_info_addr_item *item;

        found = hip_for_each_locator_addr_item(hip_update_find_address_match,
					       NULL, locator, peer_ip);
	HIP_IFEL(found, 0, "No address translation\n");

	/* @todo: xx fixme: should APPEND the address to locator */

	HIP_IFEL(!(item = hip_get_locator_first_addr_item(locator)), -1,
		 "No addresses in locator\n");
	ipv6_addr_copy(&item->address, peer_ip);
	HIP_DEBUG("Assuming NATted peer, overwrote first locator\n");

out_err:

	return err;
}

/** hip_handle_update_plain_locator - handle UPDATE(LOCATOR, SEQ)
 * @param entry hadb entry corresponding to the peer
 * @param msg the HIP packet
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @param dst_ip destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * For each address in the LOCATOR, we reply with ACK and
 * UPDATE(SPI, SEQ, ACK, ECHO_REQUEST)
 *
 * @return 0 if successful, otherwise < 0.
 */
int hip_handle_update_plain_locator(hip_ha_t *entry, struct hip_common *msg,
				    struct in6_addr *src_ip,
				    struct in6_addr *dst_ip,
				    struct hip_esp_info *esp_info,
				    struct hip_seq *seq)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_locator *locator;
	uint16_t mask = 0;
        struct hip_peer_addr_list_item *list_item;
        u32 spi_in;
        u32 spi_out = ntohl(esp_info->new_spi);
        
	HIP_DEBUG("\n");
       
	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	HIP_IFEL(locator == NULL, -1, "No locator!\n");
	HIP_IFEL(esp_info == NULL, -1, "No esp_info!\n");

	/* return value currently ignored, no need to abort on error? */ 
	/* XX FIXME: we should ADD the locator, not overwrite */
	if (entry->nat_mode)
		hip_update_check_simple_nat(src_ip, locator);

        /* remove unused addresses from peer addr list */
        list_item = malloc(sizeof(struct hip_peer_addr_list_item));
        if (!list_item) 
            goto out_err;
        ipv6_addr_copy(&list_item->address, &entry->preferred_address);
        HIP_DEBUG_HIT("Checking if preferred address was in locator", &list_item->address);
        if (!hip_update_locator_contains_item(locator, list_item)) {
            HIP_DEBUG("Preferred address was not in locator, so changing it"
                      " and removing SAs\n");
            spi_in = hip_hadb_get_latest_inbound_spi(entry);
            hip_delete_sa(spi_in, &entry->local_address, 
                          &entry->preferred_address, AF_INET6,0,
                          (int)entry->peer_udp_port);
            hip_delete_sa(entry->default_spi_out, &entry->preferred_address, 
                          &entry->local_address, AF_INET6,0,
                          (int)entry->peer_udp_port);
            ipv6_addr_copy(&entry->preferred_address, src_ip); 
        }

        if (!hip_hadb_get_spi_list(entry, spi_out)) {
		struct hip_spi_out_item spi_out_data;

		HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = spi_out;
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1); 
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created yet)\n",
			spi_out);
	}

	HIP_IFEL(hip_update_handle_locator_parameter(entry, locator, esp_info),
		 -1, "hip_update_handle_locator_parameter failed\n");

 out_err:
	if (update_packet)
            HIP_FREE(update_packet);
        if (list_item)
            HIP_FREE(list_item);   
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int set_address_state(hip_ha_t *entry, struct in6_addr *src_ip){
	int err = 0;
	/*
	 struct hip_spi_in_item *spi_in = NULL;
 	spi_in = hip_hadb_get_spi_in_list(entry, esp_info_old_spi);*/
//	For setting status of src_addresses to ACTIVE after echo req is obtained
	return err;
}

/** hip_handle_update_addr_verify - handle address verification UPDATE
 * @param entry hadb entry corresponding to the peer
 * @param msg the HIP packet
 * @param src_ip source IPv6 address to use in the UPDATE to be sent out
 * @param dst_ip destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * handle UPDATE(SPI, SEQ, ACK, ECHO_REQUEST) or handle UPDATE(SPI,
 * SEQ, ECHO_REQUEST)
 *
 * @return 0 if successful, otherwise < 0.
 */
int hip_handle_update_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip,
				  struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo = NULL;
	uint16_t mask = 0;

	HIP_DEBUG("\n");

	/* Assume already locked entry */
	HIP_IFEL(!(echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST)), -1, 
		 "ECHO not found\n");
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1, 
		 "SEQ not found\n");
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory\n");


	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, hitr, hits);

	/* reply with UPDATE(ACK, ECHO_RESPONSE) */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
		 "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1, 
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");

	/* ECHO_RESPONSE (no sign) */
	HIP_DEBUG("echo opaque data len=%d\n",
		   hip_get_param_contents_len(echo));

	HIP_HEXDUMP("ECHO_REQUEST in LOCATOR addr check",
			     (void *)echo +
		     	     sizeof(struct hip_tlv_common),
			     hip_get_param_contents_len(echo));

	HIP_IFEL(hip_build_param_echo(update_packet,
				      (void *)echo +
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_len(echo), 0, 0),
		 -1, "Building of ECHO_RESPONSE failed\n");

	HIP_DEBUG("Sending ECHO RESPONSE/UPDATE packet (address check).\n");
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(dst_ip, src_ip,
			      (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			      entry->peer_udp_port, update_packet, entry, 0),
		 -ECOMM, "Sending UPDATE packet failed.\n");
	
	HIP_IFEL(set_address_state(entry, src_ip),
		 -1, "Setting Own address status to ACTIVE failed\n");

	entry->update_state = 0; /* No retransmissions */

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_handle_update_seq(hip_ha_t *entry, 
		          struct hip_common *msg)
	
{
	int err = 0;
	uint32_t pkt_update_id = 0; /* UPDATE ID in packet */
        uint32_t update_id_in = 0;  /* stored incoming UPDATE ID */
        int is_retransmission = 0;
        struct hip_seq *seq = NULL;
	struct hip_hmac *hmac = NULL;
	struct hip_dh_fixed *dh;

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	pkt_update_id = ntohl(seq->update_id);
	HIP_DEBUG("SEQ: UPDATE ID: %u\n", pkt_update_id);
	
	update_id_in = entry->update_id_in;
	_HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
	
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


	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	HIP_IFEL(hmac == NULL, -1, "HMAC not found. Dropping packet\n");
	
	/* 
	 * 3. The system MUST verify the HMAC in the UPDATE packet.
	 * If the verification fails, the packet MUST be dropped. 
	 * **Moved to receive_update due to commonality with ack processing**
	 *
	 *
	 * 4. The system MAY verify the SIGNATURE in the UPDATE
	 * packet. If the verification fails, the packet SHOULD be
	 * dropped and an error message logged. 
	 * **Moved to receive_update due to commonality with ack processing**
	 *
	*/

	/* 5.  If a new SEQ parameter is being processed, 
	   the system MUST record the Update ID in the 
	   received SEQ parameter, for replay protection. */
	if (seq && !is_retransmission) {
		entry->update_id_in = pkt_update_id;
		_HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}
 out_err:
	if (err)
		HIP_ERROR("SEQUENCE handler failed, err=%d\n", err);

	return err;


}


int hip_set_rekeying_state(hip_ha_t *entry,
			   struct hip_esp_info *esp_info){
	int err = 0;
	uint32_t old_spi, new_spi;

	old_spi = esp_info->old_spi;
       	new_spi = esp_info->new_spi; 

       	if(hip_update_exists_spi(entry, ntohl(old_spi),
		                 HIP_SPI_DIRECTION_OUT, 0) || 
			         old_spi == 0){ 
        	/* old SPI is the existing SPI  or is zero*/
		if(old_spi == new_spi)
			/* mm-04 5.3 1. old SPI is equal to new SPI
			 */
			entry->update_state = 0; //no rekeying
			//FFT: Do we need a sanity check that both old_spi and new_spi cant be zero
		else if(new_spi != 0){
			/* mm-04 5.3 2. Old SPI is existing SPI and new SPI is non-zero
			 *           3. Old SPI is zero and new SPI is non-zero
			 */
			entry->update_state = HIP_UPDATE_STATE_REKEYING;
		}
		else {
			/* mm-04 5.3 4. Old SPI is existing, new SPI is zero
			 */
			entry->update_state = HIP_UPDATE_STATE_DEPRECATING;	
		}

	
	}
 	return entry->update_state;		
		
}	

int hip_handle_esp_info(struct hip_common *msg, 
		        hip_ha_t *entry){	
	

	int err = 0, keying_state = 0;
	struct hip_esp_info *esp_info;
	uint16_t keymat_index = 0;
	struct hip_dh_fixed *dh;
	
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	keymat_index = ntohs(esp_info->keymat_index);
	
	keying_state = hip_set_rekeying_state(entry, esp_info);	
        //HIP_IFEL(keying_state, -1, "Protocol Error: mm-04 Sec 5.3\n");
 
	switch(keying_state){
		case HIP_UPDATE_STATE_REKEYING:
			/* @todo: rekeying stuff goes here */
			break;
		case HIP_UPDATE_STATE_DEPRECATING:
			break;
		default:
			// No rekeying
			return 0;
	}
	
	/* esp-02 6.9 1. If the received UPDATE contains a
	 * Diffie-Hellman parameter, the received Keymat 
	 * Index MUST be zero. If this test fails, the packet
	 *  SHOULD be dropped and the system SHOULD log an 
	 *  error message. */

	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		HIP_IFEL(!esp_info, -1, "Packet contains DH but not ESP_INFO\n");
		HIP_IFEL(keymat_index != 0, -EINVAL,
			 "UPDATE contains Diffie-Hellman parameter with non-zero"
			 "keymat value %u in ESP_INFO. Dropping\n", keymat_index);
	}
	/* esp-02 6.9 2. if no outstanding request, process as in sec 6.9.1
	 */	
        // TODO:Check for outstanding rekeying request
	/* esp-02 6.9 3. If there is an outstanding rekeying request,
	 * UPDATE must be acked, save ESP_INFO, DH params, continue 
	 * processing as stated in 6.10
	 */
	


out_err: 
	if(err)
		HIP_DEBUG("Error while processing Rekeying for update packet err=%d", err);
	return err;
}

int hip_create_reg_response(hip_ha_t *entry, struct hip_tlv_common * reg,
			    uint8_t *requests, int request_count,
			    in6_addr_t *src_ip, in6_addr_t *dst_ip)
{
        int err = 0;
        uint16_t mask = 0;
        struct hip_common *update_packet = NULL;
        uint32_t update_id_out = 0;
        struct hip_reg_request *reg_request = NULL;
        
        if (reg != NULL) {
                reg_request = (struct hip_reg_request *)reg;
                HIP_DEBUG("Received registration message from client\n");
        }
        
        /* Reply with UPDATE-packet containing the response */
        
        HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
                 "Out of memory.\n");
        HIP_DEBUG_HIT("sending UPDATE to", &entry->hit_peer);
        HIP_DEBUG_HIT("... from", &entry->hit_our);

        entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
                                                     mask, &entry->hit_our,
                                                     &entry->hit_peer);
        /********** SEQ **********/  
        entry->update_id_out++;
        update_id_out = entry->update_id_out;
        /* todo: handle this case */
        HIP_IFEL(!update_id_out, -EINVAL,
                 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
        HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
                 "Building of SEQ param failed\n");
            
        /********** ACK **********/  
        /* Piggyback ACK of the received message */
        if (reg_request) {
                HIP_IFEL(hip_build_param_ack(update_packet, entry->update_id_in), -1,
                        "Building of ACK failed\n");
        }
        /********** REG_RESPONSE/REG_FAILED **********/        
        /* Check service requests and build reg_response and/or reg_failed */
	/** @todo change to use hip_handle_regrequest(). For that we need
	    entry, source message and destination message. We don't have the
	    source message here... */
	hip_handle_registration_attempt(entry, update_packet, reg_request, 
					requests, request_count);
        
        
        /********** HMAC **********/
        HIP_IFEL(hip_build_param_hmac_contents(update_packet,
                                               &entry->hip_hmac_out), -1,
                 "Building of HMAC failed\n");

        /********** SIGNATURE **********/
        HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
                 "Could not sign UPDATE. Failing\n");

        /********** Send UPDATE **********/
        HIP_DEBUG("Sending UPDATE packet with registration response\n");
        HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(src_ip, dst_ip, 0, 0,
                update_packet, entry, 1), -1, "csum_send failed\n");
out_err: 
        return err;
}



int hip_handle_reg_info(hip_ha_t * entry, struct hip_tlv_common * reg, 
        uint8_t *types, int type_count)
{       
        struct hip_reg_info *reg_info = (struct hip_reg_info *)reg;
        /*TODO: Server announces that new services are available. */
}


#ifdef CONFIG_HIP_ESCROW

int hip_handle_escrow_parameter(hip_ha_t * entry, 
	struct hip_keys * keys)
{
	uint32_t spi, spi_old;
	uint16_t op, len, alg;
	int err = 0;
	HIP_KEA * kea = NULL; 
	HIP_KEA_EP * ep = NULL;
	struct in6_addr * hit, * peer_hit, * ip;
	int accept = 0;
	
	HIP_IFEL(!(kea = hip_kea_find(&entry->hit_peer)), -1, 
		"No KEA found: Could not add escrow endpoint info");
	
	 hit = (struct in6_addr *)&keys->hit;
         peer_hit = (struct in6_addr *)&keys->peer_hit;
	 ip = (struct in6_addr *)&keys->address;		
	 
	 HIP_DEBUG_HIT("handle escrow param hit:", hit);
	 
	 op = ntohs(keys->operation);
	 spi = ntohl(keys->spi);
	 spi_old = ntohl(keys->spi_old);
	 len = ntohs(keys->key_len);
	 alg = ntohs(keys->alg_id);

	 switch (op) {
	 	
	 	case HIP_ESCROW_OPERATION_ADD:
	 		HIP_IFEL(!(ep = hip_kea_ep_create(hit, peer_hit, ip, alg,
				spi, len, &keys->enc)), -1,
				"Error creating kea endpoint");
	 		HIP_IFEBL(hip_kea_add_endpoint(kea, ep), -1, hip_kea_put_ep(ep), 
	 			"Error while adding endpoint");
                        break;
	 	
	 	case HIP_ESCROW_OPERATION_MODIFY:
	 		HIP_IFEL(!(ep = hip_kea_ep_find(ip, spi_old)), -1, 
	 			"Could not find endpoint to be modified");
	 		hip_kea_remove_endpoint(ep);
	 		HIP_IFEL(!(ep = hip_kea_ep_create(hit, peer_hit, ip, alg,
				spi, len, &keys->enc)), -1,
				"Error creating kea endpoint");
	 		HIP_IFEBL(hip_kea_add_endpoint(kea, ep), -1, hip_kea_put_ep(ep), 
	 			"Error while adding endpoint");	
	 		break;
	 	
	 	case HIP_ESCROW_OPERATION_DELETE:
	 		HIP_IFEL(!(ep = hip_kea_ep_find(ip, spi_old)), -1, 
	 			"Could not find endpoint to be deleted");
	 		hip_kea_remove_endpoint(ep);
	 		break;
	 	
	 	default:	
	 		HIP_ERROR("Unknown operation type in escrow parameter %d", 
	 			op);	 
			accept = -1;	
	 }
	/* If firewall is used, the received information shuold be delivered 
	 * to it. TODO: a better place for this? */ 	
	if (accept == 0) {
		if (hip_firewall_is_alive()) {
			HIP_DEBUG("Firewall alive!\n");
			if (hip_firewall_add_escrow_data(entry, hit, peer_hit, keys))
				HIP_DEBUG("Sent data to firewall\n");
		}
	}
			
out_err:
	if (kea)
		hip_keadb_put_entry(kea);
	if (err)
		HIP_DEBUG("Error while handlling escrow parameter");		
	return err;
}

#endif //CONFIG_HIP_ESCROW

int hip_handle_encrypted(hip_ha_t *entry, 
	struct hip_tlv_common *enc)
{
	int err = 0;
	char * tmp_enc = NULL;
	struct hip_tlv_common * enc_param = NULL;
	uint16_t crypto_len;
	unsigned char *iv;
	int param_type;
	
	HIP_DEBUG("hip_handle_encrypted\n");

	HIP_IFEL(!(tmp_enc = HIP_MALLOC(hip_get_param_total_len(enc),
					GFP_KERNEL)), -ENOMEM,
		 "No memory for temporary parameter\n");

	memcpy(tmp_enc, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/
	_HIP_HEXDUMP("Recv. Key", &entry->hip_enc_in.key, 24);

	switch (entry->hip_transform) {
	case HIP_HIP_AES_SHA1:
 		enc_param = (struct hip_tlv_common *)
		  (tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
 		iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 16 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
		HIP_DEBUG("aes crypto len: %d\n", crypto_len);
		break;
	case HIP_HIP_3DES_SHA1:
 		enc_param = (struct hip_tlv_common *)
		  (tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
 		iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 8 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
		break;
	case HIP_HIP_NULL_SHA1:
		enc_param = (struct hip_tlv_common *)
			(tmp_enc + sizeof(struct hip_encrypted_null_sha1));
 		iv = NULL;
 		/* 4 = reserved */
 		crypto_len = hip_get_param_contents_len(enc) - 4;
		break;
	default:
		HIP_IFEL(1, -EINVAL, "Unknown HIP transform: %d\n", entry->hip_transform);
	}

	HIP_DEBUG("Crypto encrypted\n");
	_HIP_HEXDUMP("IV: ", iv, 16); /* Note: iv can be NULL */
	
	HIP_IFEL(hip_crypto_encrypted(enc_param, iv, entry->hip_transform,
				      crypto_len, &entry->hip_enc_in.key,
				      HIP_DIRECTION_DECRYPT), -EINVAL,
		 "Decryption of encrypted parameter failed\n");
	
	param_type = hip_get_param_type(enc_param);
	
	/* Handling contents */
	 switch (param_type) {
	 case HIP_PARAM_KEYS:
#ifdef CONFIG_HIP_ESCROW
	 	HIP_IFEL(hip_handle_escrow_parameter(entry, (struct hip_keys *)enc_param), -1, "Error while handling hip_keys parameter\n");
#endif
	 	break;
	 default:
	 	HIP_IFEL(1, -EINVAL, "Unknown update paramer type in encrypted %d\n", param_type);
	 }	

out_err:
	if (err)
		HIP_DEBUG("Error while handling encrypted parameter\n");		
	if (tmp_enc)
		HIP_FREE(tmp_enc);	
	return err;
}

int hip_update_peer_preferred_address(hip_ha_t *entry, struct hip_peer_addr_list_item *addr, uint32_t spi_in){

	int err = 0, i = 0;
	//uint32_t spi_in;
	struct hip_spi_in_item *item, *tmp;
        hip_list_t *item_nd = NULL, *tmp_nd = NULL;
        struct netdev_address *n;
        struct in6_addr local_addr;
        
	HIP_DEBUG("Checking spi setting 0x%x\n",spi_in); 

	HIP_DEBUG_HIT("hit our", &entry->hit_our);
	HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("local", &entry->local_address);
	HIP_DEBUG_IN6ADDR("peer", &addr->address);
        
	//spi_in = hip_get_spi_to_update_in_established(entry, &entry->local_address);
	HIP_IFEL(spi_in == 0, -1, "No inbound SPI found for daddr\n");

        if (IN6_IS_ADDR_V4MAPPED(&entry->local_address) 
            != IN6_IS_ADDR_V4MAPPED(&addr->address)) {
            HIP_DEBUG("AF difference in addrs, checking if possible to choose same AF\n");
            list_for_each_safe(item_nd, tmp_nd, addresses, i) {
                n = list_entry(item_nd);
                if (IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)) 
                    == IN6_IS_ADDR_V4MAPPED(&addr->address)) {
                    HIP_DEBUG("Found addr with same AF\n");
                    memset(&local_addr, 0, sizeof(struct in6_addr));
                    memcpy(&local_addr, hip_cast_sa_addr(&n->addr), sizeof(struct in6_addr));
                    hip_print_hit("Using addr for SA", &local_addr);
                    break;
                }
            }
        } else {
            /* same AF as in addr, use &entry->local_address */
            memset(&local_addr, 0, sizeof(struct in6_addr));
            memcpy(&local_addr, &entry->local_address, sizeof(struct in6_addr));
        }

	/* @todo: enabling 1s makes hard handovers work, but softhandovers
	   fail */
#if 1
	hip_delete_hit_sp_pair(&entry->hit_our, &entry->hit_peer, IPPROTO_ESP, 1);

	hip_delete_sa(entry->default_spi_out, &addr->address, &local_addr, 
		      AF_INET6, 0, (int)entry->peer_udp_port);
#endif

#if 1
	hip_delete_hit_sp_pair(&entry->hit_peer, &entry->hit_our, IPPROTO_ESP, 1);
#endif 

	hip_delete_sa(spi_in, &addr->address, &local_addr, AF_INET6,
			      (int)entry->peer_udp_port, 0);

	HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_our, &entry->hit_peer,
				       &local_addr, &addr->address,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

	HIP_IFEL(hip_add_sa(&local_addr, &addr->address, 
			    &entry->hit_our,
			    &entry->hit_peer, 
			    &entry->default_spi_out, entry->esp_transform,
			    &entry->esp_out, &entry->auth_out, 1, 
	   		    HIP_SPI_DIRECTION_OUT, 0,  
			    (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			    entry->peer_udp_port ), -1, 
			   "Error while changing outbound security association for new peer preferred address\n");
	
#if 1
	HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_peer, &entry->hit_our,
				       &addr->address, &local_addr,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");
#endif

	HIP_IFEL(hip_add_sa(&addr->address, &local_addr, 
			    &entry->hit_peer, 
			    &entry->hit_our,
			    &spi_in, entry->esp_transform,
			    &entry->esp_in, &entry->auth_in, 1, 
	   		    HIP_SPI_DIRECTION_IN, 0,
			    (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),  
			    entry->peer_udp_port), -1, 
			   "Error while changing inbound security association for new preferred address\n");

out_err:
	return err;
}

int hip_update_handle_echo_response(hip_ha_t *entry,
				    struct hip_echo_response *echo_resp, 
                                    struct in6_addr *src_ip){

	int err = 0, i;
	hip_list_t *item, *tmp;
	struct hip_spi_out_item *out_item;

	HIP_DEBUG("\n");

	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		int ii;
		hip_list_t *a_item, *a_tmp;
		struct hip_peer_addr_list_item *addr;
		out_item = list_entry(item);

		list_for_each_safe(a_item, a_tmp, out_item->peer_addr_list, ii)
		{
			addr = list_entry(a_item);
			_HIP_DEBUG("checking address, seq=%u\n", addr->seq_update_id);
			if (memcmp(&addr->address, src_ip, sizeof(struct in6_addr)) == 0)
			{
				if (hip_get_param_contents_len(echo_resp) 
                                    != sizeof(addr->echo_data))
				{
					HIP_ERROR("echo data len mismatch\n");
					continue;
				}
				if (memcmp(addr->echo_data,
				           (void *)echo_resp+sizeof(struct hip_tlv_common),
				           sizeof(addr->echo_data)) != 0)
				{ 
					HIP_ERROR("ECHO_RESPONSE differs from ECHO_REQUEST\n");
					continue;
				}	
				HIP_DEBUG("address verified successfully, setting state to ACTIVE\n");
				addr->address_state = PEER_ADDR_STATE_ACTIVE;
				HIP_DEBUG("Changing Security Associations for the new peer address\n");
                                /* if bex address then otherwise no */
                                if (ipv6_addr_cmp(&entry->preferred_address, &addr->address)==0) {
					uint32_t spi = hip_hadb_get_spi(entry, -1);
					HIP_DEBUG("Setting SA for bex locator\n");
					HIP_IFEL(hip_update_peer_preferred_address(entry, addr, spi), -1, 
						 "Error while changing SAs for mobility\n");
                                }
				do_gettimeofday(&addr->modified_time);
				if (addr->is_preferred)
				{
					/* maybe we should do this default address selection
					   after handling the LOCATOR .. */
					hip_hadb_set_default_out_addr(entry, out_item, &addr->address);
				}
				else HIP_DEBUG("address was not set as preferred address\n");
			}
		}
	}

out_err:
	return err;
}

/**
 * hip_receive_update - receive UPDATE packet
 * @param msg buffer where the HIP packet is in
 *
 * This is the initial function which is called when an UPDATE packet
 * is received. The validity of the packet is checked and then this
 * function acts according to whether this packet is a reply or not.
 *
 * @return 0 if successful (HMAC and signature (if needed) are
 * validated, and the rest of the packet is handled if current state
 * allows it), otherwise < 0.
 */
int hip_receive_update(struct hip_common *msg, struct in6_addr *update_saddr,
		       struct in6_addr *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo)
{
	int err = 0, state = 0, has_esp_info = 0;
	int updating_addresses = 0;
	struct in6_addr *hits = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct hip_locator *locator = NULL;
	struct hip_echo_request *echo = NULL;
	struct hip_echo_response *echo_response = NULL;
        struct hip_tlv_common *reg_request = NULL;
        struct hip_tlv_common *reg_response = NULL;
        struct hip_tlv_common *reg_failed = NULL;
        struct hip_tlv_common *reg_info = NULL;
	struct in6_addr *src_ip = NULL , *dst_ip = NULL;
	struct hip_tlv_common *encrypted = NULL;
	
	HIP_DEBUG("enter\n");

	src_ip = update_saddr;
	dst_ip = update_daddr;
	hits = &msg->hits;

	HIP_IFEL(!entry, -1, "Entry not found\n");
	HIP_LOCK_HA(entry);
	state = entry->state;

	HIP_DEBUG("Received UPDATE in state %s\n", hip_state_str(state));

	/* in state R2-SENT: Receive UPDATE, go to ESTABLISHED and
	 * process from ESTABLISHED state
	 *
	 * CHK: Is it too early to do this?
	 *                           -Bagri */
	if (state == HIP_STATE_R2_SENT) {
		state = entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Moved from R2-SENT to ESTABLISHED\n");
	}

	if (!(state == HIP_STATE_ESTABLISHED) ) {
		HIP_DEBUG("Received UPDATE in illegal state %s. Dropping\n",
			  hip_state_str(state));
		err = -EINVAL;
		goto out_err;
	}

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	echo_response = hip_get_param(msg, HIP_PARAM_ECHO_RESPONSE);
	encrypted = hip_get_param(msg, HIP_PARAM_ENCRYPTED);
        reg_request = hip_get_param(msg, HIP_PARAM_REG_REQUEST);
        reg_response = hip_get_param(msg, HIP_PARAM_REG_RESPONSE);
        reg_failed = hip_get_param(msg, HIP_PARAM_REG_FAILED);
        reg_info = hip_get_param(msg, HIP_PARAM_REG_INFO);

	if(ack)
		HIP_DEBUG("ACK found: %u\n", ntohl(ack->peer_update_id));
	if (esp_info){
		HIP_DEBUG("LOCATOR: SPI new 0x%x\n", ntohl(esp_info->new_spi));
		has_esp_info = 1;
	}
        if (locator)
            HIP_DEBUG("LOCATOR found\n");
	if (echo)
		HIP_DEBUG("ECHO_REQUEST found\n");
	if (echo_response)
		HIP_DEBUG("ECHO_RESPONSE found\n");

	if (ack)
		//process ack
		entry->hadb_update_func->hip_update_handle_ack(entry, ack,
							       has_esp_info);
	if (seq)
		HIP_IFEL(hip_handle_update_seq(entry, msg), -1, "seq\n");
	
        /* base-05 Sec 6.12.1.2 6.12.2.2 The system MUST verify the 
	 * HMAC in the UPDATE packet.If the verification fails, 
	 * the packet MUST be dropped. */
	HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1, 
		 "HMAC validation on UPDATE failed\n");

	/* base-05 Sec 6.12.1.3 6.12.2.3. The system MAY verify 
	 * the SIGNATURE in the UPDATE packet. If the verification fails, 
	 * the packet SHOULD be dropped and an error message logged. */
	HIP_IFEL(entry->verify(entry->peer_pub, msg), -1, 
		 "Verification of UPDATE signature failed\n");
 	
	/* Node moves within public Internet or from behind a NAT to public
	   Internet. */
	if(sinfo->dst_port == 0){
                HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);
            	/* HIP_DEBUG("UPDATE packet was NOT destined to port 50500.\n"); */
		entry->nat_mode = 0;
		entry->peer_udp_port = 0;
		entry->hadb_xmit_func->hip_send_pkt = hip_send_raw;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	} else {
		/* Node moves from public Internet to behind a NAT, stays
		   behind the same NAT or moves from behind one NAT to behind
		   another NAT. */
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);
		entry->nat_mode = 1;
		entry->peer_udp_port = sinfo->src_port;
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		ipv6_addr_copy(&entry->local_address, dst_ip);
		ipv6_addr_copy(&entry->preferred_address, src_ip);
		
		/* Somehow the addresses in the entry doesn't get updated for
		   mobility behind nat case. The "else" would be called only
		   when the client moves from behind NAT to behind NAT.
		   Updating the entry addresses here.
		   
		   Miika: Is it the correct place to be done? -- Abi
		   
		   Error was because of multiple locator parameter, code
		   shifted to after setting of preferred address by the
		   mm logic
		   -- Bagri */	
	}
	
	if(esp_info)
		HIP_IFEL(hip_handle_esp_info(msg, entry), -1,
			 "Error in processing esp_info\n");
	
	//mm stuff after this
	if (locator)
		//handle locator parameter
		err = entry->hadb_update_func->hip_handle_update_plain_locator(entry, msg, src_ip, dst_ip, esp_info, seq);
	else if (echo) {
		//handle echo_request
		err = entry->hadb_update_func->hip_handle_update_addr_verify(entry, msg, src_ip, dst_ip);
	}
	else if (echo_response) {
		//handle echo response
		hip_update_handle_echo_response(entry, echo_response, src_ip);
	}
	
	if (encrypted) {
		// handle encrypted parameter
                HIP_DEBUG("ENCRYPTED found\n");
		HIP_IFEL(hip_handle_encrypted(entry, encrypted), -1, "Error in processing encrypted parameter\n");
                HIP_IFEL(hip_update_send_ack(entry, msg, src_ip, dst_ip), -1, "Error sending ack\n");
	}
	
        if (reg_request) {
                //handle registration request
                uint8_t *types = NULL;
                int type_count;
                types = (uint8_t *)(hip_get_param_contents(msg, HIP_PARAM_REG_REQUEST));
                type_count = hip_get_param_contents_len(reg_request) - 1; // leave out lifetime field
                HIP_IFEL(hip_create_reg_response(entry, reg_request, 
                        (uint8_t *)(types + 1), type_count, dst_ip, src_ip), -1,
                        "Error handling reg_request\n");
                
        }
        if (reg_response || reg_failed) {
                //handle registration request
                HIP_IFEL(hip_handle_registration_response(entry, msg), -1, 
                        "Error handling reg_response\n");
                HIP_IFEL(hip_update_send_ack(entry, msg, src_ip, dst_ip), -1, 
                        "Error sending ack\n");
        }
        if (reg_info) {
                //handle reg_info
                uint8_t *types = NULL;
                int type_count;
                types = (uint8_t *)(hip_get_param_contents(msg, HIP_PARAM_REG_INFO));
                type_count = hip_get_param_contents_len(reg_info) - 2; // leave out lifetime fields
                
                HIP_IFEL(hip_handle_reg_info(entry, reg_info, (types + 2), 
                        type_count), -1, "Error handling reg_info\n");
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

/** hip_copy_spi_in_addresses - copy addresses to the inbound SPI
 * @param src address list
 * @param spi_in the inbound SPI the addresses are copied to
 * @param count number of addresses in @src
 *
 * A simple helper function to copy interface addresses to the inbound
 * SPI of. Caller must kfree the allocated memory.
 *
 * @return 0 on success, < 0 otherwise.
 */
int hip_copy_spi_in_addresses(struct hip_locator_info_addr_item *src,
			      struct hip_spi_in_item *spi_in,
			      int count) {
	size_t s = count * sizeof(struct hip_locator_info_addr_item);
	void *p = NULL;

	HIP_DEBUG("src=0x%p count=%d\n", src, count);
	if (!spi_in || (src && count <= 0)) {
 		HIP_ERROR("!spi_in or src & illegal count (%d)\n", count);
		return -EINVAL;
	}

	if (src) {
	p = HIP_MALLOC(s, GFP_ATOMIC);
		if (!p) {
			HIP_ERROR("kmalloc failed\n");
			return -ENOMEM;
		}
		memcpy(p, src, s);
	} else
		count = 0;

	_HIP_DEBUG("prev addresses_n=%d\n", spi_in->addresses_n);
	if (spi_in->addresses) {
		HIP_DEBUG("kfreeing old address list at 0x%p\n",
			  spi_in->addresses);
		HIP_FREE(spi_in->addresses);
	}

	spi_in->addresses_n = count;
	spi_in->addresses = p;

	return 0;
}
/* update_preferred_address - change preferred address advertised to the peer for this connection
 * 
 * @param entry hadb entry corresponding to the peer
 * @param new_pref_addr the new prefferred address
 */
int hip_update_preferred_address(struct hip_hadb_state *entry,
				 struct in6_addr *new_pref_addr,
				 struct in6_addr *daddr,
				 uint32_t *_spi_in){

	int err = 0;
	struct hip_spi_in_item *item, *tmp;
	uint32_t spi_in = *_spi_in;
	HIP_DEBUG("Checking spi setting %x\n",spi_in); 

	HIP_DEBUG_HIT("hit our", &entry->hit_our);
	HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("new_pref_addr", new_pref_addr);
	HIP_DEBUG_IN6ADDR("daddr", daddr);

	hip_delete_hit_sp_pair(&entry->hit_our, &entry->hit_peer, IPPROTO_ESP, 1);

	hip_delete_sa(entry->default_spi_out, daddr, &entry->local_address, AF_INET6,0,
			      (int)entry->peer_udp_port);
#if 1
	hip_delete_hit_sp_pair(&entry->hit_peer, &entry->hit_our, IPPROTO_ESP, 1);
#endif
	/* @todo: check that this works with the pfkey api */
	hip_delete_sa(spi_in, &entry->local_address, &entry->hit_our, AF_INET6,
			      (int)entry->peer_udp_port, 0);

	HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_our, &entry->hit_peer,
				       new_pref_addr, daddr,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");


	HIP_IFEL(hip_add_sa(new_pref_addr, daddr, 
			    &entry->hit_our,
			    &entry->hit_peer, 
			    &entry->default_spi_out, entry->esp_transform,
			    &entry->esp_out, &entry->auth_out, 1, 
	   		    HIP_SPI_DIRECTION_OUT, 0,  
			    (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			    entry->peer_udp_port ), -1, 
			   "Error while changing outbound security association for new preferred address\n");
	
	/*hip_delete_hit_sp_pair(&entry->hit_peer, &entry->hit_our, IPPROTO_ESP, 1);

	hip_delete_sa(spi_in, &entry->local_address, AF_INET6,
			      (int)entry->peer_udp_port, 0);*/

	HIP_IFEL(_spi_in == NULL, -1, "No inbound SPI found for daddr\n");

#if 1
	HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_peer,&entry->hit_our,
				       daddr, new_pref_addr,
				       IPPROTO_ESP, 1, 0), -1,
		 			"Setting up SP pair failed\n");
#endif

	HIP_IFEL(hip_add_sa(daddr, new_pref_addr, 
			    &entry->hit_peer, 
			    &entry->hit_our,
			    &spi_in, entry->esp_transform,
			    &entry->esp_in, &entry->auth_in, 1, 
	   		    HIP_SPI_DIRECTION_IN, 0,  
			    entry->peer_udp_port,
			    (entry->nat_mode ? HIP_NAT_UDP_PORT : 0)), -1, 
			   "Error while changing inbound security association for new preferred address\n");

	ipv6_addr_copy(&entry->local_address, new_pref_addr);

out_err:
	return err;
		
}

int hip_update_src_address_list(struct hip_hadb_state *entry, 
				struct hip_locator_info_addr_item *addr_list, 
				struct in6_addr *daddr,
				int addr_count,	int esp_info_old_spi,
				int is_add, struct sockaddr* addr){
	   	
        int err = 0, i, preferred_address_found = 0; 
        int choose_random = 0, change_preferred_address = 0;
	struct hip_spi_in_item *spi_in = NULL;
	struct hip_locator_info_addr_item *loc_addr_item = addr_list;
	struct in6_addr *saddr, *comp_addr = hip_cast_sa_addr(addr);

	HIP_DEBUG("\n");
	
	/* avoid advertising the same address set */
 	/* (currently assumes that lifetime or reserved field do not
 	 * change, later store only addresses) */
 	spi_in = hip_hadb_get_spi_in_list(entry, esp_info_old_spi);
 	if (!spi_in) {
		HIP_ERROR("SPI listaddr list copy failed\n");
 		goto out_err;
 	}
 	if (addr_count == spi_in->addresses_n &&
 	    addr_list && spi_in->addresses &&
 	    memcmp(addr_list, spi_in->addresses,
 		   addr_count *
		   sizeof(struct hip_locator_info_addr_item)) == 0) {
 		HIP_DEBUG("Same address set as before, return\n");
 		return GOTO_OUT;
	} else {
		HIP_DEBUG("Address set has changed, continue\n");
	}

	/* Peer's preferred address. Can be changed by the source address
	   selection below if we don't find any addresses of the same family
	   as peer's preferred address (intrafamily handover). */
	HIP_IFE(hip_hadb_get_peer_addr(entry, daddr), -1);

        /* dont go to out_err but to ... */
        if(!addr_list) {
            HIP_DEBUG("No address list\n");
            goto skip_pref_update;
        }
        
	/* spi_in->spi is equal to esp_info_old_spi. In the loop below, we make
	 * sure that the source and destination address families match
	 */

	loc_addr_item = addr_list;

	HIP_IFEL((addr->sa_family == AF_INET), -1, "all addresses in update should be mapped");

	/* if we have deleted the old address and it was preferred than 
	   we chould make new preferred address. Now, we chose it as random address in list 
	*/
	if( !is_add && ipv6_addr_cmp(&entry->local_address, comp_addr) == 0 ) {
		choose_random = 1;
	}

	if( is_add && is_active_handover ) {
		change_preferred_address = 1;/* comp_addr = hip_cast_sa_addr(addr); */
	} else {
		comp_addr = &entry->local_address;
	} 

	if (choose_random) { 
            int been_here = 0;
        choose_random:
            loc_addr_item = addr_list;
            for(i = 0; i < addr_count; i++, loc_addr_item++) {
                struct in6_addr *saddr = &loc_addr_item->address;
                /*		HIP_HEXDUMP("a1: ", saddr, sizeof(*saddr));
				HIP_HEXDUMP("a2: ", daddr, sizeof(*daddr));
				HIP_HEXDUMP("a3: ", &entry->local_address, sizeof(*daddr));*/
                if (memcmp(comp_addr, saddr, sizeof(struct in6_addr)) == 0) {
                    if (IN6_IS_ADDR_V4MAPPED(saddr)  == IN6_IS_ADDR_V4MAPPED(daddr)) {
                        /* Select the first match */
                        loc_addr_item->reserved = ntohl(1 << 7);
                        preferred_address_found = 1;
                        if( change_preferred_address && is_add) {
                            HIP_IFEL(hip_update_preferred_address(entry,saddr,
                                                                  daddr, 
                                                                  &spi_in->spi),-1, 
                                     "Setting New Preferred Address Failed\n");		      
                        } else {
                            HIP_DEBUG("Preferred Address is the old preferred address\n");
                        }
                        HIP_DEBUG_IN6ADDR("addr: ", saddr);
                        break;
                    }
                }
            }
            if ((preferred_address_found == 0) && (been_here == 0)) {
                hip_list_t *item = NULL, *tmp = NULL, *item_outer = NULL, *tmp_outer = NULL;
                struct hip_peer_addr_list_item *addr_li;
                struct hip_spi_out_item *spi_out;
                int i = 0, ii = 0;
                list_for_each_safe(item_outer, tmp_outer, entry->spis_out, i) {
                    spi_out = list_entry(item_outer);
                    ii = 0;
                    tmp = NULL;
                    item = NULL;
                    list_for_each_safe(item, tmp, spi_out->peer_addr_list, ii) {
                        addr_li = list_entry(item);
                        hip_print_hit("SPI out addresses", &addr_li->address);
                        if (IN6_IS_ADDR_V4MAPPED(&addr_li->address) != IN6_IS_ADDR_V4MAPPED(daddr)) {
                            HIP_DEBUG("Found other family than BEX address family\n");
                            ipv6_addr_copy(daddr, &addr_li->address);
                            ipv6_addr_copy(&entry->preferred_address, &addr_li->address);
                            goto break_list_for_loop; /* or just break? FIX later */
                        }
                    }
                }
                break_list_for_loop:
                been_here = 1;
                goto choose_random;
            }           
        }
	if (preferred_address_found)
		goto skip_pref_update;

	loc_addr_item = addr_list;
	/* Select the first match */
	for(i = 0; i < addr_count; i++, loc_addr_item++)
	{
		saddr = &loc_addr_item->address;
		if (IN6_IS_ADDR_V4MAPPED(saddr) == IN6_IS_ADDR_V4MAPPED(daddr) &&
                    !is_add)
		{
                    loc_addr_item->reserved = ntohl(1 << 7);
                    HIP_DEBUG_IN6ADDR("first match: ", saddr);
                    HIP_IFEL(hip_update_preferred_address(entry,saddr,
                                                          daddr, 
                                                          &spi_in->spi),-1, 
                             "Setting New Preferred Address Failed\n");
                    preferred_address_found = 1;
                    break;
		}
	}

 skip_pref_update:

	if(!preferred_address_found && !is_add){
		memset(&entry->local_address, 0, sizeof(struct in6_addr));
		HIP_IFEL(1, GOTO_OUT, "Preferred address Not found !!\n");
	}

	/* remember the address set we have advertised to the peer */
	err = hip_copy_spi_in_addresses(addr_list, spi_in, addr_count);
	loc_addr_item = addr_list;
	for(i = 0; i < addr_count; i++, loc_addr_item++) {
		int j, addr_exists = 0;		
		struct in6_addr *iter_addr = &loc_addr_item->address;
		for(j = 0; j < spi_in->addresses_n; j++){
			struct hip_locator_info_addr_item *spi_addr_item = 
                            (struct hip_locator_info_addr_item *) spi_in->addresses + j; 
			if(ipv6_addr_cmp(&spi_addr_item->address, iter_addr)) {
				loc_addr_item->state = spi_addr_item->state;
				addr_exists = 1;
			}
		}	
		if(!addr_exists) {
			loc_addr_item->state = ADDR_STATE_WAITING_ECHO_REQ;
		}
	}
out_err:
	return err;



}	
/** hip_send_update - send initial UPDATE packet to the peer
 * @param entry hadb entry corresponding to the peer
 * @param addr_list if non-NULL, LOCATOR parameter is added to the UPDATE
 * @param addr_count number of addresses in @addr_list
 * @param ifindex if non-zero, the ifindex value of the interface which caused the event
 * @param flags TODO comment
 *
 * @return 0 if UPDATE was sent, otherwise < 0.
 */
int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags, 
		    int is_add, struct sockaddr* addr)
{
	int err = 0, make_new_sa = 0, /*add_esp_info = 0,*/ add_locator;
        int was_bex_addr = -1;
        int i = 0;
	uint32_t update_id_out = 0;
	uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	uint32_t new_spi_in = 0, old_spi;
	struct hip_common *update_packet = NULL;
	struct in6_addr saddr = { 0 }, daddr = { 0 };
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	struct hip_own_addr_list_item *own_address_item, *tmp;
        hip_list_t *tmp_li = NULL, *item = NULL;
        struct netdev_address *n;
	struct in6_addr zero_addr = IN6ADDR_ANY_INIT;

	HIP_DEBUG("\n");
	
        old_spi = hip_hadb_get_spi(entry, -1);
	
	add_locator = flags & SEND_UPDATE_LOCATOR;
	HIP_DEBUG("addr_list=0x%p addr_count=%d ifindex=%d flags=0x%x\n",
		  addr_list, addr_count, ifindex, flags);
	if (!ifindex)
		_HIP_DEBUG("base draft UPDATE\n");

	if (add_locator)
		HIP_DEBUG("mm UPDATE, %d addresses in LOCATOR\n", addr_count);
	else
		HIP_DEBUG("Plain UPDATE\n");

	/* Start building UPDATE packet */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory.\n");
	HIP_DEBUG_HIT("sending UPDATE to HIT", &entry->hit_peer);
	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, &entry->hit_our,
						     &entry->hit_peer);
	if (add_locator) {
		/* mm stuff, per-ifindex SA */
		/* reuse old SA if we have one, else create a new SA */
		mapped_spi = hip_hadb_get_spi(entry, ifindex);
		HIP_DEBUG("mapped_spi=0x%x\n", mapped_spi);
		if (mapped_spi) {
			make_new_sa = 0;
			_HIP_DEBUG("Mobility with single SA pair, readdress with no rekeying\n");
			HIP_DEBUG("Reusing old SA\n");
			/* Mobility with single SA pair */
		} else {
			_HIP_DEBUG("Host multihoming\n");
			make_new_sa = 1;
			_HIP_DEBUG("TODO\n");
		}
	} else {
		/* base draft UPDATE, create a new SA anyway */
		_HIP_DEBUG("base draft UPDATE, create a new SA\n");
	}

	/* If this is mm-UPDATE (ifindex should be then != 0) avoid
	 * sending empty LOCATORs to the peer if we have not sent previous
	 * information on this ifindex/SPI yet */
	if (ifindex != 0 && mapped_spi == 0 && addr_count == 0) {
		HIP_DEBUG("NETDEV_DOWN and ifindex not advertised yet, returning\n");
		goto out;
	}

	HIP_DEBUG("make_new_sa=%d\n", make_new_sa);

	if (make_new_sa) {
		HIP_IFEL(!(new_spi_in = hip_acquire_spi(&entry->hit_peer,
							&entry->hit_our)), 
			 -1, "Error while acquiring a SPI\n");
		HIP_DEBUG("Got SPI value for the SA 0x%x\n", new_spi_in);

		/** @todo move to rekeying_finish */
		if (!mapped_spi) {
			struct hip_spi_in_item spi_in_data;

			_HIP_DEBUG("previously unknown ifindex, creating a new item to inbound spis_in\n");
			memset(&spi_in_data, 0,
			       sizeof(struct hip_spi_in_item));
			spi_in_data.spi = new_spi_in;
			spi_in_data.ifindex = ifindex;
			spi_in_data.updating = 1;
			HIP_IFEL(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN,
						  &spi_in_data), -1, 
				 "Add_spi failed\n");
		} else {
			_HIP_DEBUG("is previously mapped ifindex\n");
		}
	} else {
		HIP_DEBUG("not creating a new SA\n");
		new_spi_in = mapped_spi;
	}

	_HIP_DEBUG("entry->current_keymat_index=%u\n",
		   entry->current_keymat_index);

	if (addr_list) {
		if (make_new_sa) {
			/* mm02 Host multihoming - currently simultaneous SAs are not supported */
			esp_info_old_spi = old_spi;
			esp_info_new_spi = old_spi; // new_spi_in;
			HIP_DEBUG("Multihoming, new SA: old=%x new=%x\n", esp_info_old_spi, esp_info_new_spi);
		} else {
			HIP_DEBUG("Reusing old SPI\n");
			esp_info_old_spi = mapped_spi;
			esp_info_new_spi = mapped_spi;
		}
	} else {
		HIP_DEBUG("adding ESP_INFO, Old SPI <> New SPI\n");
		/* plain UPDATE or readdress with rekeying */
		/* update the SA of the interface which caused the event */
		HIP_IFEL(!(esp_info_old_spi =
			   hip_hadb_get_spi(entry, ifindex)), -1,
			 "Could not find SPI to use in Old SPI\n");
		/* here or later ? */
		hip_set_spi_update_status(entry, esp_info_old_spi, 1);
		//esp_info_new_spi = new_spi_in;
		esp_info_new_spi = esp_info_old_spi;
	}
	
        /* if del then we have to remove SAs for that address */
        was_bex_addr = ipv6_addr_cmp(hip_cast_sa_addr(addr), &entry->local_address);

	if (is_add && !ipv6_addr_cmp(&entry->local_address, &zero_addr)) {
	    ipv6_addr_copy(&entry->local_address, hip_cast_sa_addr(addr));
             err = hip_update_src_address_list(entry, addr_list, &daddr,
                                              addr_count, esp_info_new_spi, is_add, addr);
           if(err == GOTO_OUT)
		goto out;
            else if(err)
                goto out_err;

	   HIP_IFEL(err = hip_update_preferred_address(entry, hip_cast_sa_addr(addr),
						       &entry->preferred_address,
						       &esp_info_new_spi), -1,
		    "Updating peer preferred address failed\n");
           
	}

        if (!is_add && (was_bex_addr == 0)) {
            HIP_DEBUG("Netlink event was del, removing SAs for the address for this entry\n");
            hip_delete_sa(esp_info_old_spi, hip_cast_sa_addr(addr), 
                          &entry->preferred_address, AF_INET6,0,
                          (int)entry->peer_udp_port);
            hip_delete_sa(entry->default_spi_out, &entry->preferred_address, 
                          hip_cast_sa_addr(addr), AF_INET6,0,
                          (int)entry->peer_udp_port);
     
            /* and we have to do it before this changes the local_address */
            err = hip_update_src_address_list(entry, addr_list, &daddr,
                                              addr_count, esp_info_old_spi, is_add, addr);
            if(err == GOTO_OUT)
		goto out;
            else if(err)
                goto out_err;
        }

	/* Send UPDATE(ESP_INFO, LOCATOR, SEQ) */
	HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
		  esp_info_old_spi, esp_info_new_spi);
	HIP_IFEL(hip_build_param_esp_info(update_packet,
					  entry->current_keymat_index,
					  esp_info_old_spi,
					  esp_info_new_spi),
			 -1, "Building of ESP_INFO param failed\n");
 	
	if (add_locator) {
		err = hip_build_param_locator(update_packet, addr_list,
					      addr_count);

		HIP_IFEL(err, err, "Building of LOCATOR param failed\n");
	} else
		HIP_DEBUG("not adding LOCATOR\n");

	hip_update_set_new_spi_in(entry, esp_info_old_spi,
				  esp_info_new_spi, 0);
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	/* todo: handle this case */
	HIP_IFEL(!update_id_out, -EINVAL,
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ param failed\n");

	/* remember the update id of this update */
	hip_update_set_status(entry, esp_info_old_spi,
			      0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
			      entry->current_keymat_index);

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
	 	 "Could not sign UPDATE. Failing\n");

	/* Send UPDATE */
	hip_set_spi_update_status(entry, esp_info_old_spi, 1);


        /* before sending check if the AFs match and do something about it
           so it doesn't fail in raw send */

        if(IN6_IS_ADDR_V4MAPPED(&entry->local_address) 
           == IN6_IS_ADDR_V4MAPPED(&daddr))
            memcpy(&saddr, &entry->local_address, sizeof(saddr));
	else {
            list_for_each_safe(item, tmp_li, addresses, i) {
                n = list_entry(item);
                if (IN6_IS_ADDR_V4MAPPED(&daddr) == 
                    IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr))) {
                    memcpy(&saddr, hip_cast_sa_addr(&n->addr), sizeof(saddr));
                    break;
                }
            }
        }

	HIP_DEBUG("Sending initial UPDATE packet.\n");
        /* guarantees retransmissions */
	entry->update_state = HIP_UPDATE_STATE_REKEYING;

        if (!is_add && (was_bex_addr == 0)) {
            err = entry->hadb_xmit_func->
                hip_send_pkt(&saddr, &daddr, (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
                             entry->peer_udp_port, update_packet, entry, 1);
        } else {
            err = entry->hadb_xmit_func->
                hip_send_pkt(&entry->local_address, &entry->preferred_address,
                             (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
                             entry->peer_udp_port, update_packet, entry, 1);
        }
        HIP_DEBUG("Send_pkt returned %d\n", err);
        //		 -ECOMM, "Sending UPDATE packet failed.\n");
        err = 0;
	/** @todo 5. The system SHOULD start a timer whose timeout value
	    should be ..*/
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	_HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");

	hip_set_spi_update_status(entry, esp_info_old_spi, 0);
	/* delete IPsec SA on failure */
	HIP_ERROR("TODO: delete SA\n");
 out:

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
 * Sends UPDATE packet to every peer.
 *
 * UPDATE is sent to the peer only if the peer is in established state. Add
 * LOCATOR parameter if @c addr_list is non-null. @c ifindex tells which device
 * caused the network device event.
 *
 * @param addr_list if non-NULL, LOCATOR parameter is added to the UPDATE
 * @param addr_count number of addresses in @addr_list
 * @param ifindex if non-zero, the ifindex value of the interface which caused the event
 * @param flags flags passed to @hip_send_update
 */
void hip_send_update_all(struct hip_locator_info_addr_item *addr_list,
			 int addr_count, int ifindex, int flags, int is_add, struct sockaddr *addr)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;
	struct sockaddr_in6 addr_sin6;

	/** @todo check UPDATE also with radvd (i.e. same address is added
	    twice). */

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_DEBUG("test: returning, ifindex=0 (fix this for non-mm UPDATE)\n");
		return;
	}

	if (addr->sa_family == AF_INET) {
		memset(&addr_sin6, 0, sizeof(addr_sin6));
		addr_sin6.sin6_family = AF_INET6;
		IPV4_TO_IPV6_MAP(((struct in_addr *) hip_cast_sa_addr(addr)),
				 ((struct in6_addr *) hip_cast_sa_addr(&addr_sin6)));
	} else if (addr->sa_family == AF_INET6) {
		memcpy(&addr_sin6, addr, sizeof(addr_sin6));
	} else {
		HIP_ERROR("Bad address family %d\n", addr->sa_family);
		return;
	}

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;
        /* AB: rk.length = 100 rk is NULL next line opulates rk with all valid
	ha entries */
	HIP_IFEL(hip_for_each_ha(hip_update_get_all_valid, &rk), 0, 
		 "for_each_ha err.\n");
	for (i = 0; i < rk.count; i++) {
		struct in6_addr *local_addr = &((rk.array[i])->local_address);
		if (rk.array[i] != NULL) { 

#if 0
			if (is_add && !ipv6_addr_cmp(local_addr, &zero_addr)) {
				HIP_DEBUG("Zero addresses, adding new default\n");
				ipv6_addr_copy(local_addr, &addr_sin6);
			}
#endif
			hip_send_update(rk.array[i], addr_list, addr_count,
					ifindex, flags, is_add, (struct sockaddr *) &addr_sin6);

#if 0
			if (!is_add && addr_count == 0) {
				HIP_DEBUG("Deleting last address\n");
				memset(local_addr, 0, sizeof(struct in6_addr));
			}
#endif

			hip_hadb_put_entry(rk.array[i]);
			//hip_put_ha(rk.array[i]);
		}
	}

out_err:
	return;
}


int hip_update_send_ack(hip_ha_t *entry, struct hip_common *msg,
        struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
        int err = 0;
        struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
        struct hip_common *update_packet = NULL;
        struct hip_seq *seq = NULL;
        struct hip_echo_request *echo = NULL;
        uint16_t mask = 0;

        /* Assume already locked entry */
        echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
        HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1, 
                 "SEQ not found\n");
        HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
                 "Out of memory\n");


        entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
                                                     mask, hitr, hits);

        /* reply with UPDATE(ACK, [ECHO_RESPONSE]) */
        HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
                 "Building of ACK failed\n");

        /* Add HMAC */
        HIP_IFEL(hip_build_param_hmac_contents(update_packet,
                                               &entry->hip_hmac_out), -1, 
                 "Building of HMAC failed\n");

        /* Add SIGNATURE */
        HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
                 "Could not sign UPDATE. Failing\n");

        /* ECHO_RESPONSE (no sign) */
        if (echo) {
                HIP_DEBUG("echo opaque data len=%d\n", 
                        hip_get_param_contents_len(echo));
                HIP_HEXDUMP("ECHO_REQUEST ",
                             (void *)echo +
                             sizeof(struct hip_tlv_common),
                             hip_get_param_contents_len(echo));
                HIP_IFEL(hip_build_param_echo(update_packet,
                                      (void *)echo +
                                      sizeof(struct hip_tlv_common),
                                      hip_get_param_contents_len(echo), 0, 0),
                        -1, "Building of ECHO_RESPONSE failed\n");
        }
        
        HIP_DEBUG("Sending reply UPDATE packet (ack)\n");
        HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(dst_ip, src_ip, 0, 0,
						     update_packet, entry, 0),
                 -1, "csum_send failed\n");

 out_err:
        if (update_packet)
                HIP_FREE(update_packet);
        HIP_DEBUG("end, err=%d\n", err);
        return err;      
}                                  
                                  
/* op = 0/1 (zero for cancelling registration) */
int hip_update_send_registration_request(hip_ha_t *entry, 
        struct in6_addr *server_hit, int *types, int type_count, int op) 
{
        int err = 0;
        struct hip_common *update_packet = NULL;
        struct hip_seq *seq = NULL;
        uint16_t mask = 0;
        struct in6_addr saddr = { 0 }, daddr = { 0 };
        uint8_t lifetime = 0; 
        uint32_t update_id_out = 0;
        
        /* If not cancelling, requesting maximum lifetime always (255) TODO: fix */        
        if (op)
              lifetime = 255;
                
        hip_hadb_get_peer_addr(entry, &daddr);
        memcpy(&saddr, &entry->local_address, sizeof(saddr));
                
        HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM, "Out of memory\n");
        entry->hadb_misc_func->hip_build_network_hdr(update_packet, 
                HIP_UPDATE, mask, &entry->hit_our, server_hit);
        entry->update_id_out++;
        update_id_out = entry->update_id_out;
        _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
        /* todo: handle this case */
        HIP_IFEL(!update_id_out, -EINVAL,
                "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
        HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ param failed\n");
        
        HIP_IFEL(hip_build_param_reg_request(
		      update_packet, lifetime, (uint8_t *)types, type_count, 1),
		 -1, "Building of REG_REQUEST failed\n");

        /* Add HMAC */
        HIP_IFEL(hip_build_param_hmac_contents(update_packet,
                &entry->hip_hmac_out), -1, "Building of HMAC failed\n");
        /* Add SIGNATURE */
        HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
                "Could not sign UPDATE. Failing\n");
        
        HIP_DEBUG("Sending initial UPDATE packet (reg_request)\n");
        HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(&saddr, &daddr, 0, 0,
                update_packet, entry, 0), -1, "csum_send failed\n");

out_err:
        if (update_packet)
                HIP_FREE(update_packet);
        return err;
}

