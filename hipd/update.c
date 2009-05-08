/**
 * @file
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP). This file is under
 * heavy editing currently.
 *
 * @author  Baris Boyvat <baris#boyvat.com>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#include "update.h"
#include "update_old.h"

#include "protodefs.h"

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;

int hip_receive_update_old(hip_common_t *msg, in6_addr_t *update_saddr,
		       in6_addr_t *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo)
{
	int err = 0, has_esp_info = 0, pl = 0, send_ack = 0;
	in6_addr_t *hits = NULL;
	in6_addr_t *src_ip = NULL , *dst_ip = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct hip_locator *locator = NULL;
	struct hip_echo_request *echo_request = NULL;
	struct hip_echo_response *echo_response = NULL;
	struct hip_tlv_common *encrypted = NULL;
	uint32_t spi = 0;
	struct hip_stun *stun = NULL;

	HIP_DEBUG("\n");


        /** For debugging
        hip_print_locator_addresses(msg);
        if (entry)
            hip_print_peer_addresses(entry); */

        _HIP_DEBUG_HIT("receive a stun from: ", update_saddr);

#ifdef CONFIG_HIP_RVS
        if (hip_relay_get_status() == HIP_RELAY_ON)
        {
              hip_relrec_t *rec = NULL;
              hip_relrec_t dummy;

              /* Check if we have a relay record in our database matching the
                 Responder's HIT. We should find one, if the Responder is
                 registered to relay.*/
              HIP_DEBUG_HIT("Searching relay record on HIT ", &msg->hitr);
              memcpy(&(dummy.hit_r), &msg->hitr, sizeof(msg->hitr));
              rec = hip_relht_get(&dummy);
              if (rec == NULL)
              {
                  HIP_INFO("No matching relay record found.\n");
              }
              else if (rec->type == HIP_FULLRELAY || rec->type == HIP_RVSRELAY)
              {
                   hip_relay_forward(msg, update_saddr, update_daddr, rec, sinfo, HIP_UPDATE, rec->type);
                   goto out_err;
              }
         }
     else
#endif
        /* RFC 5201: If there is no corresponding HIP association, the
	 * implementation MAY reply with an ICMP Parameter Problem. */
	if(entry == NULL) {
		HIP_ERROR("No host association database entry found.\n");
		err = -1;
		goto out_err;

	}
	/* RFC 5201: An UPDATE packet is only accepted if the state is only
	   processed in state ESTABLISHED. However, if the state machine is in
	   state R2-SENT and an UPDATE is received, the state machine should
	   move to state ESTABLISHED (see table 5 under section 4.4.2. HIP
	   State Processes). */
	else if(entry->state == HIP_STATE_R2_SENT) {
		entry->state == HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Received UPDATE in state %s, moving to "\
			  "ESTABLISHED.\n", hip_state_str(entry->state));
	} else if(entry->state != HIP_STATE_ESTABLISHED) {
		HIP_ERROR("Received UPDATE in illegal state %s.\n",
			  hip_state_str(entry->state));
		err = -EPROTO;
		goto out_err;
	}

	src_ip = update_saddr;
	dst_ip = update_daddr;
	hits = &msg->hits;

	/* RFC 5201: The UPDATE packet contains mandatory HMAC and HIP_SIGNATURE
	   parameters, and other optional parameters. The UPDATE packet contains
	   zero or one SEQ parameter. An UPDATE packet contains zero or one ACK
	   parameters. (see section 5.3.5). A single UPDATE packet may contain
	   both a sequence number and one or more acknowledgment numbers. (see
	   section 4.2).

	   Thus, we first have to verify the HMAC and HIP_SIGNATURE parameters
	   and only after successful verification, we can move to handling the
	   optional parameters. */

	/* RFC 5201: The system MUST verify the HMAC in the UPDATE packet. If
	   the verification fails, the packet MUST be dropped. */
	HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
		 "HMAC validation on UPDATE failed.\n");

	/* RFC 5201: The system MAY verify the SIGNATURE in the UPDATE packet.
	   If the verification fails, the packet SHOULD be dropped and an error
	   message logged. */
	HIP_IFEL(entry->verify(entry->peer_pub_key, msg), -1,
		 "Verification of UPDATE signature failed.\n");

	/* RFC 5201: If both ACK and SEQ parameters are present, first ACK is
	   processed, then the rest of the packet is processed as with SEQ. */
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	if (ack != NULL) {
		HIP_DEBUG("ACK parameter found with peer Update ID %u.\n",
			  ntohl(ack->peer_update_id));
		entry->hadb_update_func->hip_update_handle_ack(
			entry, ack, has_esp_info);
	}

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	if (seq != NULL) {
		HIP_DEBUG("SEQ parameter found with  Update ID %u.\n",
			  ntohl(seq->update_id));
		HIP_IFEL(hip_handle_update_seq(entry, msg), -1,
			 "Error when handling parameter SEQ.\n");
	}

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL){
		HIP_DEBUG("ESP INFO parameter found with new SPI %u.\n",
			  ntohl(esp_info->new_spi));
		has_esp_info = 1;
		HIP_IFEL(hip_handle_esp_info(msg, entry), -1,
			 "Error in processing esp_info\n");
	}

	/* RFC 5206: End-Host Mobility and Multihoming. */
	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	echo_request = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	echo_response = hip_get_param(msg, HIP_PARAM_ECHO_RESPONSE);
	if (locator != NULL) {
		HIP_DEBUG("LOCATOR parameter found.\n");
		err = entry->hadb_update_func->hip_handle_update_plain_locator(
			entry, msg, src_ip, dst_ip, esp_info, seq);
	} else {
		if (echo_request != NULL) {
			HIP_DEBUG("ECHO_REQUEST parameter found.\n");
			err = entry->hadb_update_func->hip_handle_update_addr_verify(
				entry, msg, src_ip, dst_ip);
			/* Check the peer learning case. Can you find the src_ip
			   from spi_out->peer_addr_list if the addr is not found add it
			   -- SAMU */
			if (!err) {
				hip_print_peer_addresses(entry);
				pl = hip_peer_learning(esp_info, entry, src_ip);
				/* pl left unchecked because currently we are not
				   that interested in the success of PL */
				hip_print_peer_addresses(entry);
			}
		}
		if (echo_response != NULL) {
			HIP_DEBUG("ECHO_RESPONSE parameter found.\n");
			hip_update_handle_echo_response(entry, echo_response, src_ip);
		}
	}

	encrypted = hip_get_param(msg, HIP_PARAM_ENCRYPTED);
	if (encrypted != NULL) {
		HIP_DEBUG("ENCRYPTED found\n");
		HIP_IFEL(hip_handle_encrypted(entry, encrypted), -1,
			 "Error in processing encrypted parameter\n");
		send_ack = 1;
	}

	/* Node moves within public Internet or from behind a NAT to public
	   Internet.

	   Should this be moved inside the LOCATOR parameter handling? Does node
	   movement mean that we should expect a LOCATOR parameter?
	   -Lauri 01.07.2008. */
	if(sinfo->dst_port == 0){
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);
		entry->nat_mode = 0;
		entry->peer_udp_port = 0;
		entry->hadb_xmit_func->hip_send_pkt = hip_send_raw;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	} else {
		/* Node moves from public Internet to behind a NAT, stays
		   behind the same NAT or moves from behind one NAT to behind
		   another NAT. */
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);

		if (!entry->nat_mode)
			entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;

		entry->peer_udp_port = sinfo->src_port;
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		ipv6_addr_copy(&entry->our_addr, dst_ip);
		ipv6_addr_copy(&entry->peer_addr, src_ip);
	}

	/* RFC 5203: Registration Extension
	   When there is a REG_INFO parameter present and in the parameter are
	   listed changes that affect the set of requester's services, we must
	   response with an UPDATE packet containing a REG_REQUEST parameter.

	   When there is a REG_REQUEST parameter present and in the parameter
	   are listed services that the registrar is able to provide, we must
	   response with an UPDATE packet containing a REG_RESPONSE parameter.

	   When REG_INFO or REG_REQUEST is present, we just set the send_ack
	   bit and build the response parameter in the hip_update_send_ack().
	   This may lead to acking SEQs more than once, but since the update
	   implementation is currently being revised, we settle for this
	   arrangement for now.

	   REG_RESPONSE or REG_FAILED parametes do not need any response.
	   -Lauri 01.07.2008. */
	if(hip_get_param(msg, HIP_PARAM_REG_INFO) != NULL) {
		send_ack = 1;
	} else if(hip_get_param(msg, HIP_PARAM_REG_REQUEST) != NULL) {
		send_ack = 1;
	} else {
		hip_handle_param_reg_response(entry, msg);
		hip_handle_param_reg_failed(entry, msg);
	}

	/********** ESP-PROT anchor (OPTIONAL) **********/

	/* RFC 5201: presence of a SEQ parameter indicates that the
	 * receiver MUST ACK the UPDATE
	 *
	 * should be added above in handling of SEQ, but this breaks
	 * UPDATE as it might send duplicates the way ACKs are
	 * implemented right now */
	HIP_IFEL(esp_prot_handle_update(msg, entry, src_ip, dst_ip), -1,
			"failed to handle received esp prot anchor\n");

	/************************************************/

	if(send_ack) {
		HIP_IFEL(hip_update_send_ack(entry, msg, src_ip, dst_ip), -1,
			 "Error sending UPDATE ACK.\n");
	}

 out_err:
	if (err != 0)
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);

	if (entry != NULL) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}

	//empty the oppipdb
	empty_oppipdb();

        /** For debugging
        if (entry)
            hip_print_peer_addresses(entry); */

	return err;
}

void hip_create_locators(struct hip_locator_addr_item *locators)
{
    int err = 0;
    struct hip_locator *loc;
    struct hip_common locator_msg;

    hip_msg_init(&locator_msg);
    HIP_IFEL(hip_build_locators_old(&locator_msg, 0), -1,
             "Failed to build locators\n");
    HIP_IFEL(hip_build_user_hdr(&locator_msg,
                                SO_HIP_SET_LOCATOR_ON, 0), -1,
             "Failed to add user header\n");
    loc = hip_get_param(&locator_msg, HIP_PARAM_LOCATOR);
    hip_print_locator_addresses(&locator_msg);
    locators = hip_get_locator_first_addr_item(loc);

 out_err:
    return;
}

void hip_create_update_msg(struct hip_hadb_state *entry,
        hip_common_t *update_packet, struct hip_locator_addr_item *locators)
{
    int err = 0;
    uint32_t update_id_out = 0;
    uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
    uint16_t mask = 0;

    HIP_DEBUG("creating the UPDATE packet");

    entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
                                                 mask, &entry->hit_our,
						     &entry->hit_peer);

    // Build locators
    HIP_DEBUG("locators = 0x%p locator_count = %d\n", locators, address_count);
    err = hip_build_param_locator(update_packet, locators, address_count);

    // Handle SPI numbers
    esp_info_old_spi  = hip_hadb_get_spi(entry, -1);
    esp_info_new_spi = esp_info_old_spi;

    HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
        esp_info_old_spi, esp_info_new_spi);

    HIP_IFEL(hip_build_param_esp_info(update_packet, entry->current_keymat_index,
        esp_info_old_spi, esp_info_new_spi),
	-1, "Building of ESP_INFO param failed\n");

    // TODO check the following function!
    hip_update_set_new_spi_in(entry, esp_info_old_spi,
        esp_info_new_spi, 0);

    /*************** SEQ (OPTIONAL) ***************/
    entry->update_id_out++;
    update_id_out = entry->update_id_out;
    _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
    /** @todo Handle this case. */
    HIP_IFEL(!update_id_out, -EINVAL,
        "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
    HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1,
      "Building of SEQ param failed\n");

    /* remember the update id of this update */
    hip_update_set_status(entry, esp_info_old_spi,
        0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
        entry->current_keymat_index);

    // Add HMAC
    HIP_IFEL(hip_build_param_hmac_contents(update_packet,
        &entry->hip_hmac_out), -1,
	"Building of HMAC failed\n");

    // Add SIGNATURE
    HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
        "Could not sign UPDATE. Failing\n");

out_err:
    return;
}

/*int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags,
		    int is_add, struct sockaddr* addr)*/
void hip_send_update_pkt(struct hip_hadb_state *entry, struct in6_addr_t *src_addr,
        struct in6_addr_t *dst_addr, struct hip_locator_addr_item *locators)
{
    int err = 0;
    hip_common_t update_packet;

    // Anchor update or plain (base draft update?)

    hip_create_update_msg(entry, &update_packet, locators);

    // TODO: set the local address unverified for that dst_hit();

    // or should we queue the message here?
    err = entry->hadb_xmit_func->
        hip_send_pkt(src_addr, dst_addr,
            (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
	    entry->peer_udp_port, &update_packet, entry, 1);
}

void hip_send_update_to_one_peer(struct hip_hadb_state *entry,
    struct hip_locator_addr_item *locators)
{
    if (hip_shotgun_status == SO_HIP_SHOTGUN_OFF)
    {
        HIP_DEBUG_IN6ADDR("ha local addr", &entry->our_addr);
        HIP_DEBUG_IN6ADDR("ha peer addr", &entry->peer_addr);

        hip_send_update_pkt(entry, &entry->our_addr, &entry->peer_addr, locators);
    }
    // TODO
    /*else
    {
        for go through all local addressses
        {
            for go through all peer addresses
            {
                if (check_if_address_peer_ok)
                    send_update_pkt()
            }
        }
    }*/

}
void hip_send_update()
{
    struct hip_locator_addr_item *locators;
    int i = 0;
    hip_ha_t *entry;
    hip_list_t *item, *tmp;
    
    hip_create_locators(locators);
    
    // Go through all the peers and send update packets
    list_for_each_safe(item, tmp, hadb_hit, i)
    {
        entry = list_entry(item);
        
        if (entry->hastate == HIP_HASTATE_HITOK &&
	    entry->state == HIP_STATE_ESTABLISHED) 
        {
            hip_send_update_to_one_peer(entry, locators);
        }
    }
}

/*int hip_receive_update_old(hip_common_t *msg, in6_addr_t *update_saddr,
		       in6_addr_t *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo);*/
int hip_receive_update(msg, src_addr, dst_addr, entry)
{
    /*if (!make_sanity_checks())
        exit;
    
    if (echo_request)
    {
        send_echo_response();
        return;
    }
            
    if (echo_response)
    {
        set_address_verified();

        // check the sequence
        if_same_update_seq_not_already_processed()
            set_peer_preferred_address(dst_addr); //< SA creation can be in that function
    }*/
}

void hip_send_update_all_old(struct hip_locator_info_addr_item *addr_list,
			 int addr_count, int ifindex, int flags, int is_add,
			 struct sockaddr *addr)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;
	struct sockaddr_in * p = NULL;
	struct sockaddr_in6 addr_sin6;
	struct in_addr ipv4;
	struct in6_addr ipv6;

	HIP_DEBUG_SOCKADDR("addr", addr);

	if (hip_get_nsupdate_status())
		nsupdate(0);

	/** @todo check UPDATE also with radvd (i.e. same address is added
	    twice). */

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_DEBUG("test: returning, ifindex=0 (fix this for non-mm "\
			  "UPDATE)\n");
		return;
	}

	if (addr->sa_family == AF_INET)
		HIP_DEBUG_LSI("Addr", hip_cast_sa_addr(addr));
	else if (addr->sa_family == AF_INET6)
		HIP_DEBUG_HIT("Addr", hip_cast_sa_addr(addr));
	else
		HIP_DEBUG("Unknown addr family in addr\n");

	if (addr->sa_family == AF_INET) {
		memset(&addr_sin6, 0, sizeof(struct sockaddr_in6));
		memset(&ipv4, 0, sizeof(struct in_addr));
		memset(&ipv6, 0, sizeof(struct in6_addr));
		p = (struct sockaddr_in *)addr;
		memcpy(&ipv4, &p->sin_addr, sizeof(struct in_addr));
		IPV4_TO_IPV6_MAP(&ipv4, &ipv6);
		memcpy(&addr_sin6.sin6_addr, &ipv6, sizeof(struct in6_addr));
		addr_sin6.sin6_family = AF_INET6;
	} else if (addr->sa_family == AF_INET6) {
		memcpy(&addr_sin6, addr, sizeof(addr_sin6));
	} else {
		HIP_ERROR("Bad address family %d\n", addr->sa_family);
		return;
	}

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;
	/* AB: rk.length = 100 rk is NULL next line populates rk with all valid
	   ha entries */
	HIP_IFEL(hip_for_each_ha(hip_update_get_all_valid_old, &rk), 0,
		 "for_each_ha err.\n");
	for (i = 0; i < rk.count; i++) {
		if (rk.array[i] != NULL) {
                        // in6_addr_t *local_addr = &((rk.array[i])->our_addr);

#if 0
			if (is_add && !ipv6_addr_cmp(local_addr, &zero_addr)) {
				HIP_DEBUG("Zero addresses, adding new default\n");
				ipv6_addr_copy(local_addr, addr_sin6);
			}
#endif
                        HIP_DEBUG_HIT("ADDR_SIN6",&addr_sin6.sin6_addr);
			hip_send_update(rk.array[i], addr_list, addr_count,
					ifindex, flags, is_add,
					(struct sockaddr *) &addr_sin6);

#if 0
			if (!is_add && addr_count == 0) {
				HIP_DEBUG("Deleting last address\n");
				memset(local_addr, 0, sizeof(in6_addr_t));
			}
#endif
			hip_hadb_put_entry(rk.array[i]);
		}
	}

	//empty the oppipdb
	empty_oppipdb();

 out_err:

	return;
}

int hip_send_update_old(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags,
		    int is_add, struct sockaddr* addr)
{
	int err = 0, make_new_sa = 0, add_locator;
	int was_bex_addr = -1;
	int i = 0;
	uint32_t update_id_out = 0;
	uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	uint32_t new_spi_in = 0, old_spi;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	hip_list_t *tmp_li = NULL, *item = NULL;
	hip_common_t *update_packet = NULL;
	in6_addr_t zero_addr = IN6ADDR_ANY_INIT;
	in6_addr_t saddr = { 0 }, daddr = { 0 };
	struct netdev_address *n;
	struct hip_own_addr_list_item *own_address_item, *tmp;
	int anchor_update = 0;
	struct hip_spi_out_item *spi_out = NULL;

	HIP_DEBUG("\n");

	HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);

	HIP_IFEL(entry->is_loopback, 0, "Skipping loopback\n");

	// used to distinguish anchor-update from other message types
	anchor_update = flags & SEND_UPDATE_ESP_ANCHOR;

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
		/* mm stuff, per-ifindex SA
		   reuse old SA if we have one, else create a new SA.
		   miika: changing of spi is not supported, see bug id 434 */
		/* mapped_spi = hip_hadb_get_spi(entry, ifindex); */
		mapped_spi = hip_hadb_get_spi(entry, -1);
		HIP_DEBUG("mapped_spi=0x%x\n", mapped_spi);
		if (mapped_spi) {
			make_new_sa = 0;
			HIP_DEBUG("Mobility with single SA pair, readdress with no "\
				  "rekeying\n");
			HIP_DEBUG("Reusing old SA\n");
			/* Mobility with single SA pair */
		} else {
			HIP_DEBUG("Host multihoming\n");
			make_new_sa = 1;
			_HIP_DEBUG("TODO\n");
		}
	} else {
		/* base draft UPDATE, create a new SA anyway */
		_HIP_DEBUG("base draft UPDATE, create a new SA\n");

		// we reuse the old spi for the ANCHOR update
		mapped_spi = hip_hadb_get_spi(entry, -1);
	}

	/* If this is mm-UPDATE (ifindex should be then != 0) avoid
	   sending empty LOCATORs to the peer if we have not sent previous
	   information on this ifindex/SPI yet */
	if (ifindex != 0 && mapped_spi == 0 && addr_count == 0) {
		HIP_DEBUG("NETDEV_DOWN and ifindex not advertised yet, returning\n");
		goto out;
	}

	HIP_DEBUG("make_new_sa=%d\n", make_new_sa);

	if (make_new_sa) {
		HIP_IFEL(!(new_spi_in = entry->hadb_ipsec_func->hip_acquire_spi(&entry->hit_peer,
							&entry->hit_our)),
			 -1, "Error while acquiring a SPI\n");
		HIP_DEBUG("Got SPI value for the SA 0x%x\n", new_spi_in);

		/** @todo move to rekeying_finish */
		if (!mapped_spi) {
			struct hip_spi_in_item spi_in_data;

			_HIP_DEBUG("previously unknown ifindex, creating a new item "\
				   "to inbound spis_in\n");
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
			/* mm Host multihoming. Currently simultaneous SAs are not
			   supported. Neither is changing of SPI (see bug id 434) */
			esp_info_old_spi = old_spi;
			esp_info_new_spi = old_spi; // new_spi_in;
			HIP_DEBUG("Multihoming, new SA: old=%x new=%x\n",
				  esp_info_old_spi, esp_info_new_spi);
		} else {
			HIP_DEBUG("Reusing old SPI\n");
			esp_info_old_spi = mapped_spi;
			esp_info_new_spi = mapped_spi;
		}
	//} else /* hack to prevent sending of ESP-update when only ANCHOR-update */
	} else if (!anchor_update)
	{
		HIP_DEBUG("adding ESP_INFO, Old SPI <> New SPI\n");
		/* plain UPDATE or readdress with rekeying */
		/* update the SA of the interface which caused the event */
		HIP_IFEL(!(esp_info_old_spi =
			   hip_hadb_get_spi(entry, ifindex)), -1,
			 "Could not find SPI to use in Old SPI\n");
		/* here or later ? */
		hip_set_spi_update_status(entry, esp_info_old_spi, 1);
		//esp_info_new_spi = new_spi_in; /* see bug id 434 */
		esp_info_new_spi = esp_info_old_spi;
	} else
	{
		HIP_DEBUG("Reusing old SPI\n");
		esp_info_old_spi = mapped_spi;
		esp_info_new_spi = mapped_spi;
	}

	/* this if is another hack to make sure we don't send ESP-update
	 * when we only want a pure ANCHOR-update */
	if (addr != NULL)
	{
		/* if del then we have to remove SAs for that address */
		was_bex_addr = ipv6_addr_cmp(hip_cast_sa_addr(addr),
						 &entry->our_addr);
	}

	/* Some address was added and BEX address is nulled */
	if (is_add && !ipv6_addr_cmp(&entry->our_addr, &zero_addr))
	{
		ipv6_addr_copy(&entry->our_addr, hip_cast_sa_addr(addr));
		err = hip_update_src_address_list(entry, addr_list, &daddr,
						  addr_count, esp_info_new_spi,
						  is_add, addr);
		if(err == GOTO_OUT)
			goto out;
		else if(err)
			goto out_err;

		HIP_IFEL(err = hip_update_preferred_address(
				 entry, hip_cast_sa_addr(addr),
				 &entry->peer_addr, &esp_info_new_spi), -1,
			 "Updating peer preferred address failed\n");
	}

	if (!is_add && (was_bex_addr == 0)) {
		HIP_DEBUG("Netlink event was del, removing SAs for the address for "\
			  "this entry\n");
		default_ipsec_func_set.hip_delete_sa(esp_info_old_spi, hip_cast_sa_addr(addr),
			      &entry->peer_addr, AF_INET6,
			      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      (int)entry->peer_udp_port);
		default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &entry->peer_addr,
			      hip_cast_sa_addr(addr), AF_INET6,
			      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      (int)entry->peer_udp_port);

		/* and we have to do it before this changes the local_address */
		err = hip_update_src_address_list(entry, addr_list, &daddr,
						  addr_count, esp_info_old_spi,
						  is_add, addr);
 		if(err == GOTO_OUT)
			goto out;
		else if(err)
			goto out_err;
	}

	if (!anchor_update)
	{
		/* Send UPDATE(ESP_INFO, LOCATOR, SEQ) */
		HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
			  esp_info_old_spi, esp_info_new_spi);
		HIP_IFEL(hip_build_param_esp_info(
				 update_packet, entry->current_keymat_index,
				 esp_info_old_spi, esp_info_new_spi),
			 -1, "Building of ESP_INFO param failed\n");

		if (add_locator)
		{
			err = hip_build_param_locator(update_packet, addr_list,
							  addr_count);
		  HIP_IFEL(err, err, "Building of LOCATOR param failed\n");
		} else
		  HIP_DEBUG("not adding LOCATOR\n");

		 hip_update_set_new_spi_in(entry, esp_info_old_spi,
					   esp_info_new_spi, 0);
	}

	/*************** SEQ (OPTIONAL) ***************/

     entry->update_id_out++;
     update_id_out = entry->update_id_out;
     _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
     /** @todo Handle this case. */
     HIP_IFEL(!update_id_out, -EINVAL,
	      "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
     HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1,
	      "Building of SEQ param failed\n");

     /* remember the update id of this update */
     hip_update_set_status(entry, esp_info_old_spi,
			   0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
			   entry->current_keymat_index);

     /********** ESP-PROT anchor (OPTIONAL) **********/

     /* @note params mandatory for this UPDATE type are the generally mandatory
      *       params HMAC and HIP_SIGNATURE as well as this ESP_PROT_ANCHOR and
      *       the SEQ in the signed part of the message
      * @note SEQ has to be set in the message before calling this function. It
      * 	  is the hook saying if we should add the anchors or not
      * @note the received acknowledgement should trigger an add_sa where
      * 	  update = 1 and direction = OUTBOUND
      * @note combination with other UPDATE types is possible */
	 HIP_IFEL(esp_prot_update_add_anchor(update_packet, entry), -1,
			 "failed to add esp prot anchor\n");

     /************************************************/

     /* Add HMAC */
     HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					    &entry->hip_hmac_out), -1,
	      "Building of HMAC failed\n");


	 /* Add SIGNATURE */
	 HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
		  "Could not sign UPDATE. Failing\n");

     /* Send UPDATE */
     hip_set_spi_update_status(entry, esp_info_old_spi, 1);


     /* before sending check if the AFs match and do something about it
	so it doesn't fail in raw send */

     /* If it was add and the address_count was larger than one
	we presumably have the bex address so why change src_addr :)

	One reason to do it is the following:
	BEX over ipv4.
	HO to other IF.
	rtm del addr to ipv4 and ipv6 address we got.
	rtm new addr to ipv6 addr which gets to be the src addr and first update
	fails because we do not know peers ipv6 addr.
	rtm new addr to ipv4 addr
	This is not added now

	Now if add and address_count > 1 it should check first
	if there is same address family in peer_addr_list
	if there is no addresses that belong to same af change the src addr
     */

     if (is_add && (address_count > 1)) {
	     hip_list_t *itemj = NULL, *tmpj = NULL, *item_outerj = NULL,
                     *tmp_outerj = NULL;
             struct hip_peer_addr_list_item *addr_lij;
             struct hip_spi_out_item *spi_outj;
             int ij = 0, iij = 0;
	     HIP_DEBUG("is add and address count > 1\n");
             list_for_each_safe(item_outerj, tmp_outerj, entry->spis_out, ij) {
                     spi_outj = list_entry(item_outerj);
                     iij = 0;
                     tmpj = NULL;
                     itemj = NULL;
                     list_for_each_safe(itemj, tmpj, spi_outj->peer_addr_list, iij) {
                             addr_lij = list_entry(itemj);
                             HIP_DEBUG_HIT("SPI out addresses", &addr_lij->address);
                             if (IN6_IS_ADDR_V4MAPPED(&addr_lij->address) ==
                                 IN6_IS_ADDR_V4MAPPED(&saddr) &&
				 (ipv6_addr_is_teredo(&addr_lij->address) ==
				  ipv6_addr_is_teredo(&saddr))) {
                                     HIP_DEBUG("Found matching addr\n");
 				     goto skip_src_addr_change;
                             }
                     }
             }
     }

     if(IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
	== IN6_IS_ADDR_V4MAPPED(&daddr)) {
	     HIP_DEBUG_IN6ADDR("saddr", &saddr);
	     HIP_DEBUG_IN6ADDR("daddr", &daddr);
	     HIP_DEBUG("Same address family\n");
	     memcpy(&saddr, &entry->our_addr, sizeof(saddr));
     } else {
	  HIP_DEBUG("Different address family\n");
	  list_for_each_safe(item, tmp_li, addresses, i) {
	       n = list_entry(item);
	       if (IN6_IS_ADDR_V4MAPPED(&daddr) ==
		   hip_sockaddr_is_v6_mapped(&n->addr)) {
		    HIP_DEBUG_IN6ADDR("chose address", hip_cast_sa_addr(&n->addr));
                    memcpy(&saddr, hip_cast_sa_addr(&n->addr), sizeof(saddr));
                    ipv6_addr_copy(&entry->our_addr, &saddr);
                    break;
	       }
	  }
     }

skip_src_addr_change:

     /* needs to check also that if entry->our_addr differed from
        entry->peer_addr. This because of case where CN has 4 and 6 addrs
        and MN has initially 4 and it does a hard handover 6. This results into
        mismatch of addresses that possibly could be fixed by checking the peer_addr_list
        SEE ALSO BZ ID 458 */
     if (IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
         != IN6_IS_ADDR_V4MAPPED(&entry->peer_addr)) {
             hip_list_t *item = NULL, *tmp = NULL, *item_outer = NULL,
                     *tmp_outer = NULL;
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
                             HIP_DEBUG_HIT("SPI out addresses", &addr_li->address);
                             if (IN6_IS_ADDR_V4MAPPED(&addr_li->address) ==
                                 IN6_IS_ADDR_V4MAPPED(&entry->our_addr) &&
				 (ipv6_addr_is_teredo(&addr_li->address) ==
				  ipv6_addr_is_teredo(&entry->our_addr))) {
                                     HIP_DEBUG("Found matching addr\n");
                                     ipv6_addr_copy(&daddr, &addr_li->address);
                                     ipv6_addr_copy(&entry->peer_addr,
                                                    &addr_li->address);
                                     /** @todo Or just break? Fix later. */
                                     goto out_of_loop;
                             }
                     }
             }
     }
 out_of_loop:

     HIP_DEBUG("Sending initial UPDATE packet.\n");
     /* guarantees retransmissions */
     entry->update_state = HIP_UPDATE_STATE_REKEYING;

     HIP_DEBUG_IN6ADDR("ha local addr", &entry->our_addr);
     HIP_DEBUG_IN6ADDR("ha peer addr", &entry->peer_addr);
     HIP_DEBUG_IN6ADDR("saddr", &saddr);
     HIP_DEBUG_IN6ADDR("daddr", &daddr);

     if (is_add || (was_bex_addr != 0))
     {
	     saddr = entry->our_addr;
	     daddr = entry->peer_addr;
     };

     err = entry->hadb_xmit_func->
	     hip_send_pkt(&saddr, &daddr,
		    (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
		    entry->peer_udp_port, update_packet, entry, 1);

     HIP_DEBUG("Send_pkt returned %d\n", err);

     // Send update to the rendezvous server as well, if there is one available
     if (entry->rendezvous_addr)
     {
	  err = entry->hadb_xmit_func->
	       hip_send_pkt(&saddr, entry->rendezvous_addr,
			    (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			    entry->peer_udp_port, update_packet, entry, 1);

	  HIP_DEBUG("Send_pkt returned %d\n", err);
     }

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

static int hip_update_get_all_valid_old(hip_ha_t *entry, void *op)
{
	struct hip_update_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	if (entry->hastate == HIP_HASTATE_HITOK &&
	    entry->state == HIP_STATE_ESTABLISHED) {
		hip_hadb_hold_entry(entry);
		rk->array[rk->count] = entry;
		rk->count++;
	} else
		_HIP_DEBUG("skipping HA entry 0x%p (state=%s)\n",
			  entry, hip_state_str(entry->state));

	return 0;
}

