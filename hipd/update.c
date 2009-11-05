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

int update_id_window_size = 50;

int hip_create_locators(hip_common_t* locator_msg,
        struct hip_locator_info_addr_item **locators)
{
        int err = 0;
        struct hip_locator *loc;

        hip_msg_init(locator_msg);
        HIP_IFEL(hip_build_locators_old(locator_msg, 0, hip_get_nat_mode(NULL)), -1,
                 "Failed to build locators\n");
        HIP_IFEL(hip_build_user_hdr(locator_msg,
                                    SO_HIP_SET_LOCATOR_ON, 0), -1,
                 "Failed to add user header\n");
        loc = hip_get_param(locator_msg, HIP_PARAM_LOCATOR);
        hip_print_locator_addresses(locator_msg);
        *locators = hip_get_locator_first_addr_item(loc);

out_err:
        return err;
}

/// @todo : should we implement base draft update with ifindex 0 stuff ??
/// @todo :  Divide this function into more pieces, handle_spi, handle_seq, etc
/// @todo : Remove the uncommented lines?
int hip_create_update_msg(hip_common_t* received_update_packet,
        struct hip_hadb_state *ha, hip_common_t *update_packet_to_send,
        struct hip_locator_info_addr_item *locators,
        int type)
{
        int err = 0;

        uint32_t update_id_out = 0;
        uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
        uint16_t mask = 0;
      	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo_request = NULL;

        HIP_DEBUG("Creating the UPDATE packet\n");

        if (type != HIP_UPDATE_LOCATOR)
                HIP_DEBUG("UPDATE without locators\n");

        ha->hadb_misc_func->hip_build_network_hdr(update_packet_to_send, HIP_UPDATE,
                                                     mask, &ha->hit_our,
                                                         &ha->hit_peer);

        // Add ESP_INFO
        if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
                // Handle SPI numbers
                esp_info_old_spi  = ha->spi_inbound_current;
                esp_info_new_spi = ha->spi_inbound_current;

                HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
                    esp_info_old_spi, esp_info_new_spi);

                HIP_IFEL(hip_build_param_esp_info(update_packet_to_send, ha->current_keymat_index,
                    esp_info_old_spi, esp_info_new_spi),
                    -1, "Building of ESP_INFO param failed\n");
        }

        // Add LOCATOR
        if (type == HIP_UPDATE_LOCATOR) {
                HIP_DEBUG("locators = 0x%p locator_count = %d\n", locators, address_count);
                err = hip_build_param_locator(update_packet_to_send, locators, address_count);
        }

        // Add SEQ
        if (type == HIP_UPDATE_LOCATOR || type == HIP_UPDATE_ECHO_REQUEST) {
                // TODO check the following function!
                /* hip_update_set_new_spi_in_old(ha, esp_info_old_spi,
                    esp_info_new_spi, 0);*/

                ha->update_id_out++;
                update_id_out = ha->update_id_out;
                _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
                /** @todo Handle this case. */
                HIP_IFEL(hip_build_param_seq(update_packet_to_send, update_id_out), -1,
                  "Building of SEQ param failed\n");

                /* remember the update id of this update */
                /* hip_update_set_status(ha, esp_info_old_spi,
                    0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
                    ha->current_keymat_index); */

                /************************************************/
        }

        // Add ACK
        if (type == HIP_UPDATE_ECHO_REQUEST || type == HIP_UPDATE_ECHO_RESPONSE) {
                HIP_IFEL(!(seq = hip_get_param(received_update_packet,
                    HIP_PARAM_SEQ)), -1, "SEQ not found\n");

                HIP_IFEL(hip_build_param_ack(update_packet_to_send,
                    ntohl(seq->update_id)), -1, "Building of ACK failed\n");
        }

        // Add HMAC
        HIP_IFEL(hip_build_param_hmac_contents(update_packet_to_send,
                &ha->hip_hmac_out), -1, "Building of HMAC failed\n");

        // Add SIGNATURE
        HIP_IFEL(ha->sign(ha->our_priv_key, update_packet_to_send), -EINVAL,
                "Could not sign UPDATE. Failing\n");

       	/* Add ECHO_REQUEST (no signature)
         * Notice that ECHO_REQUEST is same for the identical UPDATE packets
         * sent between different address combinations.
         */
        if (type == HIP_UPDATE_ECHO_REQUEST) {
                HIP_HEXDUMP("ECHO_REQUEST in the host association",
                        ha->echo_data, sizeof(ha->echo_data));
                HIP_IFEBL2(hip_build_param_echo(update_packet_to_send, ha->echo_data,
			sizeof(ha->echo_data), 0, 1),
                        -1, return , "Building of ECHO_REQUEST failed\n");
        }

        /* Add ECHO_RESPONSE (no signature) */
        if (type == HIP_UPDATE_ECHO_RESPONSE) {
              	echo_request = hip_get_param(received_update_packet,
                        HIP_PARAM_ECHO_REQUEST);
                HIP_IFEL(!echo_request, -1, "ECHO REQUEST not found!\n");

		HIP_DEBUG("echo opaque data len=%d\n",
			  hip_get_param_contents_len(echo_request));
		HIP_HEXDUMP("ECHO_REQUEST ",
			    (void *)echo_request +
			    sizeof(struct hip_tlv_common),
			    hip_get_param_contents_len(echo_request));
		HIP_IFEL(hip_build_param_echo(update_packet_to_send, (void *) echo_request +
                        sizeof(struct hip_tlv_common),
                        hip_get_param_contents_len(echo_request), 0, 0),
			-1, "Building of ECHO_RESPONSE failed\n");
	}

out_err:
        return err;
}

/*int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags,
		    int is_add, struct sockaddr* addr)*/
void hip_send_update_pkt(hip_common_t* update_packet_to_send, 
        struct hip_hadb_state *ha, struct in6_addr *src_addr,
        struct in6_addr *dst_addr)
{
        int err = 0;

        // TODO: set the local address unverified for that dst_hit();

        err = ha->hadb_xmit_func->
            hip_send_pkt(src_addr, dst_addr,
                    (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                    ha->peer_udp_port, update_packet_to_send, ha, 1);

out_err:
        return;
}

int recreate_security_associations(struct hip_hadb_state *ha, in6_addr_t *src_addr,
        in6_addr_t *dst_addr)
{
        int err = 0;
        int prev_spi_out = ha->spi_outbound_current;
        int new_spi_out = ha->spi_outbound_new;
        
        int prev_spi_in = ha->spi_inbound_current;
        int new_spi_in = ha->spi_inbound_current;

        // Delete previous security policies
        ha->hadb_ipsec_func->hip_delete_hit_sp_pair(&ha->hit_our, &ha->hit_peer,
                IPPROTO_ESP, 1);
        ha->hadb_ipsec_func->hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our,
                IPPROTO_ESP, 1);

        // Delete the previous SAs
        HIP_DEBUG("Previous SPI out =0x%x\n", prev_spi_out);
        HIP_DEBUG("Previous SPI in =0x%x\n", prev_spi_in);

        HIP_DEBUG_IN6ADDR("Our current active addr", &ha->our_addr);
        HIP_DEBUG_IN6ADDR("Peer's current active addr", &ha->peer_addr);

        default_ipsec_func_set.hip_delete_sa(prev_spi_out, &ha->peer_addr,
					     &ha->our_addr, HIP_SPI_DIRECTION_OUT, ha);
	default_ipsec_func_set.hip_delete_sa(prev_spi_in, &ha->our_addr,
					     &ha->peer_addr, HIP_SPI_DIRECTION_IN, ha);

        // Create a new security policy
        HIP_IFEL(ha->hadb_ipsec_func->hip_setup_hit_sp_pair(&ha->hit_our,
                &ha->hit_peer, src_addr, dst_addr, IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

        // Create a new inbound SA
        HIP_DEBUG("Creating a new inbound SA, SPI=0x%x\n", new_spi_in);

        HIP_IFEL(ha->hadb_ipsec_func->hip_add_sa(dst_addr, src_addr,
                &ha->hit_peer, &ha->hit_our, new_spi_in, ha->esp_transform,
                &ha->esp_in, &ha->auth_in, 1, HIP_SPI_DIRECTION_IN, 0,
                ha), -1,
	      "Error while changing inbound security association\n");

	HIP_DEBUG("New inbound SA created with SPI=0x%x\n", new_spi_in);

        /*HIP_IFEL(ha->hadb_ipsec_func->hip_setup_hit_sp_pair(&ha->hit_peer,
                &ha->hit_our, dst_addr, src_addr, IPPROTO_ESP, 1, 0),
	      -1, "Setting up SP pair failed\n");*/

        // Create a new outbound SA
        HIP_DEBUG("Creating a new outbound SA, SPI=0x%x\n", new_spi_out);
	ha->local_udp_port = ha->nat_mode ? hip_get_local_nat_udp_port() : 0;

      	HIP_IFEL(ha->hadb_ipsec_func->hip_add_sa(src_addr, dst_addr,
                &ha->hit_our, &ha->hit_peer, new_spi_out, ha->esp_transform,
                &ha->esp_out, &ha->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0,
                ha), -1,
	      "Error while changing outbound security association\n");

	HIP_DEBUG("New outbound SA created with SPI=0x%x\n", new_spi_out);
        
out_err:
        return err;
};

// Locators should be sent to the whole verified addresses!!!
int hip_send_update_to_one_peer(hip_common_t* received_update_packet,
        struct hip_hadb_state *ha, struct in6_addr *src_addr,
        struct in6_addr *dst_addr, struct hip_locator_info_addr_item *locators,
        int type)
{
        int err = 0;
        hip_list_t *item = NULL, *tmp = NULL;
	int i = 0;
        hip_common_t* update_packet_to_send = NULL;

        HIP_IFEL(!(update_packet_to_send = hip_msg_alloc()), -ENOMEM,
                "Out of memory while allocation memory for the update packet\n");
        err = hip_create_update_msg(received_update_packet, ha, update_packet_to_send,
                locators, type);
        if (err)
            goto out_err;

        if (hip_shotgun_status == SO_HIP_SHOTGUN_OFF)
        {
                switch (type) {
                case HIP_UPDATE_LOCATOR:
                case HIP_UPDATE_ECHO_RESPONSE:
                        HIP_DEBUG_IN6ADDR("Sending update from", src_addr);
                        HIP_DEBUG_IN6ADDR("to", dst_addr);

                        hip_send_update_pkt(update_packet_to_send, ha, src_addr,
                                dst_addr);

                        break;
                case HIP_UPDATE_ECHO_REQUEST:
                        list_for_each_safe(item, tmp, ha->addresses_to_send_echo_request, i) {
                                dst_addr = list_entry(item);

                                _HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                                _HIP_DEBUG_IN6ADDR("to", dst_addr);

                                if (!are_addresses_compatible(src_addr, dst_addr))
                                        continue;

                                HIP_DEBUG_IN6ADDR("Sending echo requests from", src_addr);
                                HIP_DEBUG_IN6ADDR("to", dst_addr);

                                hip_send_update_pkt(update_packet_to_send, ha,
                                        src_addr, dst_addr);
                        }

                        break;
                }
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

out_err:
        if (update_packet_to_send)
                free(update_packet_to_send);
}

int hip_send_update_locator()
{
        int err = 0;
        struct hip_locator_info_addr_item *locators;
        int i = 0;
        hip_ha_t *ha;
        hip_list_t *item, *tmp;
        hip_common_t *locator_msg;

        HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
            "Out of memory while allocation memory for the packet\n");
        HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

        // Go through all the peers and send update packets
        list_for_each_safe(item, tmp, hadb_hit, i)
        {
                ha = list_entry(item);

                if (ha->hastate == HIP_HASTATE_HITOK &&
                    ha->state == HIP_STATE_ESTABLISHED)
                {
                        err = hip_send_update_to_one_peer(NULL, ha, &ha->our_addr,
                                &ha->peer_addr, locators, HIP_UPDATE_LOCATOR);
                        if (err)
                            goto out_err;
                }
        }

out_err:
        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON)
            hip_recreate_all_precreated_r1_packets();
        if (locator_msg)
            free(locator_msg);
}

int hip_check_hmac_and_signature(hip_common_t* msg, hip_ha_t *entry)
{
        int err = 0;

        /** @todo Check these references again because these checks are done
         * separately for ACKs and SEQs.

        /* RFC 5201 Section 6.12.1. Handling a SEQ Parameter in a Received
         *  UPDATE Message:
         * 3. The system MUST verify the HMAC in the UPDATE packet. If
         * the verification fails, the packet MUST be dropped. */
        HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
                 "HMAC validation on UPDATE failed.\n");

        /* RFC 5201 Section 6.12.1. Handling a SEQ Parameter in a Received
         *  UPDATE Message:
         * 4. The system MAY verify the SIGNATURE in the UPDATE packet.
         * If the verification fails, the packet SHOULD be dropped and an error
         * message logged. */
        HIP_IFEL(entry->verify(entry->peer_pub_key, msg), -1,
                 "Verification of UPDATE signature failed.\n");

     out_err:
        return err;
}

int hip_is_preferred_peer_addr_in_locators_obselete(hip_ha_t *ha,
        struct hip_locator *locator)
{
        int ret = 0;
    
        struct hip_peer_addr_list_item *list_item;

        list_item = malloc(sizeof(struct hip_peer_addr_list_item));
	if (!list_item)
        {
                HIP_ERROR("Couldn't allocate memory for list_item (type "
                        "hip_peer_addr_list_item)\n");
                return -1;
        }

	ipv6_addr_copy(&list_item->address, &ha->peer_addr);
	HIP_DEBUG_HIT("Checking if preferred address was in locator",
		      &list_item->address);
        
	ret = hip_update_locator_contains_item_old(locator, list_item);
        if (list_item)
		HIP_FREE(list_item);
        
        return ret;
        
}

int hip_handle_locator_parameter(hip_ha_t *ha, in6_addr_t *src_addr,
        struct hip_locator *locator)
{
        int err = 0;
        int locator_addr_count = 0;
        int i = 0;
        u32 spi_in = 0;
        struct hip_peer_addr_list_item *locator_address_item;
        union hip_locator_info_addr *locator_info_addr;
        struct in6_addr *peer_addr = 0;
        int preferred_addr_not_in = 1;

        HIP_IFEL(!locator, -1, "locator is NULL");

      	locator_addr_count = hip_get_locator_addr_item_count(locator);
	HIP_IFEL((locator_addr_count < 0), -1, "Negative address count\n");

	HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
		  locator_addr_count, hip_get_param_total_len(locator));

        _HIP_DEBUG("The previous addresses to send update request:\n");
        // hip_print_addresses_to_send_update_request(ha);

        // Empty the addresses_to_send_echo_request list before adding the
        // new addresses
        hip_remove_addresses_to_send_echo_request(ha);

        locator_address_item = hip_get_locator_first_addr_item(locator);
	for (i = 0; i < locator_addr_count; i++)
        {
                locator_info_addr = hip_get_locator_item(locator_address_item, i);
         
                peer_addr = malloc(sizeof(in6_addr_t));
                if (!peer_addr)
                {
                        HIP_ERROR("Couldn't allocate memory for peer_addr.\n");
                        return -1;
                };

                memcpy(peer_addr, hip_get_locator_item_address(locator_info_addr),
                    sizeof(in6_addr_t));
                list_add(peer_addr, ha->addresses_to_send_echo_request);

                HIP_DEBUG_IN6ADDR("Comparing", peer_addr);
                HIP_DEBUG_IN6ADDR("to ", &ha->peer_addr);

                if (!ipv6_addr_cmp(peer_addr, &ha->peer_addr))
                        preferred_addr_not_in = 0;
        }

        hip_print_addresses_to_send_update_request(ha);

	if (preferred_addr_not_in)
        {
                HIP_DEBUG("Preferred address was not in locator, Handle"
                        "specially this case if needed!");
        }

out_err:
        return err;
}

/*int hip_handle_spi_out_oldish(hip_ha_t *ha, struct hip_esp_info *esp_info,
        struct hip_locator *locator, struct hip_seq *seq)
{
        int err = 0;

        u32 spi_out = ntohl(esp_info->new_spi);

        if (!hip_hadb_get_spi_list(ha, spi_out))
        {
                struct hip_spi_out_item spi_out_data;

                HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
                memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
                spi_out_data.spi = spi_out;
                spi_out_data.seq_update_id = ntohl(seq->update_id);
                HIP_IFE(hip_hadb_add_spi(ha, HIP_SPI_DIRECTION_OUT,
                                         &spi_out_data), -1);
                HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created "\
                          "yet)\n", spi_out);
        }

out_err:
        return err;
}*/

/*int hip_handle_locator_parameter(hip_ha_t *entry,
		struct hip_locator *loc,
		struct hip_esp_info *esp_info) {
	uint32_t old_spi = 0, new_spi = 0, i, err = 0;
	int zero = 0, n_addrs = 0, ii = 0;
	int same_af = 0, local_af = 0, comp_af = 0, tmp_af = 0;
	hip_list_t *item = NULL, *tmplist = NULL;
	struct hip_locator_info_addr_item *locator_address_item;
	struct hip_locator_info_addr_item2 *locator_address_item2;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *a, *tmp, addr;
	struct netdev_address *n;
	struct hip_locator *locator = NULL;

	if ((locator = loc) == NULL) {
		HIP_DEBUG("No locator as input\n");
		locator = entry->locator;
                HIP_DEBUG("Using entry->locator\n");
	}

	HIP_INFO_LOCATOR("in handle locator", locator);

	HIP_IFEL(!locator, -1, "No locator to handle\n");

	old_spi = ntohl(esp_info->new_spi);
	new_spi = ntohl(esp_info->new_spi);
	HIP_DEBUG("LOCATOR SPI old=0x%x new=0x%x\n", old_spi, new_spi);

	/* If following does not exit, its a bug: outbound SPI must have been
	already created by the corresponding ESP_INFO in the same UPDATE
	packet */
/*	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, new_spi)), -1,
			"Bug: outbound SPI 0x%x does not exist\n", new_spi);

	/* Set all peer addresses to unpreferred */

	/** @todo Compiler warning; warning: passing argument 1 of
	 * 'hip_update_for_each_peer_addr' from incompatible pointer type.
	 *  What is the real point with this one anyway?
	 */

#if 0
	HIP_IFE(hip_update_for_each_peer_addr(hip_update_set_preferred,
				   entry, spi_out, &zero), -1);
#endif
/*	if(locator)
		HIP_IFEL(hip_update_for_each_peer_addr(hip_update_deprecate_unlisted,
					 entry, spi_out, locator), -1,
					 "Depracating a peer address failed\n");

	/* checking did the locator have any address with the same family as
	entry->our_addr, if not change local address to address that
	has same family as the address(es) in locator, if possible */

/*	if (! locator || hip_nat_get_control(entry) == HIP_NAT_MODE_ICE_UDP) {
		goto out_of_loop;
	}

	locator_address_item = hip_get_locator_first_addr_item(locator);
	local_af =
		IN6_IS_ADDR_V4MAPPED(&entry->our_addr) ? AF_INET :AF_INET6;
	if (local_af == 0) {
		HIP_DEBUG("Local address is invalid, skipping\n");
		goto out_err;
	}

	n_addrs = hip_get_locator_addr_item_count(locator);
	for (i = 0; i < n_addrs; i++) {
		/* check if af same as in entry->local_af */
/*		comp_af = IN6_IS_ADDR_V4MAPPED(hip_get_locator_item_address(hip_get_locator_item(locator_address_item, i)))
			? AF_INET : AF_INET6;
		if (comp_af == local_af) {
			HIP_DEBUG("LOCATOR contained same family members as "\
					"local_address\n");
			same_af = 1;

			break;
		}
	}
	if (same_af != 0) {
		HIP_DEBUG("Did not find any address of same family\n");
		goto out_of_loop;
	}

	/* look for local address with family == comp_af */
/*	list_for_each_safe(item, tmplist, addresses, ii) {
		n = list_entry(item);
		tmp_af = hip_sockaddr_is_v6_mapped(&n->addr) ?
			AF_INET : AF_INET6;
		if (tmp_af == comp_af) {
			HIP_DEBUG("LOCATOR did not contain same family members "
					"as local_address, changing our_addr and "
					"peer_addr\n");
			/* Replace the local address to match the family */
/*			memcpy(&entry->our_addr,
					hip_cast_sa_addr(&n->addr),
					sizeof(in6_addr_t));
			/* Replace the peer preferred address to match the family */
/*			locator_address_item = hip_get_locator_first_addr_item(locator);
			/* First should be OK, no opposite family in LOCATOR */

/*			memcpy(&entry->peer_addr,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			memcpy(&addr.address,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			HIP_IFEL(hip_update_peer_preferred_address(
					entry, &addr, new_spi), -1,
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
/*	if (n_addrs == 0) /* our own extension, use some other SPI */
/*		(void)hip_hadb_relookup_default_out(entry);
	/* relookup always ? */
/*#endif

/*out_err:
	return err;
}
*/

int hip_update_for_each_peer_addr_old(
	int (*func)
	(hip_ha_t *entry, struct hip_peer_addr_list_item *list_item,
	 struct hip_spi_out_item *spi_out, void *opaq),
	hip_ha_t *entry, struct hip_spi_out_item *spi_out, void *opaq)
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


#if 0
int hip_handle_locator_parameter_oldish(hip_ha_t *ha, struct hip_esp_info *esp_info,
        struct hip_locator *locator)
{
        int err = 0;
        int i = 0;
       	struct hip_locator_info_addr_item *locator_address_item;
        int is_our_preferred_addr_family_ipv4 = 0;
        int is_our_addr_family_ipv4 = 0;
        int is_peer_addr_family_ipv4 = 0;
        int locator_addr_count = 0;
        int same_addr_family = 0;
        union hip_locator_info_addr *locator_info_addr;
        struct in6_addr *peer_addr;
        struct hip_spi_out_item *spi_out;
        uint32_t old_spi = 0, new_spi = 0;
        hip_list_t *item = NULL, *tmplist = NULL;
        struct netdev_address *netdev_addr;
        struct hip_peer_addr_list_item addr;

        if (locator == NULL)
        {
                err = -1;
                HIP_ERROR("Locator parameter is empty.\n");
                goto out_err;
        }

       	old_spi = ntohl(esp_info->old_spi);
	new_spi = ntohl(esp_info->new_spi);
	HIP_DEBUG("LOCATOR SPI old=0x%x new=0x%x\n", old_spi, new_spi);

	/* If following does not exit, its a bug: outbound SPI must have been
	already created by the corresponding ESP_INFO in the same UPDATE
	packet */
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(ha, new_spi)), -1,
			"Bug: outbound SPI 0x%x does not exist\n", new_spi);

        // Deprecate all peer addresses
        HIP_IFEL(hip_update_for_each_peer_addr_old(hip_update_deprecate_unlisted,
            		 ha, spi_out, locator), -1,
			 "Deprecating a peer address failed\n");

        is_our_addr_family_ipv4 =
		IN6_IS_ADDR_V4MAPPED(&ha->our_addr) ? AF_INET :AF_INET6;

        locator_address_item = hip_get_locator_first_addr_item(locator);
	locator_addr_count = hip_get_locator_addr_item_count(locator);
        for (i = 0; i < hip_get_locator_addr_item_count(locator); i++)
        {
                locator_info_addr = hip_get_locator_item(locator_address_item, i);
                peer_addr = hip_get_locator_item_address(locator_info_addr);
                is_peer_addr_family_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr)
			? AF_INET : AF_INET6;

		if (is_peer_addr_family_ipv4 == is_our_addr_family_ipv4)
                {
			HIP_DEBUG("LOCATOR contained same family members as "\
					"local_address\n");
			same_addr_family = 1;
			break;
		}
	}

        if (same_addr_family != 0) {
		HIP_DEBUG("Did not find any address of same family\n");
		goto out_of_loop;
	}

	list_for_each_safe(item, tmplist, addresses, i) {
		netdev_addr = list_entry(item);
                is_our_addr_family_ipv4 = hip_sockaddr_is_v6_mapped(&netdev_addr->addr) ?
			AF_INET : AF_INET6;
		if (is_peer_addr_family_ipv4 == is_our_addr_family_ipv4) {
			HIP_DEBUG("Found a local address having the same family"
                                " as the peer address");
			/* Replace the local address to match the family */
			memcpy(&ha->our_addr,
					hip_cast_sa_addr(&netdev_addr->addr),
					sizeof(in6_addr_t));
			/* Replace the peer preferred address to match the family */
			locator_address_item = hip_get_locator_first_addr_item(locator);
			/* First should be OK, no opposite family in LOCATOR */

			memcpy(&ha->peer_addr,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			memcpy(&addr.address,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			HIP_IFEL(hip_update_peer_preferred_address(
					ha, &addr, new_spi), -1,
					"Setting peer preferred address failed\n");

			goto out_of_loop;
		}
	}

out_of_loop:
	if (locator) {
		HIP_IFEL(hip_for_each_locator_addr_item(hip_update_add_peer_addr_item,
						  ha, locator, &new_spi), -1,
						  "Locator handling failed\n");
        }

out_err:
        return err;
}

#endif

int hip_handle_first_update_packet(hip_common_t* received_update_packet,
        hip_ha_t *ha, in6_addr_t *src_addr)
{
        int err = 0;
        struct hip_locator *locator;
        struct hip_esp_info *esp_info;

        locator = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
        err = hip_handle_locator_parameter(ha, src_addr, locator);
        if (err)
            goto out_err;

        esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
        ha->spi_outbound_new = ntohl(esp_info->new_spi);

        // Randomize the echo response opaque data before sending ECHO_REQUESTS.
        // Notice that we're using the same opaque value for the identical
        // UPDATE packets sent between different address combinations.
        get_random_bytes(ha->echo_data, sizeof(ha->echo_data));

        err = hip_send_update_to_one_peer(received_update_packet, ha, &ha->our_addr,
                &ha->peer_addr, NULL, HIP_UPDATE_ECHO_REQUEST);
        if (err)
            goto out_err;

out_err:
        return err;
}

void hip_handle_second_update_packet(hip_common_t* received_update_packet,
        hip_ha_t *ha, in6_addr_t *src_addr, in6_addr_t *dst_addr)
{
        struct hip_esp_info *esp_info;

        hip_send_update_to_one_peer(received_update_packet, ha, src_addr,
                dst_addr, NULL, HIP_UPDATE_ECHO_RESPONSE);

        esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
        ha->spi_outbound_new = ntohl(esp_info->new_spi);
        
        recreate_security_associations(ha, src_addr, dst_addr);

        // Set active addresses
        ipv6_addr_copy(&ha->our_addr, src_addr);
      	ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

void hip_handle_third_update_packet(hip_common_t* received_update_packet, 
        hip_ha_t *ha, in6_addr_t *src_addr, in6_addr_t *dst_addr)
{
        recreate_security_associations(ha, src_addr, dst_addr);

        // Set active addresses
        ipv6_addr_copy(&ha->our_addr, src_addr);
      	ipv6_addr_copy(&ha->peer_addr, dst_addr);
}

int hip_receive_update(hip_common_t* received_update_packet, in6_addr_t *src_addr,
        in6_addr_t *dst_addr, hip_ha_t *ha, hip_portpair_t *sinfo)
{
        int err = 0;
        int ack_peer_update_id = 0;
        int seq_update_id = 0;
        int has_esp_info = 0;
       	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
        struct hip_esp_info *esp_info = NULL;
	struct hip_locator *locator = NULL;
	struct hip_echo_request *echo_request = NULL;
	struct hip_echo_response *echo_response = NULL;
        int same_seq = 0;

        /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
         * the implementation MAY reply with an ICMP Parameter Problem. */
        HIP_IFEL(!ha, -1, "No host association database entry found.\n");

        /// @todo: Relay support

        /* RFC 5201 Section 4.4.2, Table 5: According to the state processes
         * listed, the state is moved from R2_SENT to ESTABLISHED if an
         * UPDATE packet is received */
        if (ha->state == HIP_STATE_R2_SENT) {
                ha->state == HIP_STATE_ESTABLISHED;
                HIP_DEBUG("Received UPDATE in state %s, moving to "\
                          "ESTABLISHED.\n", hip_state_str(ha->state));
        } else if (ha->state != HIP_STATE_ESTABLISHED) {

                HIP_ERROR("Received UPDATE in illegal state %s.\n",
                          hip_state_str(ha->state));
                err = -EPROTO;
                goto out_err;
        }

        /* RFC 5201 Section 6.12: Receiving UPDATE Packets */
        HIP_DEBUG("previous incoming update id=%u\n", ha->update_id_in);
        HIP_DEBUG("previous outgoing update id=%u\n", ha->update_id_out);

        /* RFC 5201 Section 6.12: 3th or 4th step:
         *
         * Summary: ACK is processed before SEQ if both are present.
         *
         * 4th step: If the association is in the ESTABLISHED state and there is
         * both an ACK and SEQ in the UPDATE, the ACK is first processed as
         * described in Section 6.12.2, and then the rest of the UPDATE is
         * processed as described in Section 6.12.1 */
        ack = hip_get_param(received_update_packet, HIP_PARAM_ACK);
        if (ack != NULL) {
                ack_peer_update_id = ntohl(ack->peer_update_id);
                HIP_DEBUG("ACK parameter found with peer Update ID %u.\n",
                        ack_peer_update_id);
                /*ha->hadb_update_func->hip_update_handle_ack(
                        ha, ack, has_esp_info);*/
                if (ack_peer_update_id != ha->update_id_out) {
                        // Simplified logic of RFC 5201 6.12.2, 1st step:
                        // We drop the packet if the Update ID in the ACK
                        // parameter does not equal to the last outgoing Update ID
                        HIP_DEBUG("Update ID (%u) in the ACK parameter does not "
                                "equal to the last outgoing Update ID (%u). "
                                "Dropping the packet.\n",
                                ack_peer_update_id,
                                ha->update_id_out);
                        err = -1;
                        goto out_err;
                }
        }

        /* RFC 5201 Sections 6.12: 2nd or 4th step:
         *
         * 2nd case: If the association is in the ESTABLISHED state and the SEQ
         * (but not ACK) parameter is present, the UPDATE is processed and replied
         * to as described in Section 6.12.1. */
        seq = hip_get_param(received_update_packet, HIP_PARAM_SEQ);
        if (seq != NULL) {
                seq_update_id = ntohl(seq->update_id);
                HIP_DEBUG("SEQ parameter found with  Update ID %u.\n",
                        seq_update_id);
                
                /// @todo 15.9.2009: Handle retransmission case

                if (ha->update_id_in != 0 &&
                    (seq_update_id < ha->update_id_in ||
                    seq_update_id > ha->update_id_in + update_id_window_size)) {
                        // RFC 5201 6.12.1 part 1:
                        HIP_DEBUG("Update ID (%u) in the SEQ parameter is not "
                                "in the window of the previous Update ID (%u). "
                                "Dropping the packet.\n",
                                seq_update_id,
                                ha->update_id_in);

                        err = -1;
                        goto out_err;
                }

                /* Section 6.12.1 5th step:
                 * If a new SEQ parameter is being processed, the parameters in the
                 * UPDATE are then processed.  The system MUST record the Update ID
                 * in the received SEQ parameter, for replay protection.
                 */

                if (ha->update_id_in != 0 && ha->update_id_in == seq_update_id)
                        same_seq = 1;

                ha->update_id_in = seq_update_id;
               	_HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", ha->update_id_in);
        }

        /* RFC 5201 Section 6.12.1 3th and 4th steps or
         *          Section 6.12.2 2nd and 3th steps */
        HIP_IFE(hip_check_hmac_and_signature(received_update_packet, ha), -1);

       	esp_info = hip_get_param(received_update_packet, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL) {
		HIP_DEBUG("ESP INFO parameter found with new SPI %u.\n",
			  ntohl(esp_info->new_spi));
		has_esp_info = 1;

                if (esp_info->new_spi != esp_info->old_spi)
                {
                    HIP_DEBUG("New SPI != Old SPI -> Please notice that "
                            "rekeying case is not implemented yet.");
                }
                /// @todo Further ESP_INFO handling
                // Done in hip_handle_esp_info() before
	}
        
        /* RFC 5206: End-Host Mobility and Multihoming. */
        // 3.2.1. Mobility with a Single SA Pair (No Rekeying)
        locator = hip_get_param(received_update_packet, HIP_PARAM_LOCATOR);
        echo_request = hip_get_param(received_update_packet, HIP_PARAM_ECHO_REQUEST);
        echo_response = hip_get_param(received_update_packet, HIP_PARAM_ECHO_RESPONSE);

        if (locator != NULL) {
                hip_handle_first_update_packet(received_update_packet,
                        ha, src_addr);
                
                goto out_err;
        }
        else if (echo_request != NULL) {
                // Ignore the ECHO REQUESTS with the same SEQ after processing
                // the first one.
                if (same_seq)
                        goto out_err;

                // We handle ECHO_REQUEST by sending an update packet
                // with reversed source and destination address.
                hip_handle_second_update_packet(received_update_packet,
                        ha, dst_addr, src_addr);

                goto out_err;
        } 
        else if (echo_response != NULL) {
                 hip_handle_third_update_packet(received_update_packet,
                         ha, dst_addr, src_addr);

                 goto out_err;
        }
	
out_err:
        if (err != 0)
                HIP_ERROR("UPDATE handler failed, err=%d\n", err);

        /** @todo Is this needed? */

        // Empty the oppipdb.
        empty_oppipdb();

        return err;
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
			hip_send_update_old(rk.array[i], addr_list, addr_count,
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
        int err = -1;

#if 0
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

	add_locator = flags & HIP_UPDATE_LOCATOR;
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
*		was_bex_addr = ipv6_addr_cmp(hip_cast_sa_addr(addr),
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
		default_ipsec_func_set.hip_delete_sa(esp_info_old_spi,
						     hip_cast_sa_addr(addr),
						     &entry->peer_addr,
						     HIP_SPI_DIRECTION_IN,
						     entry);
		default_ipsec_func_set.hip_delete_sa(entry->default_spi_out,
						     &entry->peer_addr,
						     hip_cast_sa_addr(addr),
						     HIP_SPI_DIRECTION_OUT,
						     entry);

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
/*	 HIP_IFEL(esp_prot_update_add_anchor(update_packet, entry), -1,
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

#endif

        return err;
}


int hip_update_get_all_valid_old(hip_ha_t *entry, void *op)
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

/*int hip_receive_update_old(hip_common_t *msg, in6_addr_t *update_saddr,
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

  /*      _HIP_DEBUG_HIT("receive a stun from: ", update_saddr);

#ifdef CONFIG_HIP_RVS
        if (hip_relay_get_status() == HIP_RELAY_ON)
        {
              hip_relrec_t *rec = NULL;
              hip_relrec_t dummy;

              /* Check if we have a relay record in our database matching the
                 Responder's HIT. We should find one, if the Responder is
                 registered to relay.*/
 /*             HIP_DEBUG_HIT("Searching relay record on HIT ", &msg->hitr);
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
/*	if(entry == NULL) {
		HIP_ERROR("No host association database entry found.\n");
		err = -1;
		goto out_err;

	}
	/* RFC 5201: An UPDATE packet is only accepted if the state is only
	   processed in state ESTABLISHED. However, if the state machine is in
	   state R2-SENT and an UPDATE is received, the state machine should
	   move to state ESTABLISHED (see table 5 under section 4.4.2. HIP
	   State Processes). */
/*	else if(entry->state == HIP_STATE_R2_SENT) {
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
/*	HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
		 "HMAC validation on UPDATE failed.\n");

	/* RFC 5201: The system MAY verify the SIGNATURE in the UPDATE packet.
	   If the verification fails, the packet SHOULD be dropped and an error
	   message logged. */
/*	HIP_IFEL(entry->verify(entry->peer_pub_key, msg), -1,
		 "Verification of UPDATE signature failed.\n");

	/* RFC 5201: If both ACK and SEQ parameters are present, first ACK is
	   processed, then the rest of the packet is processed as with SEQ. */
/*	ack = hip_get_param(msg, HIP_PARAM_ACK);
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
		HIP_IFEL(hip_handle_update_seq_old(entry, msg), -1,
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
/*	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
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
/*			if (!err) {
				hip_print_peer_addresses(entry);
				pl = hip_peer_learning(esp_info, entry, src_ip);
				/* pl left unchecked because currently we are not
				   that interested in the success of PL */
/*				hip_print_peer_addresses(entry);
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
/*	if(sinfo->dst_port == 0){
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);
		entry->nat_mode = 0;
		entry->peer_udp_port = 0;
		entry->hadb_xmit_func->hip_send_pkt = hip_send_raw;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	} else {
		/* Node moves from public Internet to behind a NAT, stays
		   behind the same NAT or moves from behind one NAT to behind
		   another NAT. */
/*		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);

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
/*	if(hip_get_param(msg, HIP_PARAM_REG_INFO) != NULL) {
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
/*	HIP_IFEL(esp_prot_handle_update(msg, entry, src_ip, dst_ip), -1,
			"failed to handle received esp prot anchor\n");

	/************************************************/

/*	if(send_ack) {
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

/*	return err;
}
*/
