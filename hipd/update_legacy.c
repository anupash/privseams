/**
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with DHT and
 * base exchange code.
 */

#include "update_legacy.h"

/**
 * Builds udp and raw locator items into locator list to msg
 * this is the extension of hip_build_locators in output.c
 * type2 locators are collected also
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR2 on success, or negative error value on error
 */
int hip_build_locators_old(struct hip_common *msg, uint32_t spi, hip_transform_suite_t ice)
{
    int err = 0, i = 0, count1 = 0, count2 = 0, UDP_relay_count = 0;
    int addr_max1, addr_max2;
    struct netdev_address *n;
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs1 = NULL;
    struct hip_locator_info_addr_item2 *locs2 = NULL;
    hip_ha_t *ha_n;

    //TODO count the number of UDP relay servers.
    // check the control state of every hatb_state.

    if (address_count == 0) {
	    HIP_DEBUG("Host has only one or no addresses no point "
		      "in building LOCATOR2 parameters\n");
	    goto out_err;
    }

    //TODO check out the count for UDP and hip raw.
    addr_max1 = address_count;
    // let's put 10 here for now. anyhow 10 additional type 2 addresses should be enough
    addr_max2 = HIP_REFLEXIVE_LOCATOR_ITEM_AMOUNT_MAX + 10;

    HIP_IFEL(!(locs1 = malloc(addr_max1 *
			      sizeof(struct hip_locator_info_addr_item))),
	     -1, "Malloc for LOCATORS type1 failed\n");
    HIP_IFEL(!(locs2 = malloc(addr_max2 *
			      sizeof(struct hip_locator_info_addr_item2))),
                 -1, "Malloc for LOCATORS type2 failed\n");


    memset(locs1,0,(addr_max1 *
		    sizeof(struct hip_locator_info_addr_item)));

    memset(locs2,0,(addr_max2 *
		    sizeof(struct hip_locator_info_addr_item2)));

    HIP_DEBUG("there are %d type 1 locator item\n" , addr_max1);

    if (ice == HIP_NAT_MODE_ICE_UDP)
	    goto build_ice_locs;

    list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
 	    HIP_DEBUG_IN6ADDR("Add address:",hip_cast_sa_addr(&n->addr));
            HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)));
	    memcpy(&locs1[count1].address, hip_cast_sa_addr(&n->addr),
		   sizeof(struct in6_addr));
	    if (n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY)
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL;
	    else
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
	    locs1[count1].locator_type = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
	    locs1[count1].locator_length = sizeof(struct in6_addr) / 4;
	    locs1[count1].reserved = 0;
	    count1++;
    }

    if (ice != HIP_NAT_MODE_ICE_UDP)
	    goto skip_ice;

build_ice_locs:

#if 0
    HIP_DEBUG("Looking for reflexive addresses from a HA of a relay\n");
    i = 0;

    list_for_each_safe(item, tmp, hadb_hit, i) {
            ha_n = list_entry(item);
            if (count2 >= addr_max2)
	    	    break;
            HIP_DEBUG_IN6ADDR("Looking for reflexive, preferred address: ",
			      &ha_n->peer_addr );
            HIP_DEBUG_IN6ADDR("Looking for reflexive, local address: ",
			      &ha_n->our_addr );
            HIP_DEBUG("Looking for reflexive port: %d \n",
		      ha_n->local_reflexive_udp_port);
            HIP_DEBUG("Looking for reflexive addr: ",
		      &ha_n->local_reflexive_address);
            /* Check if this entry has reflexive port */
            if(ha_n->local_reflexive_udp_port) {
		    memcpy(&locs2[count2].address, &ha_n->local_reflexive_address,
			   sizeof(struct in6_addr));
		    locs2[count2].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
		    locs2[count2].locator_type = HIP_LOCATOR_LOCATOR_TYPE_UDP;
		    locs2[count2].locator_length = 7;
		    locs2[count2].reserved = 0;
		    // for IPv4 we add UDP information
		    locs2[count2].port = htons(ha_n->local_reflexive_udp_port);
                    locs2[count2].transport_protocol = 0;
                    locs2[count2].kind = ICE_CAND_TYPE_SRFLX;  // 2 for peer reflexive
                    locs2[count2].spi = htonl(spi);
                    locs2[count2].priority = htonl(ice_calc_priority(HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY,ICE_CAND_PRE_SRFLX,1) - ha_n->local_reflexive_udp_port);
		    HIP_DEBUG("build a locator at priority : %d\n", ntohl(locs2[count2].priority));
                    HIP_DEBUG_HIT("Created one reflexive locator item: ",
                                  &locs1[count2].address);
                    count2++;
                    if (count2 >= addr_max2)
                            break;
            }
    }

#endif

skip_ice:

    HIP_DEBUG("locator count %d\n", count1, count2);

    err = hip_build_param_locator2(msg, locs1, locs2, count1, count2);

 out_err:

    if (locs1)
	    free(locs1);
    if (locs2)
	    free(locs2);

    return err;
}

// Used in hip_update_send_echo_old
int hip_build_verification_pkt_old(hip_ha_t *entry, hip_common_t *update_packet,
			       struct hip_peer_addr_list_item *addr,
			       in6_addr_t *hits, in6_addr_t *hitr)
{
	int err = 0;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	HIP_DEBUG("building verification packet\n");
	hip_msg_init(update_packet);
	entry->hadb_misc_func->hip_build_network_hdr(
		update_packet, HIP_UPDATE, mask, hitr, hits);
	entry->update_id_out++;
	addr->seq_update_id = entry->update_id_out;

	_HIP_DEBUG("outgoing UPDATE ID for LOCATOR addr check=%u\n",
		   addr->seq_update_id);

	/* Reply with UPDATE(ESP_INFO, SEQ, ACK, ECHO_REQUEST) */

	/* ESP_INFO */
	esp_info_old_spi = entry->spi_outbound_current;
	esp_info_new_spi = esp_info_old_spi;
	HIP_IFEL(hip_build_param_esp_info(update_packet,
					  entry->current_keymat_index,
					  esp_info_old_spi,
					  esp_info_new_spi),
		 -1, "Building of ESP_INFO param failed\n");
	/* @todo Handle overflow if (!update_id_out) */
	/* Add SEQ */
	HIP_IFEBL2(hip_build_param_seq(update_packet,
				       addr->seq_update_id), -1,
		   return , "Building of SEQ failed\n");

	/* TODO: NEED TO ADD ACK */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(addr->seq_update_id)),
		 -1, "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEBL2(hip_build_param_hmac_contents(update_packet,
						 &entry->hip_hmac_out),
		   -1, return , "Building of HMAC failed\n");
	/* Add SIGNATURE */
	HIP_IFEBL2(entry->sign(entry->our_priv_key, update_packet),
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

// Used in hip_hadb_add_udp_addr_old
int hip_update_send_echo_old(hip_ha_t *entry,
			 uint32_t spi_out,
			 struct hip_peer_addr_list_item *addr){

	int err = 0, i = 0;
	struct hip_common *update_packet = NULL;
        hip_list_t *item = NULL, *tmp = NULL;
        struct netdev_address *n;

	HIP_DEBUG_HIT("new addr to check", &addr->address);

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt_old(entry, update_packet, addr,
					    &entry->hit_peer, &entry->hit_our),
		 -1, "Building Echo Packet failed\n");

        /* Have to take care of UPDATE echos to opposite family */
        if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)&addr->address)
            == IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
            HIP_IFEL(entry->hadb_xmit_func->
                     hip_send_pkt(&entry->our_addr, &addr->address,
                                  (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                  update_packet, entry, 1),
                     -ECOMM, "Sending UPDATE packet with echo data failed.\n");
	} else {
            /* UPDATE echo is meant for opposite family of local_address*/
            /* check if we have one, otherwise let fail */
            list_for_each_safe(item, tmp, addresses, i) {
                n = list_entry(item);
                if (hip_sockaddr_is_v6_mapped(&n->addr)
                    != IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
                    HIP_IFEL(entry->hadb_xmit_func->
                             hip_send_pkt(hip_cast_sa_addr(&n->addr),
                                          (struct in6_addr*)&addr->address,
                                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                          update_packet, entry, 1),
                             -ECOMM, "Sending UPDATE packet with echo data failed.\n");
                }
            }
        }

 out_err:
	return err;

}
