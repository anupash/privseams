

/** @file
 * This file defines handling functions for outgoing packets for the Host
 * Identity Protocol (HIP).
 * 
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "output.h"

enum number_dh_keys_t number_dh_keys = TWO;

/**
 * Sends an I1 packet to the peer.
 * 
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 * 
 * @param src_hit a pointer to source host identity tag.
 * @param dst_hit a pointer to destination host identity tag.
 * @param entry   a pointer to a host association database state reserved for
 *                the peer.
 * @return        zero on success, or negative error value on error.
 */
int hip_send_i1(hip_hit_t *src_hit, hip_hit_t *dst_hit, hip_ha_t *entry)
{
        struct hip_common *i1 = 0;
	struct in6_addr daddr;
	struct hip_common *i1_blind = NULL;
	uint16_t mask = 0;
	int err = 0;
		
	HIP_DEBUG("\n");

#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS)) {
		mask |= HIP_CONTROL_RVS_CAPABLE;
	}
#endif
	
	/* Assign a local private key, public key and HIT to HA */
	HIP_DEBUG_HIT("src_hit", src_hit);
	HIP_IFEL(hip_init_us(entry, src_hit), -EINVAL,
		 "Could not assign a local host id\n");
	
#ifdef CONFIG_HIP_BLIND
        if (hip_blind_get_status()) {
	  HIP_DEBUG("Blind is activated, build blinded i1\n");
	  // Build i1 message: use blind HITs and put nonce in the message 
	  HIP_IFEL((i1_blind = hip_blind_build_i1(entry, &mask)) == NULL, 
		   -1, "hip_blind_build_i1() failed\n");
	  HIP_DUMP_MSG(i1_blind);
	}
#endif	

	/* We don't need to use hip_msg_alloc(), since the I1
	   packet is just the size of struct hip_common. */ 

	/* ..except that when calculating the msg size, we need to have more than just hip_common */
	i1 = hip_msg_alloc();
			
	if (!hip_blind_get_status()) {
		entry->hadb_misc_func->
			hip_build_network_hdr(i1, HIP_I1,
					      mask, &entry->hit_our, dst_hit);
	}
	/* Calculate the HIP header length */
	hip_calc_hdr_len(i1);
	
	HIP_HEXDUMP("HIT source", &i1->hits, sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT dest", &i1->hitr, sizeof(struct in6_addr));

	HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1, 
		 "No preferred IP address for the peer.\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
	// if hitr is hashed null hit, send it as null on the wire
	if(hit_is_opportunistic_hashed_hit(&i1->hitr))
		ipv6_addr_copy(&i1->hitr, &in6addr_any);
	
	_HIP_HEXDUMP("dest hit on wire", &i1->hitr, sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &daddr, sizeof(struct in6_addr));
#endif // CONFIG_HIP_OPPORTUNISTIC

#ifdef CONFIG_HIP_BLIND
	// Send blinded i1
	if (hip_blind_get_status()) {
	  err = entry->hadb_xmit_func->hip_send_pkt(&entry->local_address, 
						    &daddr, 
						    (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
						    HIP_NAT_UDP_PORT,
						    i1_blind, entry, 1);
	}
#endif
	if (!hip_blind_get_status()) {
		err = entry->hadb_xmit_func->
			hip_send_pkt(&entry->local_address, &daddr,
				     (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
				     HIP_NAT_UDP_PORT,
				     i1, entry, 1);
	}

	HIP_DEBUG("err after sending: %d.\n", err);
	
	if (!err) {
		HIP_LOCK_HA(entry);
		entry->state = HIP_STATE_I1_SENT;
		HIP_UNLOCK_HA(entry);
	}
	else if (err == 1)
		err = 0;


out_err:
	if (i1)
	  HIP_FREE(i1);

	if (i1_blind)
	  HIP_FREE(i1_blind);
	return err;
}

/**
 * Constructs a new R1 packet payload.
 * 
 * @param src_hit      a pointer to the source host identity tag used in the
 *                     packet.
 * @param sign         a funtion pointer to a signature funtion.
 * @param host_id_priv a pointer to ...
 * @param host_id_pub  a pointer to ...
 * @param cookie       a pointer to ...
 * @return             zero on success, or negative error value on error.
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit, 
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *host_id_priv,
				 const struct hip_host_id *host_id_pub,
				 int cookie_k)
{
	struct hip_common *msg;
 	int err = 0, dh_size1, dh_size2, written1, written2, mask = 0;
 	u8 *dh_data1 = NULL, *dh_data2 = NULL;
	hip_ha_t *entry;
       	uint32_t spi = 0;
	int * service_list = NULL;
	int service_count = 0;
	int *list;
	int count = 0;
	int i = 0;

	/* Supported HIP and ESP transforms. */
 	hip_transform_suite_t transform_hip_suite[] = {
		HIP_HIP_AES_SHA1,
		HIP_HIP_3DES_SHA1,
		HIP_HIP_NULL_SHA1	};
 	hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_AES_SHA1,
		HIP_ESP_3DES_SHA1,
		HIP_ESP_NULL_SHA1
	};
 	_HIP_DEBUG("hip_create_r1() invoked.\n");
	//	struct hip_host_id  *host_id_pub = NULL;
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

 	/* Allocate memory for writing the first Diffie-Hellman shared secret */
	HIP_IFEL((dh_size1 = hip_get_dh_size(HIP_FIRST_DH_GROUP_ID)) == 0, 
		 -1, "Could not get dh_size1\n");
	HIP_IFEL(!(dh_data1 = HIP_MALLOC(dh_size1, GFP_ATOMIC)), 
		 -1, "Failed to alloc memory for dh_data1\n");
	memset(dh_data1, 0, dh_size1);

	_HIP_DEBUG("dh_size=%d\n", dh_size1);

 	/* Allocate memory for writing the second Diffie-Hellman shared secret */
	HIP_IFEL((dh_size2 = hip_get_dh_size(HIP_SECOND_DH_GROUP_ID)) == 0, 
		 -1, "Could not get dh_size2\n");
	HIP_IFEL(!(dh_data2 = HIP_MALLOC(dh_size2, GFP_ATOMIC)), 
		 -1, "Failed to alloc memory for dh_data2\n");
	memset(dh_data2, 0, dh_size2);

	_HIP_DEBUG("dh_size=%d\n", dh_size2);

	//	HIP_IFEL(!(host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO)),
	//	 -1, "Could not acquire localhost public key\n");
	//HIP_HEXDUMP("Our pub host id\n", host_id_pub,
	//	    hip_get_param_total_len(host_id_pub));
	
 	/* Ready to begin building of the R1 packet */
#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE; //XX: FIXME
#endif

	HIP_DEBUG("mask=0x%x\n", mask);
	/*! \todo TH: hip_build_network_hdr has to be replaced with an apprporiate function pointer */
	HIP_DEBUG_HIT("src_hit used to build r1 network header", src_hit);
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

	/********* LOCATOR PARAMETER ************/
        /** Type 193 **/ 
        if (hip_interfamily_status == SO_HIP_SET_INTERFAMILY_ON) {
            HIP_DEBUG("Building LOCATOR parameter\n");
            if ((err = hip_build_locators(msg)) < 0) 
                HIP_DEBUG("LOCATOR parameter building failed\n");
            _HIP_DUMP_MSG(msg);
        }
 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
					42 /* 2^(42-32) sec lifetime */, 
					0, 0),  -1, 
		 "Cookies were burned. Bummer!\n");

 	/********** Diffie-Hellman **********/
	HIP_IFEL((written1 = hip_insert_dh(dh_data1, dh_size1,
					  HIP_FIRST_DH_GROUP_ID)) < 0,
		 -1, "Could not extract the first DH public key\n");

	if (number_dh_keys == TWO){
	         HIP_IFEL((written2 = hip_insert_dh(dh_data2, dh_size2,
		       HIP_SECOND_DH_GROUP_ID)) < 0,
		       -1, "Could not extract the second DH public key\n");

	         HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
		       HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
		       HIP_SECOND_DH_GROUP_ID, dh_data2, written2), -1,
		       "Building of DH failed.\n");
	}else
	         HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
		       HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
		       HIP_MAX_DH_GROUP_ID, dh_data2, 0), -1,
		       "Building of DH failed.\n");

 	/********** HIP transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_HIP_TRANSFORM,
					   transform_hip_suite,
					   sizeof(transform_hip_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of HIP transform failed\n");

 	/********** ESP-ENC transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_ESP_TRANSFORM,  
					   transform_esp_suite,
					   sizeof(transform_esp_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of ESP transform failed\n");

	/********** Host_id **********/

	_HIP_DEBUG("This HOST ID belongs to: %s\n", 
		   hip_get_param_host_id_hostname(host_id_pub));
	HIP_IFEL(hip_build_param(msg, host_id_pub), -1, 
		 "Building of host id failed\n");

	/********** REG_INFO *********/
	/* Get service list of all services offered by this system */
	service_count = hip_get_services_list(&service_list);
	if (service_count > 0) {
		HIP_DEBUG("Adding REG_INFO parameter.\n");
                HIP_IFEL(hip_build_param_reg_info(msg, hip_get_service_min_lifetime(), 
                        hip_get_service_max_lifetime(), service_list, service_count), 
                        -1, "Building of reg_info failed\n");	
	}
        
	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	//HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

 	/********** Signature 2 **********/	

 	HIP_IFEL(sign(host_id_priv, msg), -1, "Signing of R1 failed.\n");
	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	/********** ECHO_REQUEST (OPTIONAL) *********/
	
	/* Fill puzzle parameters */
	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1, 
			 "Internal error\n");

		// FIX ME: this does not always work:
		//get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

		/* hardcode kludge */
		pz->opaque[0] = 'H';
		pz->opaque[1] = 'I';
		//pz->opaque[2] = 'P';
		/* todo: remove random_i variable */
		get_random_bytes(&random_i,sizeof(random_i));
		pz->I = random_i;
	}

 	/************** Packet ready ***************/

        // 	if (host_id_pub)
	//		HIP_FREE(host_id_pub);
 	if (dh_data1)
 		HIP_FREE(dh_data1);
 	if (dh_data2)
 		HIP_FREE(dh_data2);

	//HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	//	if (host_id_pub)
	//	HIP_FREE(host_id_pub);
 	if (msg)
 		HIP_FREE(msg);
 	if (dh_data1)
 		HIP_FREE(dh_data1);
 	if (dh_data2)
 		HIP_FREE(dh_data2);

  	return NULL;
}

/**
 * Builds locator list to msg
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR on success, or negative error value on error
 */
int hip_build_locators(struct hip_common *msg) 
{
    int err = 0, i = 0, ii = 0;
    struct netdev_address *n;
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs = NULL;
    int addr_count = 0;

    if (address_count > 1) {
        HIP_IFEL(!(locs = malloc(address_count * 
                                 sizeof(struct hip_locator_info_addr_item))), 
                 -1, "Malloc for LOCATORS failed\n");
        memset(locs,0,(address_count * 
                       sizeof(struct hip_locator_info_addr_item)));
        list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
            if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                continue;
            if (!IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr))) {
                memcpy(&locs[ii].address, hip_cast_sa_addr(&n->addr), 
                       sizeof(struct in6_addr));
                locs[ii].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
                locs[ii].locator_type = HIP_LOCATOR_LOCATOR_TYPE_IPV6;
                locs[ii].locator_length = sizeof(struct in6_addr) / 4;
                locs[ii].reserved = 0;
                ii++;
            }
        }
        list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
            if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                continue;
            if (IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr))) {
                memcpy(&locs[ii].address, hip_cast_sa_addr(&n->addr), 
                       sizeof(struct in6_addr));
                locs[ii].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
                locs[ii].locator_type = HIP_LOCATOR_LOCATOR_TYPE_IPV6;
                locs[ii].locator_length = sizeof(struct in6_addr) / 4;
                locs[ii].reserved = 0;
                ii++;
            }
        }
        err = hip_build_param_locator(msg, locs, address_count);
    }
    else
        HIP_DEBUG("Host has only one or no addresses no point "
                  "in building LOCATOR parameters\n");
 out_err:
    if (locs) free(locs);
    return err;
}

/**
 * Transmits an R1 packet to the network.
 *
 * Sends an R1 packet to the peer and stores the cookie information that was
 * sent. The packet is sent either to @c i1_saddr or  @c dst_ip depending on the
 * value of @c dst_ip. If @c dst_ip is all zeroes (::/128) or NULL, R1 is sent
 * to @c i1_saddr; otherwise it is sent to @c dst_ip. In case the incoming I1
 * was relayed through a middlebox (e.g. rendezvous server) @c i1_saddr should
 * have the address of that middlebox.
 *
 * @param i1_saddr      a pointer to the source address from where the I1 packet
 *                      was received.
 * @param i1_daddr      a pointer to the destination address where to the I1
 *                      packet was sent to (own address).
 * @param src_hit       a pointer to the source HIT i.e. responder HIT
 *                      (own HIT). 
 * @param dst_ip        a pointer to the destination IPv6 address where the R1
 *                      should be sent (peer ip).
 * @param dst_hit       a pointer to the destination HIT i.e. initiator HIT
 *                      (peer HIT).
 * @param i1_info       a pointer to the source and destination ports
 *                      (when NAT is in use).
 * @param traversed_rvs a pointer to the rvs addresses to be inserted into the
 *                      @c VIA_RVS parameter.
 * @param rvs_count     number of addresses in @c traversed_rvs.
 * @return              zero on success, or negative error value on error.
 */
int hip_xmit_r1(struct in6_addr *i1_saddr, struct in6_addr *i1_daddr,
		struct in6_addr *src_hit, struct in6_addr *dst_ip,
		const in_port_t dst_port, struct in6_addr *dst_hit,
		hip_portpair_t *i1_info, const void *traversed_rvs,
		const int is_via_rvs_nat, uint16_t *nonce) 
{
	struct hip_common *r1pkt = NULL;
	struct in6_addr *r1_dst_addr, *local_plain_hit = NULL;
	in_port_t r1_dst_port = 0;
	int err = 0;
	
	_HIP_DEBUG("hip_xmit_r1() invoked.\n");

	/* Get the destination address and port. If destination port is zero,
	   the source port of I1 becomes the destination port of R1.*/
	r1_dst_addr = (!dst_ip || ipv6_addr_any(dst_ip) ? i1_saddr : dst_ip);
	r1_dst_port = (dst_port == 0 ? i1_info->src_port : dst_port);

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* It sould not be null hit, null hit has been replaced by real local
	   hit. */
	HIP_ASSERT(!hit_is_opportunistic_hashed_hit(src_hit));
#endif
	HIP_DEBUG_HIT("hip_xmit_r1(): Source hit", src_hit);
	HIP_DEBUG_HIT("hip_xmit_r1(): Destination hit", dst_hit);
	HIP_DEBUG_HIT("hip_xmit_r1(): Own address", i1_daddr);
	HIP_DEBUG_HIT("hip_xmit_r1(): R1 destination address", r1_dst_addr);
	HIP_DEBUG("hip_xmit_r1(): R1 destination port %u.\n", r1_dst_port);
	HIP_DEBUG("hip_xmit_r1(): is_via_rvs_nat %d.\n", is_via_rvs_nat);

		
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_IFEL((local_plain_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL, 
		   -1, "Couldn't allocate memory\n");
	  HIP_IFEL(hip_plain_fingerprint(nonce, src_hit, local_plain_hit), 
		   -1, "hip_plain_fingerprints failed\n");
	  HIP_IFEL(!(r1pkt = hip_get_r1(r1_dst_addr, i1_daddr, 
					local_plain_hit, dst_hit)),
		   -ENOENT, "No precreated R1\n");
	  // replace the plain hit with the blinded hit
	  ipv6_addr_copy(&r1pkt->hits, src_hit);
	}
#endif
	if (!hip_blind_get_status()) {
	  HIP_IFEL(!(r1pkt = hip_get_r1(r1_dst_addr, i1_daddr, 
					src_hit, dst_hit)),
		   -ENOENT, "No precreated R1\n");
	}

	if (dst_hit)
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));
	
	HIP_DEBUG_HIT("hip_xmit_r1(): ripkt->hitr", &r1pkt->hitr);
	
	/* Build VIA_RVS or VIA_RVS_NAT parameter if the I1 packet was relayed
	   through a rvs. */
#ifdef CONFIG_HIP_RVS
	if(traversed_rvs)
	{
		/** @todo Parameters must be in ascending order, should this
		    be checked here? */
		if(i1_info->dst_port == HIP_NAT_UDP_PORT) {
			hip_build_param_via_rvs_nat(
				r1pkt,
				(struct hip_in6_addr_port *)traversed_rvs, 1);
		}
		else {
			hip_build_param_via_rvs(
				r1pkt, (struct in6_addr *)traversed_rvs, 1);
		}
	}
#endif

	/* R1 is send on UDP if R1 destination port is 50500. This is if:
	   a) the I1 was received on UDP.
	   b) the received I1 packet had a FROM_NAT parameter. */
	if(r1_dst_port != 0) {
		HIP_IFEL(hip_send_udp(i1_daddr, r1_dst_addr, HIP_NAT_UDP_PORT,
				      r1_dst_port, r1pkt, NULL, 0),
			 -ECOMM, "Sending R1 packet on UDP failed.\n");
	}
	/* Else R1 is send on raw HIP. */
	else {
#ifdef CONFIG_HIP_HI3
		if( i1_info->hi3_in_use ) {
			HIP_IFEL(hip_send_i3(i1_daddr, 
					     r1_dst_addr, 0, 0, 
					     r1pkt, NULL, 0),
				 -ECOMM, 
				 "Sending R1 packet through i3 failed.\n");
		}
		else {
			HIP_IFEL(hip_send_raw(
					 i1_daddr, 
					 r1_dst_addr, 0, 0, 
					 r1pkt, NULL, 0),
				 -ECOMM, 
				 "Sending R1 packet on raw HIP failed.\n");
		}
#else
		HIP_IFEL(hip_send_raw(
				 i1_daddr, r1_dst_addr, 0, 0, r1pkt, NULL, 0),
			 -ECOMM, "Sending R1 packet on raw HIP failed.\n");
#endif
	}
	
 out_err:
	if (r1pkt)
		HIP_FREE(r1pkt);
	if (local_plain_hit)
	  HIP_FREE(local_plain_hit);
	return err;
}

/**
 * Sends a NOTIFY packet to peer.
 *
 * @param entry a pointer to the current host association database state.
 * @warning     includes hardcoded debug data inserted in the NOTIFICATION.
 */ 
void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet;
	struct in6_addr daddr;

	HIP_IFE(!(notify_packet = hip_msg_alloc()), -ENOMEM);
	entry->hadb_misc_func->
		hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
				      &entry->hit_our, &entry->hit_peer);
	HIP_IFEL(hip_build_param_notification(notify_packet,
					      HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE,
					      "ABCDEFGHIJ", 10), 0,
		 "Building of NOTIFY failed.\n");
	
        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), 0);
	
	
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(NULL, &daddr, (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			      entry->peer_udp_port, notify_packet,
			      entry, 0),
		 -ECOMM, "Sending NOTIFY packet failed.\n");
	
 out_err:
	if (notify_packet)
		HIP_FREE(notify_packet);
	return;
}

/** Temporary kludge for escrow service.
    @todo remove this kludge. */
struct hip_rea_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

/**
 * ...
 *
 * @param entry a pointer to the current host association database state.
 * @param op    a pointer to...
 * @return      ...
 * @todo        Comment this function properly.
 */
static int hip_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_rea_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	/* should we check the established status also? */
	if ((entry->hastate & HIP_HASTATE_VALID) == HIP_HASTATE_VALID) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	}

	return 0;
}

/**
 * Sends a NOTIFY packet to all peer hosts.
 *
 */
void hip_send_notify_all(void)
{
        int err = 0, i;
        hip_ha_t *entries[HIP_MAX_HAS] = {0};
        struct hip_rea_kludge rk;

        rk.array = entries;
        rk.count = 0;
        rk.length = HIP_MAX_HAS;

        HIP_IFEL(hip_for_each_ha(hip_get_all_valid, &rk), 0, 
		 "for_each_ha failed.\n");
        for (i = 0; i < rk.count; i++) {
                if (rk.array[i] != NULL) {
                        hip_send_notify(rk.array[i]);
                        hip_put_ha(rk.array[i]);
                }
        }

 out_err:
        return;
}

/**
 * ...
 *
 * @param src_addr  a pointer to the packet source address.
 * @param peer_addr a pointer to the packet destination address.
 * @param msg       a pointer to a HIP packet common header with source and
 *                  destination HITs.
 * @param entry     a pointer to the current host association database state.
 * @return          zero on success, or negative error value on error.
 */
int hip_queue_packet(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		     struct hip_common* msg, hip_ha_t *entry)
{
	int err = 0;
	int len = hip_get_msg_total_len(msg);

	_HIP_DEBUG("hip_queue_packet() invoked.\n");
	/* Not reusing the old entry as the new packet may have
	   different length */
	if (!entry)
		goto out_err;
	else if (entry->hip_msg_retrans.buf) { 
            HIP_FREE(entry->hip_msg_retrans.buf);
            entry->hip_msg_retrans.buf= NULL;
	}

	HIP_IFE(!(entry->hip_msg_retrans.buf = HIP_MALLOC(len, 0)), -ENOMEM);
	memcpy(entry->hip_msg_retrans.buf, msg, len);
	memcpy(&entry->hip_msg_retrans.saddr, src_addr,
	       sizeof(struct in6_addr));
	memcpy(&entry->hip_msg_retrans.daddr, peer_addr,
	       sizeof(struct in6_addr));
	entry->hip_msg_retrans.count = HIP_RETRANSMIT_MAX;
	time(&entry->hip_msg_retrans.last_transmit);
out_err:
	return err;
}

/**
 * Sends a HIP message using raw HIP.
 *
 * Sends a HIP message to the peer on HIP/IP. This function calculates the
 * HIP packet checksum. 
 * 
 * Used protocol suite is <code>IPv4(HIP)</code> or <code>IPv6(HIP)</code>.
 * 
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr  a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param src_port   not used.
 * @param dst_port   not used.
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @see              hip_send_udp
 */
int hip_send_raw(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
	int err = 0, sa_size, sent, len, dupl, try_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4;
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock = 0;
	
	_HIP_DEBUG("hip_send_raw() invoked.\n");
	
	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);
	
	HIP_DEBUG("Sending %s packet on raw HIP.\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
	HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
	_HIP_DUMP_MSG(msg);

	dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
	len = hip_get_msg_total_len(msg);

	/* Some convinient short-hands to avoid too much casting (could be
	   an union as well) */
	src6 = (struct sockaddr_in6 *) &src;
	dst6 = (struct sockaddr_in6 *) &dst;
	src4 = (struct sockaddr_in *)  &src;
	dst4 = (struct sockaddr_in *)  &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	
	if (dst_is_ipv4) {
		hip_raw_sock = hip_raw_sock_v4;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		HIP_DEBUG("Using IPv6 raw socket\n");
		hip_raw_sock = hip_raw_sock_v6;
		sa_size = sizeof(struct sockaddr_in6);
	}

	if (local_addr) {
		HIP_DEBUG("local address given\n");
		memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
	} else {
		HIP_DEBUG("no local address, selecting one\n");
		HIP_IFEL(hip_select_source_address(&my_addr,
						   peer_addr), -1,
			 "Cannot find source address\n");
	}

	src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

	if (src_is_ipv4) {
		IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
		src4->sin_family = AF_INET;
		HIP_DEBUG_INADDR("src4", &src4->sin_addr);
	} else {
		memcpy(&src6->sin6_addr, &my_addr,
		       sizeof(struct in6_addr));
		src6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
	}

	if (dst_is_ipv4) {
		IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
		dst4->sin_family = AF_INET;

		HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
	} else {
		memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
		dst6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
	}

	if (src6->sin6_family != dst6->sin6_family) {
	  /* @todo: Check if this may cause any trouble.
	     It happens every time we send update packet that contains few locators in msg, one is 
	     the IPv4 address of the source, another is IPv6 address of the source. But even if one of 
	     them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all 
	     updates are dropped.  by Andrey "laser".

	   */
		err = -1;
		HIP_ERROR("Source and destination address families differ\n");
		goto out_err;
	}

	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char*)msg,
					    (struct sockaddr *) &src,
					    (struct sockaddr *) &dst);

	/* Note that we need the original (possibly mapped addresses here.
	   Also, we need to do queuing before the bind because the bind
	   can fail the first time during mobility events (duplicate address
	   detection). */
	if (retransmit)
		HIP_IFEL(hip_queue_packet(&my_addr, peer_addr, msg, entry), -1,
			 "Queueing failed.\n");
	
	/* Handover may cause e.g. on-link duplicate address detection
	   which may cause bind to fail. */

	HIP_IFEL(bind(hip_raw_sock, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");

	if (HIP_SIMULATE_PACKET_LOSS && HIP_SIMULATE_PACKET_IS_LOST()) {
		HIP_DEBUG("Packet loss probability: %f\n", ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100.f);
		HIP_DEBUG("Packet was lost (simulation)\n");
		goto out_err;
	}

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work properly. Thus, we use just sendto() */
	
	len = hip_get_msg_total_len(msg);
	_HIP_HEXDUMP("Dumping packet ", msg, len);

	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
		for (try_again = 0; try_again < 2; try_again++) {
			sent = sendto(hip_raw_sock, msg, len, 0,
				      (struct sockaddr *) &dst, sa_size);
			if (sent != len) {
				HIP_ERROR("Could not send the all requested"\
					  " data (%d/%d)\n", sent, len);
				sleep(2);
			} else {
				HIP_DEBUG("sent=%d/%d ipv4=%d\n",
					  sent, len, dst_is_ipv4);
				HIP_DEBUG("Packet sent ok\n");
				break;
			}
		}
	}
 out_err:
	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}

/**
 * Sends a HIP message using User Datagram Protocol (UDP).
 *
 * Sends a HIP message to the peer on UDP/IPv4. IPv6 is not supported, because
 * there are no IPv6 NATs deployed in the Internet yet. If either @c local_addr
 * or @c peer_addr is pure (not a IPv4-in-IPv6 format IPv4 address) IPv6
 * address, no message is send. IPv4-in-IPv6 format IPv4 addresses are mapped to
 * pure IPv4 addresses. In case of transmission error, this function tries to
 * retransmit the packet @c HIP_NAT_NUM_RETRANSMISSION times and sleeps for
 * @c HIP_NAT_SLEEP_TIME seconds between retransmissions. The HIP packet
 * checksum is set to zero.  
 * 
 * Used protocol suite is <code>IPv4(UDP(HIP))</code>.
 * 
 * @param local_addr a pointer to our IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr  a pointer to peer IPv4-in-IPv6 format IPv4 address.
 * @param src_port   source port number to be used in the UDP packet header
 *                   (host byte order) 
 * @param dst_port   destination port number to be used in the UDP packet header.
 *                   (host byte order).
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @see              hip_send_raw
 */ 
int hip_send_udp(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common* msg, hip_ha_t *entry, int retransmit)
{
	int sockfd = 0, err = 0, xmit_count = 0;
	/* IPv4 Internet socket addresses. */
	struct sockaddr_in src4, dst4;
	/* Length of the HIP message. */
	uint16_t packet_length = 0;
	/* Number of characters sent. */
	ssize_t chars_sent = 0;
	/* If local address is not given, we fetch one in my_addr. my_addr_ptr
	   points to the final source address (my_addr or local_addr). */
	struct in6_addr my_addr, *my_addr_ptr = NULL;
	
	_HIP_DEBUG("hip_send_udp() invoked.\n");
	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);
	HIP_DEBUG("Sending %s packet on UDP.\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_udp(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_udp(): peer_addr", peer_addr);
	HIP_DEBUG("Source port: %d, destination port: %d.\n",
		  src_port, dst_port);
	HIP_DUMP_MSG(msg);

	/* Currently only IPv4 is supported, so we set internet address family
	   accordingly and map IPv6 addresses to IPv4 addresses. */
	src4.sin_family = dst4.sin_family = AF_INET;
	
        /* Source address. */
        if (local_addr != NULL) {
		HIP_DEBUG_IN6ADDR("Local address is given", local_addr);
		HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(local_addr), -EPFNOSUPPORT,
			 "Local address is pure IPv6 address, IPv6 address "\
			 "family is currently not supported on UDP/HIP.\n");
		my_addr_ptr = local_addr;
		IPV6_TO_IPV4_MAP(local_addr, &src4.sin_addr);
	} else {
		HIP_DEBUG("Local address is NOT given, selecting one.\n");
		HIP_IFEL(hip_select_source_address(
				 &my_addr, peer_addr), -EADDRNOTAVAIL,
			 "Cannot find local address.\n");
		my_addr_ptr = &my_addr;
		IPV6_TO_IPV4_MAP(&my_addr, &src4.sin_addr);
	}
	
        /* Destination address. */
	HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(peer_addr), -EPFNOSUPPORT,
		 "Peer address is pure IPv6 address, IPv6 address family is "\
		 "currently not supported on UDP/HIP.\n");
	IPV6_TO_IPV4_MAP(peer_addr, &dst4.sin_addr);
	
        /* Source port */
	if(src_port != 0) {
		src4.sin_port = htons(src_port);
	}
	else {
		src4.sin_port = 0;
	}
	
	/* Destination port. */
	if(dst_port != 0) {
		dst4.sin_port = htons(dst_port);
	}
	else {
		dst4.sin_port = htons(HIP_NAT_UDP_PORT);
	}

	/* Zero message HIP checksum. */
	hip_zero_msg_checksum(msg);
	
	/* Get the packet total length for sendto(). */
	packet_length = hip_get_msg_total_len(msg);
	
	HIP_DEBUG("Trying to send %u bytes on UDP with source port: %u and "\
		  "destination port: %u.\n",
		  packet_length, ntohs(src4.sin_port), ntohs(dst4.sin_port));
	
	/* If this is a retransmission, the packet is queued before sending. */
	if (retransmit) {
		HIP_IFEL(hip_queue_packet(my_addr_ptr, peer_addr, msg,
					  entry), -1, "Queueing failed.\n");
	}
	
	/* Try to send the data. */
	do {
		chars_sent = sendto( hip_nat_sock_udp, msg, packet_length, 0,
				     (struct sockaddr *) &dst4, sizeof(dst4));
		if(chars_sent < 0)
		{
			/* Failure. */
			HIP_DEBUG("Problem in sending UDP packet. Sleeping "\
				  "for %d seconds and trying again.\n",
				  HIP_NAT_SLEEP_TIME);
			sleep(HIP_NAT_SLEEP_TIME);
		}
		else
		{
			/* Success. */
			break;
		}
		xmit_count++;
	} while(xmit_count < HIP_NAT_NUM_RETRANSMISSION);

	/* Verify that the message was sent completely. */
	HIP_IFEL((chars_sent != packet_length), -ECOMM,
		 "Error while sending data on UDP: %d bytes of %d sent.)\n",
		 chars_sent, packet_length);

	HIP_DEBUG("Packet sent successfully over UDP, characters sent: %u, "\
		  "packet length: %u.\n", chars_sent, packet_length);

 out_err:
	if (sockfd)
		close(sockfd);
	return err;
}

#ifdef CONFIG_HIP_HI3
/**
 * The callback for i3 "no matching id" callback.
 * 
 * @param ctx_data a pointer to...
 * @param data     a pointer to...
 * @param fun_ctx  a pointer to...
 * @todo           tkoponen: should this somehow trigger the timeout for waiting
 *                 outbound traffic (state machine)?
 */
static void no_matching_trigger(void *ctx_data, void *data, void *fun_ctx) {
	char id[32];
	sprintf_i3_id(id, (ID *)ctx_data);
	
	HIP_ERROR("Following ID not found: %s", id);
}

/** 
 * Hi3 outbound traffic processing.
 * 
 * @param src_addr  a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param not_used  source port number. Not in use.
 * @param not_used2 destination port number. Not in use.
 * @param msg       a pointer to a HIP packet common header with source and
 *                  destination HITs.
 * @param not_used3 a pointer to the current host association database state.
 *                  Not in use.
 * @param not_used4 a boolean value indicating if this is a retransmission
 *                  (@b zero if this is @b not a retransmission). Not in use.
 * @note            There are four parameters not used anywhere. However, these
 *                  parameters must exist in the function parameter list
 *                  because all the send-functions must have a uniform parameter
 *                  list as dictated by @c hip_hadb_xmit_func_set.
 * @todo            For now this supports only serialiazation of IPv6 addresses
 *                  to Hi3 header.
 * @todo            This function is outdated. Does not support in6 mapped
 *                  addresses and retransmission queues -mk
 * @todo            Does this support NAT travelsal? Or is it even supposed to
 *                  support it?
 * 
 */
int hip_send_i3(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		in_port_t not_used, in_port_t not_used2, struct hip_common *msg,
		hip_ha_t *not_used3, int not_used4)
{
	ID id;
	cl_buf *clb;
  	u16 csum;	
	int err = 0, msg_len, hdr_dst_len, hdr_src_len;
	struct sockaddr_in6 src, dst;
	struct hi3_ipv6_addr hdr_src, hdr_dst;
	struct ip *iph;
	char *buf;

	/* This code is outdated. Synchronize to the non-hi3 version */
	if (!src_addr) {
		/** @todo Obtain the preferred address. */
		HIP_ERROR("No source address.\n");
		return -1;
	}

	if (!peer_addr) {
		/** @todo Just ignore? */
		HIP_ERROR("No destination address.\n");
		return -1;
	}		


	/* Construct the Hi3 header, for now IPv6 only */
	hdr_src.sin6_family = AF_INET6;
	hdr_src_len = sizeof(struct hi3_ipv6_addr);
	memcpy(&hdr_src.sin6_addr, src_addr, sizeof(struct in6_addr));
	memcpy(&src.sin6_addr, src_addr, sizeof(struct in6_addr));

	hdr_dst.sin6_family = AF_INET6;
	hdr_dst_len = sizeof(struct hi3_ipv6_addr);
	memcpy(&hdr_dst.sin6_addr, peer_addr, sizeof(struct in6_addr));
	memcpy(&dst.sin6_addr, peer_addr, sizeof(struct in6_addr));
        /* IPv6 specific code ends */

	msg_len = hip_get_msg_total_len(msg);
	clb = cl_alloc_buf(msg_len + hdr_dst_len + hdr_src_len + sizeof(struct ip));
	if (!clb) {
		HIP_ERROR("Out of memory\n.");
		return -1;
	}

	buf = clb->data;
	iph = (struct ip*)buf;
        /* create IP header for tunneling HIP packet through i3 */                   
	iph->ip_v = 6;
	iph->ip_hl = sizeof(struct ip) >> 2;
	iph->ip_tos = 0;
	iph->ip_len = htons(msg_len+sizeof(struct ip));    /* network byte order */
	iph->ip_id = 0;                  /* let IP set this */
	iph->ip_off = 0;                 /* frag offset, MF and DF flags */
	iph->ip_ttl = 200;
	iph->ip_p = 99;
	//iph->ip_src = ((struct sockaddr_in *)src)->sin_addr;
	//iph->ip_dst = ((struct sockaddr_in *)dst)->sin_addr;
	//iph->ip_sum = in_cksum((unsigned short *)iph, sizeof (struct ip));
	
	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char *)msg, 
					    (struct sockaddr *)&src, 
					    (struct sockaddr *)&dst);

	clb->data_len = hdr_src_len + hdr_dst_len + msg_len + sizeof(struct ip);

	buf += sizeof(struct ip);
	memcpy(buf, &hdr_src, hdr_src_len);
	buf += hdr_src_len;
	memcpy(buf, &hdr_dst, hdr_dst_len);
	buf += hdr_dst_len;
  
	memcpy(buf, msg, msg_len);

	/* Send over i3 */
	bzero(&id, ID_LEN);
	memcpy(&id, &msg->hitr, sizeof(struct in6_addr));
	//cl_set_private_id(&id);

	/* exception when matching trigger not found */
	cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);
	cl_send(&id, clb, 0);  
	cl_free_buf(clb);
	
 out_err:
	return err;
}
#endif
