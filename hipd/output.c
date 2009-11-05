/* @file
 * This file defines handling functions for outgoing packets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Samu Varjonen
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include "output.h"

enum number_dh_keys_t number_dh_keys = TWO;

#ifdef ANDROID_CHANGES
#define icmp6hdr icmp6_hdr
#define icmp6_checksum icmp6_cksum
#define icmp6_identifier icmp6_id
#define icmp6_sequence icmp6_seq
#define ICMPV6_ECHO_REQUEST ICMP6_ECHO_REQUEST
#endif    

/**
* Standard BSD internet checksum routine from nmap
* for calculating the checksum field of the TCP header
*/
unsigned short in_cksum(u16 *ptr,int nbytes){
	register u32 sum;
	u16 oddbyte;
	register u16 answer;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */
	sum = 0;
	while (nbytes > 1){
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;            /* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */
	sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;          /* ones-complement, then truncate to 16 bits */
	return(answer);
}

/**
 * Sends an I1 packet to the peer. Used internally by hip_send_i1
 * Check hip_send_i1 & hip_send_pkt for the parameters.
 */
int hip_send_i1_pkt(struct hip_common *i1, hip_hit_t *dst_hit,
                    struct in6_addr *local_addr, struct in6_addr *peer_addr,
                    in_port_t src_port, in_port_t dst_port,
                    hip_ha_t *entry, int retransmit)
{
        int err = 0;

#ifdef CONFIG_HIP_OPPORTUNISTIC
        // if hitr is hashed null hit, send it as null on the wire
        if  (hit_is_opportunistic_hashed_hit(&i1->hitr))
                ipv6_addr_copy(&i1->hitr, &in6addr_any);

	if (local_addr)
		HIP_DEBUG_IN6ADDR("local", local_addr);
	if (peer_addr)
		HIP_DEBUG_IN6ADDR("peer", peer_addr);

#endif // CONFIG_HIP_OPPORTUNISTIC


        HIP_DEBUG_HIT("BEFORE sending\n", peer_addr);
        err = entry->hadb_xmit_func->
                hip_send_pkt(local_addr, peer_addr,
                             src_port,
                             dst_port,
                             i1, entry, 1);

        HIP_DEBUG("err after sending: %d.\n", err);

        if (!err)
        {
                HIP_LOCK_HA(entry);
                entry->state = HIP_STATE_I1_SENT;
                HIP_UNLOCK_HA(entry);
        }
        else if (err == 1)
        {
            err = 0;
        }

out_err:
        return err;
}

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
	uint16_t mask = 0;
	int err = 0, n = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	struct hip_peer_addr_list_item *addr;
	int i = 0;
	struct in6_addr *local_addr = NULL;
	struct in6_addr peer_addr;

	HIP_IFEL((entry->state == HIP_STATE_ESTABLISHED), 0,
		 "State established, not triggering bex\n");

	/* Assign a local private key, public key and HIT to HA */
	HIP_DEBUG_HIT("src_hit", src_hit);
	HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);
	HIP_IFEL(hip_init_us(entry, src_hit), -EINVAL,
			"Could not assign a local host id\n");
	HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);

	/* We don't need to use hip_msg_alloc(), since the I1
	   packet is just the size of struct hip_common. */

	/* ..except that when calculating the msg size, we need to have more
	   than just hip_common */

	/* So why don't we just have a hip_max_t struct to allow allocation of
	   maximum sized HIP packets from the stack? Not that it would make any
	   difference here, but playing with mallocs has always the chance of
	   leaks... */

	i1 = hip_msg_alloc();

    entry->hadb_misc_func->hip_build_network_hdr(i1, HIP_I1,
						mask, &entry->hit_our, dst_hit);

	/* Calculate the HIP header length */
	hip_calc_hdr_len(i1);

	HIP_DEBUG_HIT("HIT source", &i1->hits);
	HIP_DEBUG_HIT("HIT dest", &i1->hitr);

	HIP_DEBUG("Sending I1 to the following addresses:\n");
	hip_print_peer_addresses_to_be_added(entry);

	if (NULL == entry->peer_addr_list_to_be_added == NULL) {

		HIP_IFEL(hip_hadb_get_peer_addr(entry, &peer_addr), -1,
					"No preferred IP address for the peer.\n");

		local_addr = &entry->our_addr;
		err = hip_send_i1_pkt(i1, dst_hit,
								  local_addr, &peer_addr,
								  entry->local_udp_port,
								  entry->peer_udp_port,
								  entry, 1);
	} else {

	    if (entry->peer_addr_list_to_be_added) {
	    	HIP_DEBUG("Number of items in the peer addr list: %d ",
					  entry->peer_addr_list_to_be_added->num_items);
	    }

	    list_for_each_safe(item, tmp, entry->peer_addr_list_to_be_added, i) {

	    	addr = list_entry(item);

		    ipv6_addr_copy(&peer_addr, &addr->address);

		    err = hip_send_i1_pkt(i1, dst_hit,
								NULL, &peer_addr,
								entry->local_udp_port,
								entry->peer_udp_port,
								entry,
								1);
                
		    /* Do not bail out on error with shotgun. Some
		       address pairs just might fail. */
		}
	}

out_err:
	if (i1 != NULL) {
		free(i1);
	}
	return err;
}

/**
 * Constructs a new R1 packet payload.
 *
 * @param src_hit      a pointer to the source host identity tag used in the
 *                     packet.
 * @param sign         a funtion pointer to a signature funtion.
 * @param private_key  a pointer to ...
 * @param host_id_pub  a pointer to ...
 * @param cookie       a pointer to ...
 * @return             zero on success, or negative error value on error.
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 void *private_key,
				 const struct hip_host_id *host_id_pub,
				 int cookie_k)
{
	struct netdev_address *n = NULL;
 	hip_ha_t *entry = NULL;
	hip_common_t *msg = NULL;
 	hip_list_t *item = NULL, *tmp = NULL;
	hip_srv_t service_list[HIP_TOTAL_EXISTING_SERVICES];
	u8 *dh_data1 = NULL, *dh_data2 = NULL;
	uint32_t spi = 0;
	char order[] = "000";
	int err = 0, dh_size1 = 0, dh_size2 = 0, written1 = 0, written2 = 0;
	int mask = 0, l = 0, is_add = 0, i = 0, ii = 0, *list = NULL;
	unsigned int service_count = 0;
	int ordint = 0;
	struct hip_puzzle *pz;
	uint64_t random_i;

	/* Supported HIP and ESP transforms. */
	hip_transform_suite_t transform_hip_suite[] = {
                                                    HIP_HIP_AES_SHA1,
                                                    HIP_HIP_3DES_SHA1,
                                                    HIP_HIP_NULL_SHA1
                                                  };
    hip_transform_suite_t transform_esp_suite[] = {
                                                    HIP_ESP_AES_SHA1,
                                                    HIP_ESP_3DES_SHA1,
                                                    HIP_ESP_NULL_SHA1
                                                  };
	hip_transform_suite_t transform_nat_suite[] = {
                                                    HIP_NAT_MODE_PLAIN_UDP
                                                  };

    /* change order if necessary */
	sprintf(order, "%d", hip_transform_order);
	for ( i = 0; i < 3; i++) {
		switch (order[i]) {
		case '1':
			transform_hip_suite[i] = HIP_HIP_AES_SHA1;
			transform_esp_suite[i] = HIP_ESP_AES_SHA1;
			HIP_DEBUG("Transform order index %d is AES\n", i);
			break;
		case '2':
			transform_hip_suite[i] = HIP_HIP_3DES_SHA1;
			transform_esp_suite[i] = HIP_ESP_3DES_SHA1;
			HIP_DEBUG("Transform order index %d is 3DES\n", i);
			break;
		case '3':
 			transform_hip_suite[i] = HIP_HIP_NULL_SHA1;
			transform_esp_suite[i] = HIP_ESP_NULL_SHA1;
			HIP_DEBUG("Transform order index %d is NULL_SHA1\n", i);
			break;
		}
	}

 	_HIP_DEBUG("hip_create_r1() invoked.\n");
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

	/* Ready to begin building of the R1 packet */

	/** @todo TH: hip_build_network_hdr has to be replaced with an
	    appropriate function pointer */
	HIP_DEBUG_HIT("src_hit used to build r1 network header", src_hit);
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
					42 /* 2^(42-32) sec lifetime */,
					0, 0),  -1,
		 "Cookies were burned. Bummer!\n");

 	/* Parameter Diffie-Hellman */
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

 	/* Parameter HIP transform. */
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_HIP_TRANSFORM,
					   transform_hip_suite,
					   sizeof(transform_hip_suite) /
					   sizeof(hip_transform_suite_t)), -1,
		 "Building of HIP transform failed\n");
 	
	/* Parameter HOST_ID */
	_HIP_DEBUG("This HOST ID belongs to: %s\n",
		   hip_get_param_host_id_hostname(host_id_pub));
	HIP_IFEL(hip_build_param(msg, host_id_pub), -1,
		 "Building of host id failed\n");

	/* Parameter REG_INFO */
	hip_get_active_services(service_list, &service_count);
	HIP_DEBUG("Found %d active service(s) \n", service_count);
	hip_build_param_reg_info(msg, service_list, service_count);

 	/* Parameter ESP-ENC transform. */
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_ESP_TRANSFORM,
					   transform_esp_suite,
					   sizeof(transform_esp_suite) /
					   sizeof(hip_transform_suite_t)), -1,
		 "Building of ESP transform failed\n");

 	/********** ESP-PROT transform (OPTIONAL) **********/

 	HIP_IFEL(esp_prot_r1_add_transforms(msg), -1,
 			"failed to add optional esp transform parameter\n");

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	//HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

 	/* Parameter Signature 2 */

	HIP_IFEL(sign(private_key, msg), -1, "Signing of R1 failed.\n");

	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	/* Parameter ECHO_REQUEST (OPTIONAL) */

	/* Fill puzzle parameters */
	HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1,
		 "Internal error\n");

	// FIXME: this does not always work:
	//get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

	/* hardcode kludge */
	pz->opaque[0] = 'H';
	pz->opaque[1] = 'I';
	//pz->opaque[2] = 'P';
	/** @todo Remove random_i variable. */
	get_random_bytes(&random_i,sizeof(random_i));
	pz->I = random_i;

 	/* Packet ready */

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
int hip_send_r1(hip_common_t *i1, in6_addr_t *i1_saddr, in6_addr_t *i1_daddr,
                in6_addr_t *dst_ip, const in_port_t dst_port,
                hip_portpair_t *i1_info, uint16_t relay_para_type)
{
	hip_common_t *r1pkt = NULL;
	in6_addr_t *r1_dst_addr = NULL, *local_plain_hit = NULL,
		*r1_src_addr = i1_daddr;
	in_port_t r1_dst_port = 0;
	int err = 0;

	_HIP_DEBUG("hip_send_r1() invoked.\n");

	HIP_DEBUG_IN6ADDR("i1_saddr", i1_saddr);
	HIP_DEBUG_IN6ADDR("i1_daddr", i1_daddr);
	HIP_DEBUG_IN6ADDR("dst_ip", dst_ip);

	/* Get the final destination address and port for the outgoing R1.
	   dst_ip and dst_port have values only if the incoming I1 had
	   FROM/FROM_NAT parameter. */
	if(!ipv6_addr_any(dst_ip) && relay_para_type){
		//from RVS or relay
		if(relay_para_type == HIP_PARAM_RELAY_FROM){
			HIP_DEBUG("Param relay from\n");
			//from relay
			r1_dst_addr = i1_saddr;
			r1_dst_port = i1_info->src_port;
			// I---> NAT--> RVS-->R is not supported yet
			/*
			r1_dst_addr =  dst_ip;
			r1_dst_port = dst_port;
			*/
		}
		else if(relay_para_type == HIP_PARAM_FROM){
			HIP_DEBUG("Param from\n");
			//from RVS, answer to I
			r1_dst_addr =  dst_ip;
			if(i1_info->src_port)
				// R and RVS is in the UDP mode or I send UDP to RVS with incoming port hip_get_peer_nat_udp_port()
				r1_dst_port =  hip_get_peer_nat_udp_port();
			else
				// connection between R & RVS is in hip raw mode
				r1_dst_port =  0;
		}
	} else {
		HIP_DEBUG("No RVS or relay\n");
		/* no RVS or RELAY found;  direct connection */
		r1_dst_addr = i1_saddr;
		r1_dst_port = i1_info->src_port;
	}

/* removed by santtu because relay supported
	r1_dst_addr = (ipv6_addr_any(dst_ip) ? i1_saddr : dst_ip);
	r1_dst_port = (dst_port == 0 ? i1_info->src_port : dst_port);
*/
#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* It should not be null hit, null hit has been replaced by real local
	   hit. */
	HIP_ASSERT(!hit_is_opportunistic_hashed_hit(&i1->hitr));
#endif

	/* Case: I ----->IPv4---> RVS ---IPv6---> R */
	if (IN6_IS_ADDR_V4MAPPED(r1_src_addr) !=
	    IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
		HIP_DEBUG_IN6ADDR("r1_src_addr", r1_src_addr);
		HIP_DEBUG_IN6ADDR("r1_dst_addr", r1_dst_addr);
		HIP_DEBUG("Different relayed address families\n");
		HIP_IFEL(hip_select_source_address(r1_src_addr, r1_dst_addr),
			 -1, "Failed to find proper src addr for R1\n");
		if (!IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
			HIP_DEBUG("Destination IPv6, disabling UDP encap\n");
			r1_dst_port = 0;
		}
	}

    HIP_IFEL(!(r1pkt = hip_get_r1(r1_dst_addr, i1_daddr,
                &i1->hitr, &i1->hits)),
       -ENOENT, "No precreated R1\n");

	if (&i1->hits)
		ipv6_addr_copy(&r1pkt->hitr, &i1->hits);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));

	HIP_DEBUG_HIT("hip_send_r1(): ripkt->hitr", &r1pkt->hitr);

#ifdef CONFIG_HIP_RVS
	/* Build VIA_RVS or RELAY_TO parameter if the I1 packet was relayed
	   through a rvs. */
	/** @todo Parameters must be in ascending order, should this
	    be checked here? Now we just assume that the VIA_RVS/RELAY_TO
	    parameter is the last parameter. */
	/* If I1 had a FROM/RELAY_FROM, then we must build a RELAY_TO/VIA_RVS
	   parameter. */
	if(!ipv6_addr_any(dst_ip) && relay_para_type)
	{    // dst_port has the value of RELAY_FROM port.
		//there is port no value for FROM parameter
		//here condition is not enough
		if(relay_para_type == HIP_PARAM_RELAY_FROM)
		{
			HIP_DEBUG("Build param relay from\n");
			hip_build_param_relay_to(
				r1pkt, dst_ip, dst_port);
		}
		else if(relay_para_type == HIP_PARAM_FROM)
		{
			HIP_DEBUG("Build param from\n");
			hip_build_param_via_rvs(r1pkt, i1_saddr);
		}
	}
#endif

	/* R1 is send on UDP if R1 destination port is hip_get_peer_nat_udp_port(). This is if:
	   a) the I1 was received on UDP.
	   b) the received I1 packet had a RELAY_FROM parameter. */
	if(r1_dst_port)
	{
		HIP_IFEL(hip_send_pkt(r1_src_addr, r1_dst_addr, hip_get_local_nat_udp_port(),
				      r1_dst_port, r1pkt, NULL, 0),
			 -ECOMM, "Sending R1 packet on UDP failed.\n");
	}
	/* Else R1 is send on raw HIP. */
	else
	{
        HIP_IFEL(hip_send_pkt(
                 r1_src_addr,
                 r1_dst_addr, 0, 0,
                 r1pkt, NULL, 0),
             -ECOMM,
             "Sending R1 packet on raw HIP failed.\n");
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
	struct hip_common *notify_packet = NULL;
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
		 hip_send_pkt(NULL, &daddr, (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port, notify_packet,
			      entry, 0),
		 -ECOMM, "Sending NOTIFY packet failed.\n");

 out_err:
	if (notify_packet)
		HIP_FREE(notify_packet);
	return;
}

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

/* Checks if source and destination IP addresses are compatible for sending
 *  packets between them
 *
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 * 
 * @return          non-zero on success, zero on failure
 */
int are_addresses_compatible(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
    if (!IN6_IS_ADDR_V4MAPPED(src_addr) && IN6_IS_ADDR_V4MAPPED(dst_addr))
        return 0;

    if (IN6_IS_ADDR_V4MAPPED(src_addr) && !IN6_IS_ADDR_V4MAPPED(dst_addr))
        return 0;

    if (!IN6_IS_ADDR_LINKLOCAL(src_addr) && IN6_IS_ADDR_LINKLOCAL(dst_addr))
        return 0;

    if (IN6_IS_ADDR_LINKLOCAL(src_addr) && !IN6_IS_ADDR_LINKLOCAL(dst_addr))
        return 0;

    return 1;
};

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

	HIP_IFE(!(entry->hip_msg_retrans.buf =
		  HIP_MALLOC(len + HIP_UDP_ZERO_BYTES_LEN, 0)), -ENOMEM);
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
 * Sends a HIP message using raw HIP from one source address. Don't use this
 * function directly. It's used by hip_send_raw internally.
 *
 * @see              hip_send_udp
 */
int hip_send_raw_from_one_src(struct in6_addr *local_addr, struct in6_addr *peer_addr,
			      in_port_t src_port, in_port_t dst_port,
			      struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
	int err = 0, sa_size, sent, len, dupl, try_again, udp = 0;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4, memmoved = 0;
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock_output = 0;

	_HIP_DEBUG("hip_send_raw() invoked.\n");

	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);

	HIP_DEBUG("Sending %s packet\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
	HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
	HIP_DUMP_MSG(msg);

	//check msg length
	if (!hip_check_network_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out_err;
	}

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

	if (dst_port && dst_is_ipv4) {
	        HIP_DEBUG("Using IPv4 UDP socket\n");
		hip_raw_sock_output = hip_nat_sock_output_udp;
		sa_size = sizeof(struct sockaddr_in);
		udp = 1;
	} else if (dst_is_ipv4) {
	        HIP_DEBUG("Using IPv4 raw socket\n");
		hip_raw_sock_output = hip_raw_sock_output_v4;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		HIP_DEBUG("Using IPv6 raw socket\n");
		hip_raw_sock_output = hip_raw_sock_output_v6;
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
	if (!udp)
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

	HIP_IFEL(bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size),
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

	if (udp) {
		struct udphdr *uh = (struct udphdr *) msg;

		/* Insert 32 bits of zero bytes between UDP and HIP */
		memmove(((char *)msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr), msg, len);
		memset(((char *) msg), 0, HIP_UDP_ZERO_BYTES_LEN  + sizeof(struct udphdr));
		len += HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);

		uh->source = htons(src_port);
		uh->dest = htons(dst_port);
		uh->len = htons(len);
		uh->check = 0;
		memmoved = 1;
	}

	_HIP_HEXDUMP("Dumping packet ", msg, len);

	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
		for (try_again = 0; try_again < 2; try_again++) {
			sent = sendto(hip_raw_sock_output, msg, len, 0,
				      (struct sockaddr *) &dst, sa_size);
			if (sent != len) {
				HIP_ERROR("Could not send the all requested"\
					  " data (%d/%d)\n", sent, len);
				HIP_DEBUG("strerror %s\n",strerror(errno));
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

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets. A better
	   solution would be to have separate sockets for sending
	   and receiving because we cannot receive a broadcast while
	   sending */
	if (dst_is_ipv4) {
		src4->sin_addr.s_addr = INADDR_ANY;
		src4->sin_family = AF_INET;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		struct in6_addr any = IN6ADDR_ANY_INIT;
		src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&src6->sin6_addr, &any);
		sa_size = sizeof(struct sockaddr_in6);
	}
	bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size);

	if (udp && memmoved) {
		/* Remove 32 bits of zero bytes between UDP and HIP */
		len -= HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr);
		memmove((char *) msg, ((char *)msg) + HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr),
			len);
		memset(((char *)msg) + len, 0,
		       HIP_UDP_ZERO_BYTES_LEN + sizeof(struct udphdr));
	}

	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}



/**
 * Sends a HIP message using User Datagram Protocol (UDP). From one address.
 * Don't use this function directly, instead use hip_send_pkt()
 *
 * Sends a HIP message to the peer on UDP/IPv4. IPv6 is not supported, because
 * there are no IPv6 NATs deployed in the Internet yet. If either @c local_addr
 * or @c peer_addr is pure (not a IPv4-in-IPv6 format IPv4 address) IPv6
 * address, no message is send. IPv4-in-IPv6 format IPv4 addresses are mapped to
 * pure IPv4 addresses. In case of transmission error, this function tries to
 * retransmit the packet @c HIP_NAT_NUM_RETRANSMISSION times. The HIP packet
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
 * @todo             Add support to IPv6 address family.
 * @see              hip_send_pkt
 */
int hip_send_udp_from_one_src(struct in6_addr *local_addr,
			      struct in6_addr *peer_addr,
			      in_port_t src_port, in_port_t dst_port,
			      struct hip_common *msg, hip_ha_t *entry,
			      int retransmit)
{
	return hip_send_raw_from_one_src(local_addr, peer_addr, src_port,
					 dst_port, msg, entry, retransmit);
}


/**
 * Sends a HIP message.
 *
 * Sends a HIP message to the peer on HIP/IP. This function calculates the
 * HIP packet checksum.
 *
 * Used protocol suite is <code>IPv4(HIP)</code> or <code>IPv6(HIP)</code>.
 *
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 *                   If local_addr is NULL, the packet is sent from all addresses.
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
int hip_send_pkt(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
    int err = 0;
    struct netdev_address *netdev_src_addr = NULL;
    struct in6_addr *src_addr = NULL;
    hip_list_t *item = NULL, *tmp = NULL;
    int i = 0;

    _HIP_DEBUG_IN6ADDR("Destination address:", peer_addr);

    /* Notice that the shotgun logic requires us to check always the address family.
     *  Depending on the address family, we send the packet using UDP encapsulation or
     *  without it. Here's the current logic for UDP encapsulation (note that we
     *  assume that the port number is always > 0 when nat mode is > 0):
     *
     *               | IPv4 address | IPv6 address |
     *  -------------+--------------+--------------+
     *  nat_mode = 0 |    NONE      |    NONE      |
     *  nat_mode > 0 |    UDP       |    NONE      |
     *
     */

    if (local_addr)
    {
	    if (IN6_IS_ADDR_V4MAPPED(peer_addr) && (hip_get_nat_mode(entry) != HIP_NAT_MODE_NONE || dst_port != 0)) {
		    return hip_send_udp_from_one_src(local_addr, peer_addr,
						     src_port, dst_port,
						     msg, entry, retransmit);
	    } else {
		    return hip_send_raw_from_one_src(local_addr, peer_addr,
						     src_port, dst_port,
						     msg, entry, retransmit);
	    }
    }

    list_for_each_safe(item, tmp, addresses, i)
    {
	    netdev_src_addr = list_entry(item);
	    src_addr = hip_cast_sa_addr(&netdev_src_addr->addr);
	    
	    if (!are_addresses_compatible(src_addr, peer_addr)) {
			continue;
	    }
            
	    HIP_DEBUG_IN6ADDR("Source address:", src_addr);
	    HIP_DEBUG_IN6ADDR("Dest address:", peer_addr);
	    
	    /* Notice: errors from sending are suppressed intentiously because they occur often */
	    if (IN6_IS_ADDR_V4MAPPED(peer_addr) &&
		   (hip_get_nat_mode(entry) != HIP_NAT_MODE_NONE || dst_port != 0)) {
		    hip_send_udp_from_one_src(src_addr, peer_addr,
					      src_port, dst_port,
					      msg, entry, retransmit);
	    } else {
		    hip_send_raw_from_one_src(src_addr, peer_addr,
					      src_port, dst_port,
					      msg, entry, retransmit);
	    }
    }

out_err:
    return err;
};

/**
 * This function sends ICMPv6 echo with timestamp to dsthit
 *
 * @param socket to send with
 * @param srchit HIT to send from
 * @param dsthit HIT to send to
 *
 * @return 0 on success negative on error
 */
int hip_send_icmp(int sockfd, hip_ha_t *entry) {
	int err = 0, i = 0, identifier = 0;
	struct icmp6hdr * icmph = NULL;
	struct sockaddr_in6 dst6;
	u_char cmsgbuf[CMSG_SPACE(sizeof (struct inet6_pktinfo))];
	u_char * icmp_pkt = NULL;
	struct msghdr mhdr;
	struct iovec iov[1];
	struct cmsghdr * chdr;
	struct inet6_pktinfo * pkti;
	struct timeval tval;

	HIP_IFEL(!entry, 0, "No entry\n");

	HIP_IFEL((entry->outbound_sa_count == 0), 0,
		 "No outbound sa, ignoring keepalive\n")

	_HIP_DEBUG("Starting to send ICMPv6 heartbeat\n");

	/* memset and malloc everything you need */
	memset(&mhdr, 0, sizeof(struct msghdr));
	memset(&tval, 0, sizeof(struct timeval));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(iov, 0, sizeof(struct iovec));
	memset(&dst6, 0, sizeof(dst6));

	icmp_pkt = malloc(HIP_MAX_ICMP_PACKET);
	HIP_IFEL((!icmp_pkt), -1, "Malloc for icmp_pkt failed\n");
	memset(icmp_pkt, 0, sizeof(HIP_MAX_ICMP_PACKET));

	chdr = (struct cmsghdr *)cmsgbuf;
	pkti = (struct inet6_pktinfo *)(CMSG_DATA(chdr));

	identifier = getpid() & 0xFFFF;

	/* Build ancillary data */
	chdr->cmsg_len = CMSG_LEN (sizeof (struct inet6_pktinfo));
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	memcpy(&pkti->ipi6_addr, &entry->hit_our, sizeof(struct in6_addr));

	/* get the destination */
	memcpy(&dst6.sin6_addr, &entry->hit_peer, sizeof(struct in6_addr));
	dst6.sin6_family = AF_INET6;
	dst6.sin6_flowinfo = 0;

	/* build icmp header */
	icmph = (struct icmp6hdr *)icmp_pkt;
	icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmph->icmp6_code = 0;
	entry->heartbeats_sent++;

	icmph->icmp6_sequence = htons(entry->heartbeats_sent);
	icmph->icmp6_identifier = identifier;

	gettimeofday(&tval, NULL);

	memset(&icmp_pkt[8], 0xa5, HIP_MAX_ICMP_PACKET - 8);
 	/* put timeval into the packet */
	memcpy(&icmp_pkt[8], &tval, sizeof(struct timeval));

	/* put the icmp packet to the io vector struct for the msghdr */
	iov[0].iov_base = icmp_pkt;
	iov[0].iov_len  = sizeof(struct icmp6hdr) + sizeof(struct timeval);

	/* build the msghdr for the sendmsg, put ancillary data also*/
	mhdr.msg_name = &dst6;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = &cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);

	i = sendmsg(sockfd, &mhdr, 0);
	if (i <= 0)
		HIP_PERROR("sendmsg");

	/* Debug information*/
	_HIP_DEBUG_HIT("src hit", &entry->hit_our);
	_HIP_DEBUG_HIT("dst hit", &entry->hit_peer);
	_HIP_DEBUG("i == %d socket = %d\n", i, sockfd);
	HIP_PERROR("SENDMSG ");

	HIP_IFEL((i < 0), -1, "Failed to send ICMP into ESP tunnel\n");
	HIP_DEBUG_HIT("Succesfully sent heartbeat to", &entry->hit_peer);

out_err:
	if (icmp_pkt)
		free(icmp_pkt);
	return err;
}
