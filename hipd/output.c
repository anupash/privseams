/*
 * HIP output
 *
 * Licence: GNU/GPL
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 */

#include "output.h"

/**
 * hip_send_i1 - send an I1 packet to the responder
 * @param entry the HIP database entry reserved for the peer
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * @return 0 on success, otherwise < 0 on error.
 */
int hip_send_i1(hip_hit_t *src_hit, hip_hit_t *dst_hit, hip_ha_t *entry)
{
	struct hip_common i1;
	struct in6_addr daddr;
	int mask = 0;
	int err = 0;

#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
		mask |= HIP_CONTROL_RVS_CAPABLE;
#endif

	/* Assign a local private key, public key and HIT to HA */
	HIP_IFEL(hip_init_us(entry, src_hit), -EINVAL,
		 "Could not assign a local host id\n");

	entry->hadb_misc_func->hip_build_network_hdr((struct hip_common* ) &i1,
						     HIP_I1,
						     mask, &entry->hit_our,
						     dst_hit);
	/* Eight octet units, not including first */
	i1.payload_len = (sizeof(struct hip_common) >> 3) - 1;

	HIP_HEXDUMP("HIT source", &i1.hits, sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT dest", &i1.hitr, sizeof(struct in6_addr));

	HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1, 
		 "No preferred IP address for the peer.\n");
#ifdef CONFIG_HIP_OPPORTUNISTIC
	// if hitr is hashed null hit, send it as null on the wire
	if(hit_is_opportunistic_hashed_hit(&i1.hitr))
		ipv6_addr_copy(&i1.hitr, &in6addr_any);
	
	_HIP_HEXDUMP("dest hit on wire", &i1.hitr, sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &daddr, sizeof(struct in6_addr));
#endif // CONFIG_HIP_OPPORTUNISTIC
	
	err = entry->hadb_xmit_func->hip_csum_send(&entry->local_address,
						   &daddr,0,0, 
						   /* Kept 0 as src and dst port. This should be taken out from entry --Abi*/
						   (struct hip_common*) &i1,
						   entry, 1);
	HIP_DEBUG("err = %d\n", err);
	if (!err) {
		HIP_LOCK_HA(entry);
		entry->state = HIP_STATE_I1_SENT;
		HIP_UNLOCK_HA(entry);
	}
	else if (err == 1) err = 0;

out_err:
	return err;
}

/**
 * hip_create_r1 - construct a new R1-payload
 * @param src_hit source HIT used in the packet
 *
 * Returns 0 on success, or negative on error
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit, 
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *host_id_priv,
				 const struct hip_host_id *host_id_pub,
				 int cookie_k)
{
 	HIP_DEBUG("hip_create_r1() invoked.\n");
	struct hip_common *msg;
 	int err = 0,dh_size,written, mask;
 	u8 *dh_data = NULL;
 	/* Supported HIP and ESP transforms. */
 	hip_transform_suite_t transform_hip_suite[] = {
		HIP_HIP_AES_SHA1,
		HIP_HIP_3DES_SHA1,
		HIP_HIP_NULL_SHA1
	};
 	hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_3DES_SHA1,
		HIP_ESP_AES_SHA1,
		HIP_ESP_NULL_SHA1
	};
	//	struct hip_host_id  *host_id_pub = NULL;
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

 	/* Allocate memory for writing Diffie-Hellman shared secret */
	HIP_IFEL((dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID)) == 0, 
		 -1, "Could not get dh size\n");
	HIP_IFEL(!(dh_data = HIP_MALLOC(dh_size, GFP_ATOMIC)), 
		 -1, "Failed to alloc memory for dh_data\n");
	memset(dh_data, 0, dh_size);

	_HIP_DEBUG("dh_size=%d\n", dh_size);
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
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
					42 /* 2^(42-32) sec lifetime */, 
					0, 0),  -1, 
		 "Cookies were burned. Bummer!\n");

 	/********** Diffie-Hellman **********/
	HIP_IFEL((written = hip_insert_dh(dh_data, dh_size,
					  HIP_DEFAULT_DH_GROUP_ID)) < 0,
		 -1, "Could not extract DH public key\n");
	
	HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
							 HIP_DEFAULT_DH_GROUP_ID,
							 dh_data, written), -1,
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

	/* REG_INFO */
	/* @todo Get service-list from some function which lists all services
	   offered by this system. */
	
	int *list;
	int count = 0;
		
	count = hip_get_services_list(&list);
	
	HIP_DEBUG("Amount of services is %d.\n", count);
	
	int i;
	for (i = 0; i < count; i++) {
		HIP_DEBUG("Service is %d.\n", list[i]);
	}
	
	if (count > 0) {
		HIP_DEBUG("Adding REG_INFO parameter.\n");
		/** @todo Min and max lifetime of registration. */
		HIP_IFEL(hip_build_param_reg_info(msg,  0, 0, list, count), -1, 
		 	"Building of reg_info failed\n");	
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
 	if (dh_data)
 		HIP_FREE(dh_data);

	//HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	//	if (host_id_pub)
	//	HIP_FREE(host_id_pub);
 	if (msg)
 		HIP_FREE(msg);
 	if (dh_data)
 		HIP_FREE(dh_data);

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
int hip_xmit_r1(struct in6_addr *i1_saddr,
		struct in6_addr *i1_daddr,
		struct in6_addr *src_hit, 
		struct in6_addr *dst_ip,
		struct in6_addr *dst_hit, 
		struct hip_stateless_info *i1_info,
		const struct in6_addr *traversed_rvs,
		const int rvs_count)
{
	HIP_DEBUG("hip_xmit_r1() invoked.\n");

	struct hip_common *r1pkt = NULL;
	struct in6_addr *own_addr, *dst_addr;
	int err = 0;

	own_addr = i1_daddr;

	/* Get the destination address. */
	dst_addr = (!dst_ip || ipv6_addr_any(dst_ip) ? i1_saddr : dst_ip);

	/* dst_addr is the IP address of the Initiator... */
#ifdef CONFIG_HIP_OPPORTUNISTIC
	// it sould not be null hit, null hit has been replaced by real local hit
	HIP_DEBUG_HIT("src_hit ", src_hit);
	HIP_ASSERT(!hit_is_opportunistic_hashed_hit(src_hit));
#endif
	HIP_DEBUG_HIT("hip_xmit_r1(): Source hit", src_hit);
	HIP_DEBUG_HIT("hip_xmit_r1(): Destination hit", dst_hit);
	HIP_DEBUG_HIT("hip_xmit_r1(): Own address", own_addr);
	HIP_DEBUG_HIT("hip_xmit_r1(): Destination address", dst_addr);
	HIP_IFEL(!(r1pkt = hip_get_r1(dst_addr, own_addr, src_hit, dst_hit)), -ENOENT, 
		 "No precreated R1\n");

	if (dst_hit)
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));
	HIP_DEBUG_HIT("hip_xmit_r1(): ripkt->hitr", &r1pkt->hitr);
	
	/* Build VIA_RVS parameter if the I1 packet was relayed through a rvs. */
#ifdef CONFIG_HIP_RVS
	if(rvs_count > 0)
	{
		/** @todo Parameters must be in ascending order, should this
		    be checked here? */
		hip_build_param_via_rvs(r1pkt, traversed_rvs, rvs_count);
	}
#endif
	HIP_DUMP_MSG(r1pkt);

	/* set cookie state to used (more or less temporary solution ?) */
	_HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));
	/* Here we reverse the src port and dst port !! For obvious reason ! --Abi*/
	HIP_IFEL(hip_csum_send(own_addr, dst_addr, i1_info->dst_port,
			       i1_info->src_port, r1pkt, NULL, 0), -1, 
		 "hip_xmit_r1 failed.\n");

 out_err:
	if (r1pkt)
		HIP_FREE(r1pkt);
	return err;
}

void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet;
	struct in6_addr daddr;

	HIP_IFE(!(notify_packet = hip_msg_alloc()), -ENOMEM);
	entry->hadb_misc_func->hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
			      &entry->hit_our, &entry->hit_peer);
	HIP_IFEL(hip_build_param_notify(notify_packet, 1234, "ABCDEFGHIJ", 10), 0, 
		 "Building of NOTIFY failed.\n");

        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), 0);
	entry->hadb_xmit_func->hip_csum_send(NULL, &daddr, 0,0, notify_packet,
					     entry, 0);

 out_err:
	if (notify_packet)
		HIP_FREE(notify_packet);
	return;
}

struct hip_rea_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

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


int hip_queue_packet(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		     struct hip_common* msg, hip_ha_t *entry)
{
	int err = 0;
	int len = hip_get_msg_total_len(msg);

	HIP_IFE(!(entry->hip_msg_retrans.buf = HIP_MALLOC(len, 0)), -1);
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

int hip_csum_send(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		  in_port_t src_port, in_port_t dst_port, struct hip_common *msg,
		  hip_ha_t *entry, int retransmit)
{
	HIP_DEBUG("hip_csum_send() invoked.\n");
	HIP_DEBUG_IN6ADDR("hip_csum_send(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_csum_send(): peer_addr", peer_addr);
	HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);

	int err = 0, sa_size, sent, len, dupl, try_bind_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock = 0;
	
	if(entry) {
		HIP_DEBUG("NAT status %d\n", entry->nat_between);
	}
	
	if ((hip_nat_status && dst_is_ipv4)|| (dst_is_ipv4 && 
					       ((entry && entry->nat_between) ||
						(src_port != 0 || dst_port != 0))))
		
	{
		return hip_nat_send_udp(local_addr, peer_addr,
					src_port, dst_port, msg, entry, retransmit);
		
	} 
	
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

	HIP_ASSERT(peer_addr);

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
		err = -1;
		HIP_ERROR("Source and destination address families differ\n");
		goto out_err;
	}

	hip_zero_msg_checksum(msg);
	msg->checksum = checksum_packet((char*)msg, &src, &dst);

	if (!retransmit && hip_get_msg_type(msg) == HIP_I1)
	{
		HIP_DEBUG("Retransmit of I1, no filtering required.\n");
		err = -ENOENT;
	}
	else if (entry)
	{
		err = entry->hadb_output_filter_func->hip_output_filter(msg);
	}
	else
	{
		err = ((hip_output_filter_func_set_t *)hip_get_output_filter_default_func_set())->hip_output_filter(msg);
	}

	if (err == -ENOENT)
	{
		err = 0;
	}
	else if (err == 0)
	{
		HIP_DEBUG("Agent accepted the packet.\n");
	}
	else if (err == 1)
	{
		HIP_DEBUG("Agent is waiting user action, setting entry state to HIP_STATE_FILTERING.\n");
		HIP_IFEL(hip_queue_packet(&my_addr, peer_addr,
					  msg, entry), -1, "queue failed\n");
		err = 1;
		entry->state = HIP_STATE_FILTERING;
		HIP_HEXDUMP("HA: ", entry, 4);
		goto out_err;
	}
	else if (err == 2)
	{
		HIP_DEBUG("Recreating entries, because agent changed local HIT.\n");
		struct in6_addr addr;
		memcpy(&addr, &entry->preferred_address, sizeof(addr));
		HIP_IFEL(hip_hadb_del_peer_map(&entry->hit_peer), -1, "hip_del_peer_map failed!\n");
		HIP_IFEL(hip_hadb_add_peer_info(&msg->hits, &addr), -1, "hip_hadb_add_peer_info failed!\n");
		HIP_IFEL(entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr), -1, "hip_hadb_find_byhits failed!\n");
	}
	else if (err)
	{
		HIP_ERROR("Agent reject packet\n");
		err = -1;
	}	

	/* Note! that we need the original (possibly mapped addresses here.
	   Also, we need to do queuing before the bind because the bind
	   can fail the first time during mobility events (duplicate address
	   detection). */
	if (retransmit)
		HIP_IFEL(hip_queue_packet(&my_addr, peer_addr,
					  msg, entry), -1, "queue failed\n");

	/* Required for mobility; ensures that we are sending packets from
	   the correct source address */
	for (try_bind_again = 0; try_bind_again < 2; try_bind_again++) {
		err = bind(hip_raw_sock, (struct sockaddr *) &src, sa_size);
		if (err == EADDRNOTAVAIL) {
			HIP_DEBUG("Binding failed 1st time, trying again\n");
			HIP_DEBUG("First, sleeping a bit (duplicate address detection)\n");
			sleep(4);
		} else {
			break;
		}
	}
	HIP_IFEL(err, -1, "Binding to raw sock failed\n");
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
		sent = sendto(hip_raw_sock, msg, len, 0,
			      (struct sockaddr *) &dst, sa_size);
		HIP_IFEL((sent != len), -1,
			 "Could not send the all requested data (%d/%d)\n",
			 sent, len);
	}
	HIP_DEBUG("sent=%d/%d ipv4=%d\n", sent, len, dst_is_ipv4);
	HIP_DEBUG("Packet sent ok\n");

 out_err:
	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}

#ifdef CONFIG_HIP_HI3
/*
 * The callback for i3 "no matching id" callback.
 * FIXME: tkoponen, Should this somehow trigger the timeout for waiting outbound traffic (state machine)?
 */
static void no_matching_trigger(void *ctx_data, void *data, void *fun_ctx) {
	char id[32];
	sprintf_i3_id(id, (ID *)ctx_data);
	
	HIP_ERROR("Following ID not found: %s", id);
}

/* Hi3 outbound traffic processing */
/* XX FIXME: For now this supports only serialiazation of IPv6 addresses to Hi3 header */
/* XX FIXME: this function is outdated. Does not support in6 mapped addresses
   and retransmission queues -mk */
int hip_csum_send_i3(struct in6_addr *src_addr, 
		  struct in6_addr *peer_addr,
		  struct hip_common *msg)
{
	ID id;
	cl_buf *clb;
  	u16 csum;	
	int err, msg_len, hdr_dst_len, hdr_src_len;
	struct sockaddr_in6 src, dst;
	struct hi3_ipv6_addr hdr_src, hdr_dst;
	char *buf;

	/* This code is outdated. Synchronize to the non-hi3 version */

	if (!src_addr) {
		// FIXME: Obtain the preferred address
		HIP_ERROR("No source address.\n");
		return -1;
	}

	if (!peer_addr) {
		// FIXME: Just ignore?
		HIP_ERROR("No destination address.\n");
		return -1;
	}

	/* Construct the Hi3 header, for now IPv6 only */
	hdr_src.sin6_family = AF_INET6;
	hdr_src_len = sizeof(struct hi3_ipv6_addr);
	memcpy(&hdr_src.sin6_addr, src_addr, sizeof(struct in6_addr));
	hdr_dst.sin6_family = AF_INET6;
	hdr_dst_len = sizeof(struct hi3_ipv6_addr);
	memcpy(&hdr_dst.sin6_addr, peer_addr, sizeof(struct in6_addr));
	/* IPv6 specific code ends */

	msg_len = hip_get_msg_total_len(msg);
	clb = cl_alloc_buf(msg_len + hdr_dst_len + hdr_src_len);
	if (!clb) {
		HIP_ERROR("Out of memory\n.");
		return -1;
	}

	hip_zero_msg_checksum(msg);
	msg->checksum = checksum_packet((char *)msg, 
					(struct sockaddr *)&src, 
					(struct sockaddr *)&dst);

	buf = clb->data;
	memcpy(buf, &hdr_src, hdr_src_len);
	buf += hdr_src_len;
	memcpy(buf, &hdr_dst, hdr_dst_len);
	buf += hdr_dst_len;
  
	memcpy(buf, msg, msg_len);

	/* Send over i3 */
	bzero(&id, ID_LEN);
	memcpy(&id, &msg->hitr, sizeof(struct in6_addr));
	cl_set_private_id(&id);

	/* exception when matching trigger not found */
	cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);
	cl_send(&id, clb, 0);  
	cl_free_buf(clb);
	
 out_err:
	return err;
}
#endif
