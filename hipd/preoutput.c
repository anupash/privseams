#include "preoutput.h"

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

 out_err:
	return err;
}

int hip_csum_send(struct in6_addr *local_addr,
		  struct in6_addr *peer_addr,
		  uint32_t src_port, uint32_t dst_port,
		  struct hip_common *msg,
		  hip_ha_t *entry,
		  int retransmit)
{
	int err = 0, sa_size, sent, len, dupl, try_bind_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	int hip_raw_sock = 0; /* Points either to v4 or v6 raw sock */

	if (local_addr)
		HIP_DEBUG_IN6ADDR("local_addr", local_addr);
	if (peer_addr)
		HIP_DEBUG_IN6ADDR("peer_addr", peer_addr);

	if ((hip_nat_status && dst_is_ipv4)|| (dst_is_ipv4 && 
		((entry && entry->nat) ||
		 (src_port != 0 || dst_port != 0))))//Temporary fix 
	//if(dst_is_ipv4)// && entry->nat) //Will set this later --Abi
	{
		return hip_send_udp(local_addr, peer_addr,
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

	if (entry)
		err = entry->hadb_output_filter_func->hip_output_filter(msg);
	else
		err = ((hip_output_filter_func_set_t *)hip_get_output_filter_default_func_set())->hip_output_filter(msg);

	if (err == -ENOENT) {
		HIP_DEBUG("No agent running, continuing\n");
		err = 0;
        } else if (err == 0) {
		HIP_DEBUG("Agent accepted packet\n");
	} else if (err) {
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
		HIP_DEBUG("Packet was lost (simulation)\n");
		goto out_err;
	}

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work properly. Thus, we use just sendto() */
	
	len = hip_get_msg_total_len(msg);
	HIP_HEXDUMP("Dumping packet ", msg, len);
	
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

