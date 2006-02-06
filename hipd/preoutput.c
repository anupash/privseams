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
	entry->hip_msg_retrans.count = HIP_RETRANSMISSION_MAX;

 out_err:
	return err;
}

#ifndef CONFIG_HIP_HI3
// FIXME: This ifdef will be removed once the handler support is a bit more generic in hidb.
int hip_csum_send(struct in6_addr *src_addr,
		  struct in6_addr *peer_addr,
		  struct hip_common* msg,
		  hip_ha_t *entry,
		  int retransmit)
{
	int err = 0, ret, len = hip_get_msg_total_len(msg);
	struct sockaddr_in6 src, dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	HIP_ASSERT(peer_addr);

	if (!src_addr) {
		HIP_IFEL(hip_select_source_address(&src.sin6_addr,
						   peer_addr), -1,
			 "Cannot find source address\n");
	} else {
		memcpy(&src.sin6_addr, src_addr, sizeof(struct in6_addr));
	}

	/* The source address is needed for m&m stuff. However, I am not sure
	   if the binding is a good thing; the source address is then fixed
	   instead of the host default (remember that we are using a global
	   raw socket). This can screw up things. */

#if 0
	HIP_DEBUG_IN6ADDR("src", &src.sin6_addr);
	HIP_IFEL((bind(hip_raw_sock, (struct sockaddr *) &src,
		       sizeof(src)) < 0), -1,
		 "Binding to raw sock failed\n");

	_HIP_DEBUG_IN6ADDR("dst", peer_addr);
#endif

	memcpy(&dst.sin6_addr, peer_addr, sizeof(struct in6_addr));

	HIP_DEBUG_IN6ADDR("src", &src.sin6_addr);
	HIP_DEBUG_IN6ADDR("dst", &dst.sin6_addr);

	hip_zero_msg_checksum(msg);
	msg->checksum = checksum_packet((char *)msg, 
					(struct sockaddr *)&src, 
					(struct sockaddr *)&dst);

	err = hip_agent_filter(msg);
	if (err == -ENOENT) {
		HIP_DEBUG("No agent running, continuing\n");
		err = 0;
        } else if (err == 0) {
		HIP_DEBUG("Agent accepted packet\n");
	} else if (err) {
		HIP_ERROR("Agent reject packet\n");
		err = -1;
	}	


#if 0
        HIP_IFEL((connect(hip_raw_sock, (struct sockaddr *) &dst,
			  sizeof(dst)) < 0),
		 -1, "Connecting of raw sock failed\n");
#endif

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work. */
	HIP_IFEL((sendto(hip_raw_sock, msg, len, 0, (struct sockaddr *) &dst,
			 sizeof(dst)) != len), -1,
		 "Sending of HIP msg failed\n");

	HIP_DEBUG("Packet sent ok\n");

	if (retransmit)
		err = hip_queue_packet(src_addr, peer_addr, msg, entry);
 out_err:
	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}

#else
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
/* FIXME: For now this supports only serialiazation of IPv6 addresses to Hi3 header */
int hip_csum_send(struct in6_addr *src_addr, 
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

