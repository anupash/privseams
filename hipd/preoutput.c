#include "preoutput.h"

/* Called by userspace daemon to send a packet to wire */
#ifndef CONFIG_HIP_HI3
// FIXME: This ifdef will be removed once the handler support is a bit more generic in hidb.
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf)
{
	struct hip_work_order hwo;
	HIP_INIT_WORK_ORDER_HDR(hwo.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_SEND_PACKET, src_addr,
				peer_addr, NULL, 0, 0, 0);
	hwo.msg = buf;
	return hip_netlink_send(&hwo);
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

	msg->checksum = htons(0);
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

