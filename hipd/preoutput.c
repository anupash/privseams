#include "preoutput.h"

/* Called by userspace daemon to send a packet to wire */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf)
{
	struct hip_work_order hwo;
	hwo.hdr.type = HIP_WO_TYPE_OUTGOING;
	hwo.hdr.subtype = HIP_WO_SUBTYPE_SEND_PACKET;
	ipv6_addr_copy(&hwo.hdr.src_addr, src_addr);
	ipv6_addr_copy(&hwo.hdr.dst_addr, peer_addr);
	hwo.msg = buf;
	return hip_netlink_send(&hwo);
}

