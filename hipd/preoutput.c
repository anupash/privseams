#include "preoutput.h"

/* Called by userspace daemon to send a packet to wire */
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
                     struct hip_common* buf)
{
	struct hip_work_order hwo;
	hwo.hdr.type = HIP_WO_TYPE_OUTGOING;
	hwo.hdr.subtype = HIP_WO_SUBTYPE_SEND_PACKET;
	memcpy(&hwo.hdr.src_addr, src_addr, sizeof(struct in6_addr));
	memcpy(&hwo.hdr.dst_addr, peer_addr, sizeof(struct in6_addr));	
	hwo.msg = buf;
	return hip_netlink_send(&hwo);
}

