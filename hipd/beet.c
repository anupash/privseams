#include "beet.h"

int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr) {
	struct hip_work_order req;
	
	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_XFRM_INIT;	
	ipv6_addr_copy(&req.hdr.dst_addr, dst_addr);
	ipv6_addr_copy(&req.hdr.src_addr, dst_hit);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
		return -1;
	}

	hip_msg_free(req.msg);

	return hip_get_response();
}

int hip_xfrm_update(uint32_t spi, struct in6_addr * dst_addr, int state,
		    int dir) {
  	struct hip_work_order req;
	
	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_XFRM_UPD;
	ipv6_addr_copy(&req.hdr.dst_addr, dst_addr);
	req.hdr.arg1 = spi;
	*((int *)(&req.hdr.src_addr)) = state;
	req.hdr.arg2 = dir;
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
		return -1;
	}

	hip_msg_free(req.msg);

	return hip_get_response();
}

int hip_xfrm_delete(uint32_t spi, struct in6_addr * hit, int dir) {
  	struct hip_work_order req;
	
	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_XFRM_DEL;
	ipv6_addr_copy(&req.hdr.src_addr, hit);
	req.hdr.arg1 = spi;
	req.hdr.arg2 = dir;
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
		return -1;
	}

	hip_msg_free(req.msg);

	return hip_get_response();
}

