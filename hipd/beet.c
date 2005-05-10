#include "beet.h"

#if 0
int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr) {
	struct hip_work_order req, resp;

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_INIT, dst_hit, dst_addr, 
				NULL, 0, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}
#endif
int hip_xfrm_update(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
		    struct in6_addr *addr, uint32_t spi,
		    int state, int dir) {
  	struct hip_work_order req, resp;

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_UPD,
				hit_peer, hit_our, addr, spi, state, dir);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink\n");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}

int hip_xfrm_delete(hip_hit_t * hit, uint32_t spi, int dir) {
  	struct hip_work_order req, resp;
	
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_DEL, hit, NULL, NULL,
				spi, dir, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink\n");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}
