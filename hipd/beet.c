#include "beet.h"

int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr) {
	struct hip_work_order req, resp;

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
			    HIP_WO_SUBTYPE_XFRM_INIT, dst_hit, dst_addr, 0, 0);
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

int hip_xfrm_update(uint32_t spi, struct in6_addr * dst_addr, int state,
		    int dir) {
  	struct hip_work_order req, resp;

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_UPD,
				(struct in6_addr *)&state, dst_addr, spi, dir);
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

int hip_xfrm_delete(uint32_t spi, struct in6_addr * hit, int dir) {
  	struct hip_work_order req, resp;
	
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_DEL, hit, NULL, spi, dir);
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

int hip_xfrm_get_src_hit(hip_hit_t *src_hit, const hip_hit_t *dst_hit)
{
	return -1; // XX FIXME
}
