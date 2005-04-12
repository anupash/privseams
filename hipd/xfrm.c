#include "xfrm.h"
#include "debug.h"

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	struct hip_work_order req, resp;

	INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_DELSA, NULL, dst, spi, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}
	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	struct hip_work_order req, resp;

	INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_ACQSPI, srchit, dsthit, 0, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}

int hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
	       uint32_t *spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
	       int already_acquired, int direction) {
	struct hip_work_order req, resp;

	INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_ADDSA, srchit, dsthit, 0, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}	

	hip_build_user_hdr(req.msg, 0, 0);
	if (hip_build_param_keys(req.msg, enckey, authkey, *spi, alg, already_acquired, direction)) {
		return -1;
	}

	if (!hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}

int hip_finalize_sa(struct in6_addr *hit, u32 spi) {
	struct hip_work_order req, resp;

	INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_FINSA, NULL, hit, spi, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}

