#include "xfrm.h"
#include "debug.h"

int hip_get_response(void) {
	struct hip_work_order * resp;
	int ret; 

        resp = hip_netlink_receive();
	if (!resp) {
		return 0;

	}

	ret =  resp->hdr.arg1;
	hip_free_work_order(resp);
	return ret;
}

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	struct hip_work_order req;
	int ret;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_DELSA;
	ipv6_addr_copy(&req.hdr.dst_addr, dst);
	req.hdr.arg1 = spi;
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}
	hip_build_user_hdr(req.msg, 0, 0);

	ret = hip_netlink_send(&req);
	if (!ret) {
		HIP_ERROR("Unable to send over netlink");
		return ret;
	}

	hip_msg_free(req.msg);

	return hip_get_response();
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_ACQSPI;
	ipv6_addr_copy(&req.hdr.dst_addr, dsthit);	
	ipv6_addr_copy(&req.hdr.src_addr, srchit);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
		return 0;
	}

	hip_msg_free(req.msg);
	
	return hip_get_response();
}

int hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
	       uint32_t *spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
	       int already_acquired, int direction) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_ADDSA;
	ipv6_addr_copy(&req.hdr.dst_addr, dsthit);	
	ipv6_addr_copy(&req.hdr.src_addr, srchit);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}	

	hip_build_user_hdr(req.msg, 0, 0);
	if (hip_build_param_keys(req.msg, enckey, authkey, *spi, alg, already_acquired, direction)) {
		return -1;
	}
	
	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
		return -1;
	}
	
	hip_msg_free(req.msg);

	return hip_get_response();
}

int hip_finalize_sa(struct in6_addr *hit, u32 spi) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_FINSA;
	ipv6_addr_copy(&req.hdr.dst_addr, hit);
	req.hdr.arg1 = spi;
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


