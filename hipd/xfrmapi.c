#include "xfrmapi.h"

#include "netlink.h"

static int hip_get_response(void) {
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
	ret = hip_netlink_send(&req);
	if (!ret) {
		return ret;
	}

	return hip_get_response();
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_ACQSPI;
	ipv6_addr_copy(&req.hdr.dst_addr, dsthit);	
	ipv6_addr_copy(&req.hdr.src_addr, srchit);
	if (!hip_netlink_send(&req)) {
		return 0;
	}
	
	return hip_get_response();
}

int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
                 uint32_t *spi, int alg, void *enckey, void *authkey,
                 int already_acquired, int direction) {
	HIP_ERROR("Not implemented!");
	return 0;
}

void hip_finalize_sa(struct in6_addr *hit, u32 spi) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_FINSA;
	ipv6_addr_copy(&req.hdr.dst_addr, hit);
	req.hdr.arg1 = spi;
	if (!hip_netlink_send(&req)) {
		HIP_ERROR("Unable to send over netlink");
	}

	 hip_get_response();
}
