#include "xfrmapi.h"

#include "netlink.h"

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_DELSA;
	ipv6_addr_copy(&req.hdr.dst_addr, dst);
	req.hdr.arg1 = spi;
	return hip_netlink_send(&req);
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	struct hip_work_order req;
	struct hip_work_order * resp;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_ACQSPI;
	ipv6_addr_copy(&req.hdr.dst_addr, dsthit);	
	ipv6_addr_copy(&req.hdr.src_addr, srchit);
	if (!hip_netlink_send(&req)) {
		return 0;
	}

        resp = hip_netlink_receive();
	if (!resp) {
		return 0;
	}

	return resp->hdr.arg1;
}

int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
                 uint32_t *spi, int alg, void *enckey, void *authkey,
                 int already_acquired, int direction) {
	return 0;
}

void hip_finalize_sa(struct in6_addr *hit, u32 spi) {
	struct hip_work_order req;

	req.hdr.type = HIP_WO_TYPE_OUTGOING;
	req.hdr.subtype = HIP_WO_SUBTYPE_FINSA;
	ipv6_addr_copy(&req.hdr.dst_addr, hit);
	req.hdr.arg1 = spi;
	return hip_netlink_send(&req);
}
