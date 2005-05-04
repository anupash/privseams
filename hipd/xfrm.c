#include "xfrm.h"
#include "debug.h"

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	struct hip_work_order req, resp;
	int err = 0;

	resp.msg = NULL;
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_DELSA, NULL, dst, spi, 0, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		err = -1;
		goto out;
	}
	hip_build_user_hdr(req.msg, 0, 0);

	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink\n");
		err = 0;
		goto out;
	}

	err = resp.hdr.arg1;
out:
	if (req.msg)
		hip_msg_free(req.msg);
	if (resp.msg)
		hip_msg_free(resp.msg);

	return err;
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	struct hip_work_order req, resp;
	int err = 0;

	resp.msg = NULL;
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_ACQSPI, srchit,
				dsthit, 0, 0, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		err = -1;
		goto out;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink\n");
		err = 0;
		goto out;
	}

	err = resp.hdr.arg1;
out:
	if (req.msg)
		hip_msg_free(req.msg);
	if (resp.msg)
		hip_msg_free(resp.msg);

	return err;
}

uint32_t hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		    uint32_t spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
		    int already_acquired, int direction) {
	struct hip_work_order req, resp;
	int err;
	req.msg = NULL;
	resp.msg = NULL;

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_ADDSA, srchit, dsthit, 0, 0, 0);
	HIP_IFE(!(req.msg = hip_msg_alloc()), 0);

	hip_build_user_hdr(req.msg, 0, 0);
	HIP_IFE(hip_build_param_keys(req.msg, enckey, authkey, spi, alg, already_acquired, direction), 0);
	HIP_IFEL(hip_netlink_talk(&nl_khipd, &req, &resp), 0, "Unable to send over netlink\n");

	err = resp.hdr.arg1;

 out_err:
	if (req.msg)
		hip_msg_free(req.msg);
	if (resp.msg)
		hip_msg_free(resp.msg);

	return err;
}
