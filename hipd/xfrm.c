#include "xfrm.h"
#include "debug.h"

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	struct hip_work_order req, resp;
	int err = 0;

	resp.msg = NULL;
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_DELSA, NULL, dst, NULL, 
				spi, 0, 0);
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
				dsthit, NULL, 0, 0, 0);
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

/* Security associations in the kernel with BEET are bounded to the outer address, 
 * meaning IP addresses. As a result the parameters to be given should be such 
 * an addresses and not the HITs.
 */
uint32_t hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		    uint32_t spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
		    int already_acquired, int direction) {
	struct hip_work_order req, resp;
	int err;
	req.msg = NULL;
	resp.msg = NULL;
	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_ADDSA, srchit, dsthit, NULL,
				0, 0, 0);
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


int hip_setup_sp() {
	/* The OUTGOING and INCOMING policy is set to the generic value */
	/* FIXME: this function is used also for testing the SAs tools are correct */
	struct in6_addr saddr, daddr;
	struct hip_crypto_key enckey;
	struct hip_crypto_key authkey;

	char *temp1 = "0xc0291ff014dccd";
	char *temp2 = "0x0123456789";

	memset(&saddr, 0, sizeof(struct in6_addr));
	memset(&daddr, 0, sizeof(struct in6_addr));
#if 0
	saddr.s6_addr32[0] = htonl(0x40000000);
	daddr.s6_addr32[0] = htonl(0x40000000);

	hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, &daddr, &saddr, NULL, NULL, XFRM_POLICY_IN);
	hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, &saddr, &daddr, NULL, NULL, XFRM_POLICY_OUT);

	/* This is just an example of how to delete SPs, but it must not done in here */
	HIP_DEBUG("deleting SPs....\n");
	hip_xfrm_policy_delete(&daddr, &saddr, XFRM_POLICY_IN);
	hip_xfrm_policy_delete(&saddr, &daddr, XFRM_POLICY_OUT);
#endif
	/*FIXME: this is a test part used to set the SA and check that it works as it should. */
	saddr.s6_addr32[0] = htonl(0x3ffe0001);
	daddr.s6_addr32[0] = htonl(0x3ffe0002);
	
	memset(enckey.key, 0, HIP_MAX_KEY_LEN);
	memset(authkey.key, 0, HIP_MAX_KEY_LEN);


	memcpy(enckey.key, temp1, HIP_MAX_KEY_LEN);
	memcpy(authkey.key, temp2, HIP_MAX_KEY_LEN);

	hip_xfrm_state_modify(XFRM_MSG_NEWSA, &saddr, &daddr, 
			      23, 1, &enckey, 2, &authkey);

	return 0;
}
