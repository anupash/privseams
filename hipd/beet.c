#include "beet.h"

/**
 * hip_xfrm_policy_modify - modify the Security Policy
 * @cmd: command. %XFRM_MSG_NEWPOLICY | %XFRM_MSG_UPDPOLICY
 * @hit_our: Source HIT
 * @hit_peer: Peer HIT
 * @tmpl_saddr: source IP address
 * @tmpl_daddr: dst IP address
 * @dir: SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 *
 * Returns: 0 if successful, else < 0
 */

int hip_xfrm_policy_modify(int cmd, struct in6_addr *hit_our, struct in6_addr *hit_peer, 
			   struct in6_addr *tmpl_saddr, struct in6_addr *tmpl_daddr, int dir){

	struct hip_nl_handle rth;
	struct {
		struct nlmsghdr			n;
		struct xfrm_userpolicy_info	xpinfo;
		char				buf[RTA_BUF_SIZE];
	} req;
	char tmpls_buf[XFRM_TMPLS_BUF_SIZE];
	int tmpls_len = 0;
	unsigned flags = 0;
	int preferred_family = AF_INET6;
	struct xfrm_user_tmpl *tmpl;

	memset(&req, 0, sizeof(req));
	memset(&tmpls_buf, 0, sizeof(tmpls_buf));
	
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xpinfo));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.xpinfo.sel.family = preferred_family;

	req.xpinfo.lft.soft_byte_limit = XFRM_INF;
	req.xpinfo.lft.hard_byte_limit = XFRM_INF;
	req.xpinfo.lft.soft_packet_limit = XFRM_INF;
	req.xpinfo.lft.hard_packet_limit = XFRM_INF;

	/* Direction */
	req.xpinfo.dir = dir;
	/* SELECTOR <--> HITs */
	req.xpinfo.sel.family = preferred_family;
	memcpy(&req.xpinfo.sel.daddr, hit_peer, sizeof(req.xpinfo.sel.daddr));
	memcpy(&req.xpinfo.sel.saddr, hit_our, sizeof(req.xpinfo.sel.saddr));
	req.xpinfo.sel.prefixlen_d = 128; /* Hardcoded for AF_INET6 or 128???*/
	req.xpinfo.sel.prefixlen_s = 128; /* Hardcoded for AF_INET6 */

	/* TEMPLATE */
	tmpl = (struct xfrm_user_tmpl *)((char *)tmpls_buf);

	tmpl->family = preferred_family;
	tmpl->aalgos = (~(__u32)0);
	tmpl->ealgos = (~(__u32)0);
	tmpl->calgos = (~(__u32)0);
	tmpl->optional = 0; /* required */
	if (tmpl_saddr && tmpl_daddr) {
		memcpy(&tmpl->saddr, tmpl_saddr, sizeof(tmpl->saddr));
		memcpy(&tmpl->id.daddr, tmpl_daddr, sizeof(tmpl->id.daddr));
	}

	addattr_l(&req.n, sizeof(req), XFRMA_TMPL,
		  (void *)tmpls_buf, tmpls_len);

	if (hip_netlink_open(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (req.xpinfo.sel.family == AF_UNSPEC)
		req.xpinfo.sel.family = AF_INET6;

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);

	hip_netlink_close(&rth);

	return 0;

}

int hip_xfrm_policy_delete() {
	/* Delete the policy (XFRM_MSG_DELPOLICY) */
}

int hip_xfrm_add(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
		    struct in6_addr *addr, uint32_t spi,
		    int state, int dir){

	/* Here the SP and SA have to be added in the same manner as in IP tool */
	
	return 0;
}

int hip_xfrm_update(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
		    struct in6_addr *addr, uint32_t spi,
		    int state, int dir) {
  	struct hip_work_order req, resp;

	/* In the way as in IP tool we have to upgrade SPs and SAs */

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_UPD,
				hit_peer, hit_our, addr, spi, state, dir);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

        /* Sending the message to kernel */
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

	/* Delete the SP and SA */

	HIP_INIT_WORK_ORDER_HDR(req.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_XFRM_DEL, hit, NULL, NULL,
				spi, dir, 0);
	req.msg = hip_msg_alloc();
	if (!req.msg) {
		return -1;
	}

	hip_build_user_hdr(req.msg, 0, 0);

	/* Sending the message to kernel */
	if (hip_netlink_talk(&nl_khipd, &req, &resp)) {
		HIP_ERROR("Unable to send over netlink\n");
		return 0;
	}

	hip_msg_free(req.msg);
	hip_msg_free(resp.msg);

	return resp.hdr.arg1;
}
