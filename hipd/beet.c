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
int hip_xfrm_policy_modify(int cmd, struct in6_addr *hit_our,
			   struct in6_addr *hit_peer,
			   struct in6_addr *tmpl_saddr,
			   struct in6_addr *tmpl_daddr, int dir,
			   __u8 proto, u8 hit_prefix,
			   int preferred_family)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr			n;
		struct xfrm_userpolicy_info	xpinfo;
		char				buf[RTA_BUF_SIZE];
	} req;
	char tmpls_buf[XFRM_TMPLS_BUF_SIZE];
	int tmpls_len = 0;
	unsigned flags = 0;
	struct xfrm_user_tmpl *tmpl;

	memset(&req, 0, sizeof(req));
	memset(&tmpls_buf, 0, sizeof(tmpls_buf));
	
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xpinfo));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;

	xfrm_init_lft(&req.xpinfo.lft);

	/* Direction */
	req.xpinfo.dir = dir;

	/* SELECTOR <--> HITs */
	xfrm_fill_selector(&req.xpinfo.sel, hit_peer, hit_our, 0,
			   hit_prefix, preferred_family);

	/* TEMPLATE */
	tmpl = (struct xfrm_user_tmpl *)((char *)tmpls_buf);

	tmpl->family = preferred_family;
	/* The mode has to be BEET */
	if (proto) {
		tmpl->mode = XFRM_MODE_BEET;
		tmpl->id.proto = proto;
	}

	tmpl->aalgos = (~(__u32)0);
	tmpl->ealgos = (~(__u32)0);
	tmpl->calgos = (~(__u32)0);
	tmpl->optional = 0; /* required */
	tmpls_len += sizeof(*tmpl);
	if (tmpl_saddr && tmpl_daddr) {
		HIP_HEXDUMP("tmpl_saddr", tmpl_saddr, 16);
		HIP_HEXDUMP("tmpl_daddr", tmpl_daddr, 16);
		memcpy(&tmpl->saddr, tmpl_saddr, sizeof(tmpl->saddr));
		memcpy(&tmpl->id.daddr, tmpl_daddr, sizeof(tmpl->id.daddr));
	}

	addattr_l(&req.n, sizeof(req), XFRMA_TMPL,
		  (void *)tmpls_buf, tmpls_len);

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		return -1;

	if (req.xpinfo.sel.family == AF_UNSPEC)
		req.xpinfo.sel.family = AF_INET6;

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return -1;

	rtnl_close(&rth);

	return 0;

}

/**
 * hip_xfrm_policy_delete - delete the Security Policy
 * @dir: SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @hit_our: Source HIT
 * @hit_peer: Peer HIT
 *
 * Returns: 0 if successful, else < 0
 */
int hip_xfrm_policy_delete(struct in6_addr *hit_our,
			   struct in6_addr *hit_peer,
			   int dir, u8 proto,
			   u8 hit_prefix,
			   int preferred_family) {

	struct rtnl_handle rth;
	struct {
		struct nlmsghdr			n;
		struct xfrm_userpolicy_id	xpid;
	} req;
	char *dirp = NULL;
	char *selp = NULL;
	char *indexp = NULL;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xpid));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_DELPOLICY;

	req.xpid.dir = dir;

	/* SELECTOR <--> HITs */
	xfrm_fill_selector(&req.xpid.sel, hit_peer, hit_our, 0, hit_prefix,
			   preferred_family);

	if (req.xpid.sel.family == AF_UNSPEC)
		req.xpid.sel.family = AF_INET6;

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		return -1;

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
		HIP_INFO("No associated policies to be deleted\n");
	}

	rtnl_close(&rth);

	return 0;
}


/**
 * hip_xfrm_state_modify - modify the Security Association
 * @cmd: command. %XFRM_MSG_NEWSA | %XFRM_MSG_UPDSA
 * @hit_our: Source HIT
 * @hit_peer: Peer HIT
 * @tmpl_saddr: source IP address
 * @tmpl_daddr: dst IP address
 *
 * Returns: 0 if successful, else < 0
 */
int hip_xfrm_state_modify(int cmd, struct in6_addr *saddr,
			  struct in6_addr *daddr, 
			  struct in6_addr *src_hit, 
			  struct in6_addr *dst_hit,
			  __u32 spi, int ealg,
			  struct hip_crypto_key *enckey,
			  int enckey_len,
			  int aalg,
			  struct hip_crypto_key *authkey,
			  int authkey_len,
			  int preferred_family)
{

	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct xfrm_usersa_info xsinfo;
		char   			buf[RTA_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsinfo));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.xsinfo.family = preferred_family;

	xfrm_init_lft(&req.xsinfo.lft);

	req.xsinfo.mode = XFRM_MODE_BEET;
	req.xsinfo.id.proto = IPPROTO_ESP;

	memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
	memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
	req.xsinfo.id.spi = htonl(spi);

	/* Selector */
	xfrm_fill_selector(&req.xsinfo.sel, src_hit, dst_hit, 
			   /*IPPROTO_ESP*/ 0, /*HIP_HIT_PREFIX_LEN*/ 128,
			   preferred_family);
	
	{
		struct {
			struct xfrm_algo algo;
			char buf[XFRM_ALGO_KEY_BUF_SIZE];
		} alg;
		/* Mappings from HIP to XFRM algo names */
		char *e_algo_names[] =
			{"reserved", "aes", "des3_ede", "des3_ede",
			 "blowfish", "cipher_null", "cipher_null"};
		char *a_algo_names[] =
			{"reserved", "sha1", "sha1", "md5",
			 "sha1", "sha1", "md5"};
		char *e_name = e_algo_names[ealg];
		char *a_name = a_algo_names[aalg];
		int len;

		HIP_ASSERT(ealg < sizeof(e_algo_names));
		HIP_ASSERT(aalg < sizeof(a_algo_names));

		/* XFRMA_ALG_AUTH */
		memset(&alg, 0, sizeof(alg));
		xfrm_algo_parse((void *)&alg, XFRMA_ALG_AUTH, a_name,
				authkey->key, sizeof(alg.buf));
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_AUTH,
			  (void *)&alg, len);

		/* XFRMA_ALG_CRYPT */
		memset(&alg, 0, sizeof(alg));
		xfrm_algo_parse((void *)&alg, XFRMA_ALG_CRYPT, e_name,
				enckey->key, sizeof(alg.buf));
	
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_CRYPT,
			  (void *)&alg, len);

	}

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		return -1;

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return -1;

	rtnl_close(&rth);

	return 0;
}

/**
 * hip_xfrm_state_delete - delete the Security Association
 * @peer_addr: Peer IP address
 * @spi: Security Parameter Index
 *
 * Returns: 0 if successful
 */
int hip_xfrm_state_delete(struct in6_addr *peer_addr, __u32 spi,
			  int preferred_family) {

	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct xfrm_usersa_id	xsid;
	} req;
	char *idp = NULL;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsid));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_DELSA;
	req.xsid.family = preferred_family;

	memcpy(&req.xsid.daddr, peer_addr, sizeof(req.xsid.daddr));

	req.xsid.spi = spi;
	req.xsid.proto = IPPROTO_ESP;

	if (rtnl_open_byproto(&rth, 0, NETLINK_XFRM) < 0)
		return -1;

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return -1;

	rtnl_close(&rth);

	return 0;
}

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	return -1; /* XX FIXME: REWRITE USING XFRM */
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	return -1; /* XX FIXME: REWRITE USING XFRM */
}

/* Security associations in the kernel with BEET are bounded to the outer
 * address, meaning IP addresses. As a result the parameters to be given
 * should be such an addresses and not the HITs.
 */
uint32_t hip_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
		    struct in6_addr *src_hit, struct in6_addr *dst_hit,
		     uint32_t *spi, int ealg,
		     struct hip_crypto_key *enckey,
		     struct hip_crypto_key *authkey,
		     int already_acquired,
		     int direction) {
	/* XX FIX: how to deal with the direction? */

	int err = 0, enckey_len, authkey_len;
	int aalg = ealg;

	HIP_ASSERT(spi);

	enckey_len = hip_enc_key_length(ealg);
	authkey_len = hip_auth_key_length_esp(aalg);
	if (enckey <= 0 || authkey_len <= 0) {
		err = -1;
		HIP_ERROR("Bad enc or auth key len\n");
		goto out_err;
	}

	/* XX CHECK: is there some kind of range for the SPIs ? */
	if (!already_acquired)
		get_random_bytes(spi, sizeof(uint32_t));

	HIP_IFE(hip_xfrm_state_modify(XFRM_MSG_NEWSA, saddr, daddr, 
				      src_hit, dst_hit, *spi,
				      ealg, enckey, enckey_len, aalg,
				      authkey, authkey_len, AF_INET6), -1);
 out_err:
	return err;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr, u8 proto,
			  int use_full_prefix)
{
	int err = 0;
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

	/* XX FIXME: remove the proto argument */

	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, dst_hit, src_hit,
				       src_addr, dst_addr,
				       XFRM_POLICY_IN, proto, prefix,
				       AF_INET6), -1);
	HIP_IFE(hip_xfrm_policy_modify(XFRM_MSG_NEWPOLICY, src_hit, dst_hit,
				       dst_addr, src_addr,
				       XFRM_POLICY_OUT, proto, prefix,
				       AF_INET6), -1);
 out_err:
	return err;
}

void hip_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
			    int use_full_prefix)
{
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

	hip_xfrm_policy_delete(src_hit, src_hit, XFRM_POLICY_IN, proto,
			       prefix, AF_INET6);
	hip_xfrm_policy_delete(dst_hit, dst_hit, XFRM_POLICY_OUT, proto,
			       prefix, AF_INET6);
}

void hip_delete_default_prefix_sp_pair() {
	hip_hit_t src_hit, dst_hit;
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* See the comment in hip_setup_sp_prefix_pair() */
	src_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);
	dst_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);

	hip_delete_hit_sp_pair(&src_hit, &dst_hit, 0, 0);
}

int hip_setup_default_sp_prefix_pair() {
	int err = 0;
	hip_hit_t src_hit, dst_hit;
#if 0
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* The OUTGOING and INCOMING policy is set to the generic value */

	src_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);
	dst_hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);

	HIP_IFE(hip_setup_hit_sp_pair(&src_hit, &dst_hit, NULL, NULL, 0, 0),
		-1);
#endif
 out_err:
	return err;
}
