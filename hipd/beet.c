#include "beet.h"

/* FIXME: the family at the moment is set to be AF_INET6 */
static int preferred_family = AF_INET6;


/**
 * xfrm_fill_selector - fill in the selector.
 * Selector is bound to HITs
 * @sel: pointer to xfrm_selector to be filled in
 * @hit_our: Source HIT
 * @hit_peer : Peer HIT
 *
 * Returns: 0
 */
int xfrm_fill_selector(struct xfrm_selector *sel, struct in6_addr *hit_our, struct in6_addr *hit_peer) {

	sel->family = preferred_family;
	memcpy(&sel->daddr, hit_peer, sizeof(sel->daddr));
	memcpy(&sel->saddr, hit_our, sizeof(sel->saddr));

	/* FIXME */
	sel->prefixlen_d = 2; /* Hardcoded for AF_INET6 or 128???*/
	sel->prefixlen_s = 2; /* Hardcoded for AF_INET6 */
	return 0;
}

/** xfrm_init_lft - Initializes the lft
 * @lft: pointer to the lft struct to be initialized
 *
 * Returns: 0
 */
int xfrm_init_lft(struct xfrm_lifetime_cfg *lft) {

	lft->soft_byte_limit = XFRM_INF;
	lft->hard_byte_limit = XFRM_INF;
	lft->soft_packet_limit = XFRM_INF;
	lft->hard_packet_limit = XFRM_INF;

	return 0;
}

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
			   struct in6_addr *tmpl_daddr, int dir){

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

	xfrm_init_lft(&req.xpinfo.lft);

	/* Direction */
	req.xpinfo.dir = dir;

	/* SELECTOR <--> HITs */
	xfrm_fill_selector(&req.xpinfo.sel, hit_peer, hit_our);

	/* TEMPLATE */
	tmpl = (struct xfrm_user_tmpl *)((char *)tmpls_buf);

	tmpl->family = preferred_family;
	tmpl->aalgos = (~(__u32)0);
	tmpl->ealgos = (~(__u32)0);
	tmpl->calgos = (~(__u32)0);
	tmpl->optional = 0; /* required */
	tmpls_len += sizeof(*tmpl);
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

/**
 * hip_xfrm_policy_delete - delete the Security Policy
 * @dir: SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @hit_our: Source HIT
 * @hit_peer: Peer HIT
 *
 * Returns: 0 if successful, else < 0
 */
int hip_xfrm_policy_delete(struct in6_addr *hit_our, struct in6_addr *hit_peer, int dir) {

	struct hip_nl_handle rth;
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
	xfrm_fill_selector(&req.xpid.sel, hit_peer, hit_our);

	if (req.xpid.sel.family == AF_UNSPEC)
		req.xpid.sel.family = AF_INET6;

	if (hip_netlink_open(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
		HIP_INFO("No associated policies to be deleted\n");
	}

	hip_netlink_close(&rth);

	return 0;
}

int get_u8(__u8 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFF)
		return -1;
	*val = res;
	return 0;
}

static int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
			   char *name, char *key, int max)
{
	int len;
	int slen = strlen(key);

	strncpy(alg->alg_name, name, sizeof(alg->alg_name));

	if (slen > 2 && strncmp(key, "0x", 2) == 0) {
		/* split two chars "0x" from the top */
		char *p = key + 2;
		int plen = slen - 2;
		int i;
		int j;

		/* Converting hexadecimal numbered string into real key;
		 * Convert each two chars into one char(value). If number
		 * of the length is odd, add zero on the top for rounding.
		 */

		/* calculate length of the converted values(real key) */
		len = (plen + 1) / 2;

		if (len > max)
			HIP_ERROR("\"ALGOKEY\" makes buffer overflow\n", key);

		for (i = - (plen % 2), j = 0; j < len; i += 2, j++) {
			char vbuf[3];
			__u8 val;

			vbuf[0] = i >= 0 ? p[i] : '0';
			vbuf[1] = p[i + 1];
			vbuf[2] = '\0';

			if (get_u8(&val, vbuf, 16))
				HIP_ERROR("\"ALGOKEY\" is invalid\n", key);

			alg->alg_key[j] = val;
		}
	} else {
		len = slen;
		if (len > 0) {
			if (len > max)
				HIP_ERROR("\"ALGOKEY\" makes buffer overflow\n", key);

			strncpy(alg->alg_key, key, len);
		}
	}

	alg->alg_key_len = len * 8;

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
			  __u32 spi, int ealg,
			  struct hip_crypto_key *enckey,
			  int enckey_len,
			  int aalg,
			  struct hip_crypto_key *authkey,
			  int authkey_len){

	struct hip_nl_handle rth;
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
	
	{
		struct {
			struct xfrm_algo algo;
			char buf[XFRM_ALGO_KEY_BUF_SIZE];
		} alg;
		int len;
		/*FIXME: from the algo_numbers, we need to map the protocol into the right string,
		 * since the kernel accepts strings. */
		char *e_name = "des3_ede";
		char *a_name = "md5";

		/* XFRMA_ALG_AUTH */
		memset(&alg, 0, sizeof(alg));
		xfrm_algo_parse((void *)&alg, XFRMA_ALG_AUTH, a_name, authkey->key, sizeof(alg.buf));
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_AUTH,
			  (void *)&alg, len);

		/* XFRMA_ALG_CRYPT */
		memset(&alg, 0, sizeof(alg));
		xfrm_algo_parse((void *)&alg, XFRMA_ALG_CRYPT, e_name, enckey->key, sizeof(alg.buf));
	
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_CRYPT,
			  (void *)&alg, len);

	}

	if (hip_netlink_open(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);

	hip_netlink_close(&rth);

	return 0;
}

/**
 * hip_xfrm_state_delete - delete the Security Association
 * @peer_addr: Peer IP address
 * @spi: Security Parameter Index
 *
 * Returns: 0 if successful
 */
int hip_xfrm_state_delete(struct in6_addr *peer_addr, __u32 spi) {

	struct hip_nl_handle rth;
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

	if (hip_netlink_open(&rth, 0, NETLINK_XFRM) < 0)
		exit(1);

	if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);

	hip_netlink_close(&rth);

	return 0;
}
