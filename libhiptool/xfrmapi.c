#include "xfrmapi.h"

#ifndef CONFIG_HIP_PFKEY

/* For receiving netlink IPsec events (acquire, expire, etc);
   thread unfriendly! */
struct rtnl_handle *hip_xfrmapi_nl_ipsec;

int hip_xfrmapi_beet;
int hip_xfrmapi_sa_default_prefix;

char **e_algo_names; 
char **a_algo_names;

/* Mappings from HIP to XFRM algo names < 2.6.19 */
char *e_algo_names_old[] =
  {"reserved", "aes", "des3_ede", "des3_ede",
   "blowfish", "cipher_null", "cipher_null"};
char *a_algo_names_old[] =
  {"reserved", "sha1", "sha1", "md5",
   "sha1", "sha1", "md5"};

/* Mappings from HIP to XFRM algo names >= 2.6.19 */
char *e_algo_names_new[] =
  {"reserved", "cbc(aes)", "cbc(des3_ede)", "cbc(des3_ede)",
   "cbc(blowfish)", "ecb(cipher_null)", "ecb(cipher_null)"};
char *a_algo_names_new[] =
  {"reserved", "hmac(sha1)", "hmac(sha1)", "hmac(md5)",
   "hmac(sha1)", "hmac(sha1)", "hmac(md5)"};


void hip_xfrm_set_nl_ipsec(struct rtnl_handle *nl_ipsec) {
	hip_xfrmapi_nl_ipsec = nl_ipsec;
}

void hip_xfrm_set_beet(int beet) {
	hip_xfrmapi_beet = beet;
}

void hip_xfrm_set_default_sa_prefix_len(int len) {
	hip_xfrmapi_sa_default_prefix = len;
}

int hip_xfrm_get_beet(void) {
	return hip_xfrmapi_beet;
}

void hip_xfrm_set_algo_names(int new_algo_names) {
	e_algo_names = (new_algo_names ? e_algo_names_new : e_algo_names_old);
	a_algo_names = (new_algo_names ? a_algo_names_new : a_algo_names_old);
}

/**
 * hip_xfrm_policy_modify - modify the Security Policy
 * @param cmd command. %XFRM_MSG_NEWPOLICY | %XFRM_MSG_UPDPOLICY
 * @param hit_our Source HIT
 * @param hit_peer Peer HIT
 * @param tmpl_saddr source IP address
 * @param tmpl_daddr dst IP address
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 *
 * @return 0 if successful, else < 0
 */
int hip_xfrm_policy_modify(struct rtnl_handle *rth, int cmd,
			   hip_hit_t *hit_our, hip_hit_t *hit_peer,
			   struct in6_addr *tmpl_saddr,
			   struct in6_addr *tmpl_daddr,
			   int dir, u8 proto, u8 hit_prefix,
			   int preferred_family)
{
	struct {
		struct nlmsghdr			n;
		struct xfrm_userpolicy_info	xpinfo;
		char				buf[RTA_BUF_SIZE];
	} req;
	char tmpls_buf[XFRM_TMPLS_BUF_SIZE];
	int tmpls_len = 0, err = 0;
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
	HIP_IFE(xfrm_fill_selector(&req.xpinfo.sel, hit_peer, hit_our, 0,
				   hit_prefix, 0, 0, preferred_family), -1);

	/* TEMPLATE */
	tmpl = (struct xfrm_user_tmpl *)((char *)tmpls_buf);

	if(IN6_IS_ADDR_V4MAPPED(tmpl_saddr) || IN6_IS_ADDR_V4MAPPED(tmpl_daddr))
	{
		HIP_DEBUG("IPv4 address found in tmpl policy\n");
		tmpl->family = AF_INET;
	} else {
		tmpl->family = preferred_family;
	}
		

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
		if(tmpl->family == AF_INET){
			tmpl->saddr.a4 = tmpl_saddr->s6_addr32[3];
			tmpl->id.daddr.a4 = tmpl_daddr->s6_addr32[3];
		} else {
			memcpy(&tmpl->saddr, tmpl_saddr, sizeof(tmpl->saddr));
			memcpy(&tmpl->id.daddr, tmpl_daddr, sizeof(tmpl->id.daddr));
		}
	}

	addattr_l(&req.n, sizeof(req), XFRMA_TMPL,
		  (void *)tmpls_buf, tmpls_len);

	if (req.xpinfo.sel.family == AF_UNSPEC)
		req.xpinfo.sel.family = AF_INET6;

	{
		void *x = malloc(sizeof(req.n) * 10);
		memcpy(x, &req.n, sizeof(req.n));
		HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
			 "netlink_talk failed\n");
	}

out_err:

	return err;
}

int hip_xfrm_sa_flush(struct rtnl_handle *rth) {

	struct {
		struct nlmsghdr		  n;
		struct xfrm_usersa_flush  xfs;
	} req;
	int err = 0;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xfs));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_FLUSHSA;
	req.xfs.proto = IPPROTO_ESP;

	HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
		 "SA flush failed\n");

 out_err:

	return err;
}

int hip_xfrm_policy_flush(struct rtnl_handle *rth) {

	struct {
		struct nlmsghdr			n;
	} req;
	int err = 0;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(0);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_FLUSHPOLICY;

	HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
		 "Policy flush failed\n");

 out_err:

	return err;
}

int hip_flush_all_policy() {
	return hip_xfrm_policy_flush(hip_xfrmapi_nl_ipsec);
}

int hip_flush_all_sa() {
	return hip_xfrm_sa_flush(hip_xfrmapi_nl_ipsec);
}

/**
 * hip_xfrm_policy_delete - delete the Security Policy
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @param hit_our Source HIT
 * @param hit_peer Peer HIT
 *
 * @return 0 if successful, else < 0
 */
int hip_xfrm_policy_delete(struct rtnl_handle *rth,
			   struct in6_addr *hit_our,
			   struct in6_addr *hit_peer,
			   int dir, u8 proto,
			   u8 hit_prefix,
			   int preferred_family) {

	struct {
		struct nlmsghdr			n;
		struct xfrm_userpolicy_id	xpid;
	} req;
	char *dirp = NULL;
	char *selp = NULL;
	char *indexp = NULL;
	int err = 0;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xpid));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_DELPOLICY;

	req.xpid.dir = dir;

	/* SELECTOR <--> HITs */
	HIP_IFE(xfrm_fill_selector(&req.xpid.sel, hit_peer, hit_our, 0,
				   hit_prefix, 0, 0, preferred_family), -1);
/*
	if (req.xpid.sel.family == AF_UNSPEC)
		req.xpid.sel.family = AF_INET6;
*/
	HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
		 "No associated policies to be deleted\n");

 out_err:

	return err;
}

/**
 * Modifies a Security Association.
 * 
 * @param cmd command. %XFRM_MSG_NEWSA | %XFRM_MSG_UPDSA
 * @param hit_our Source HIT
 * @param hit_peer Peer HIT
 * @param tmpl_saddr source IP address
 * @param tmpl_daddr dst IP address
 *
 * @return 0 if successful, else < 0
 */
int hip_xfrm_state_modify(struct rtnl_handle *rth,
			  int cmd, struct in6_addr *saddr,
			  struct in6_addr *daddr, 
			  struct in6_addr *src_hit, 
			  struct in6_addr *dst_hit,
			  __u32 spi, int ealg,
			  struct hip_crypto_key *enckey,
			  int enckey_len,
			  int aalg,
			  struct hip_crypto_key *authkey,
			  int authkey_len,
			  int preferred_family,
			  int sport, int dport )
			//hip_portpair_t *sa_info)
{
	int err = 0;
	struct xfrm_encap_tmpl encap;
	struct {
		struct nlmsghdr 	n;
		struct xfrm_usersa_info xsinfo;
		char   			buf[RTA_BUF_SIZE];
	} req;

	HIP_DEBUG("hip_xfrm_state_modify() invoked.\n");
	HIP_DEBUG("sport %d, dport %d\n", sport, dport);
	HIP_DEBUG_IN6ADDR("saddr in sa", saddr);
	HIP_DEBUG_IN6ADDR("daddr in sa", daddr);
	
	memset(&req, 0, sizeof(req));

	if(IN6_IS_ADDR_V4MAPPED(saddr) || IN6_IS_ADDR_V4MAPPED(daddr))
	{	
		req.xsinfo.saddr.a4 = saddr->s6_addr32[3];
		req.xsinfo.id.daddr.a4 = daddr->s6_addr32[3];
		req.xsinfo.family = AF_INET;
	} else {
		memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
	        memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
		req.xsinfo.family = preferred_family;
 	}

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsinfo));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;

	xfrm_init_lft(&req.xsinfo.lft);

	req.xsinfo.mode = XFRM_MODE_BEET;
	req.xsinfo.id.proto = IPPROTO_ESP;

	//memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
	//memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
	req.xsinfo.id.spi = htonl(spi);

	/* Selector */
	HIP_IFE(xfrm_fill_selector(&req.xsinfo.sel, src_hit, dst_hit, 
			   0, hip_xfrmapi_sa_default_prefix, 0,0, AF_INET6), -1);
	if(req.xsinfo.family == AF_INET && (sport || dport))
	{
		xfrm_fill_encap(&encap, (sport ? sport : HIP_NAT_UDP_PORT), 
			(dport ? dport : HIP_NAT_UDP_PORT), saddr);
		HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                                  (void *)&encap, sizeof(encap)), -1);
	}
	
	{
		struct {
			struct xfrm_algo algo;
			char buf[XFRM_ALGO_KEY_BUF_SIZE];
		} alg;
		char *e_name = e_algo_names[ealg];
		char *a_name = a_algo_names[aalg];
		int len;

		HIP_ASSERT(ealg < sizeof(e_algo_names));
		HIP_ASSERT(aalg < sizeof(a_algo_names));

		memset(alg.buf, 0, sizeof(alg.buf));

		/* XFRMA_ALG_AUTH */
		memset(&alg, 0, sizeof(alg));
		HIP_IFE(xfrm_algo_parse((void *)&alg, XFRMA_ALG_AUTH, a_name,
					 authkey->key, authkey_len,
					sizeof(alg.buf)), -1);
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		HIP_IFE((addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_AUTH,
				   (void *)&alg, len)), -1);

		/* XFRMA_ALG_CRYPT */
		memset(&alg, 0, sizeof(alg));
		HIP_IFE(xfrm_algo_parse((void *)&alg, XFRMA_ALG_CRYPT, e_name,
					enckey->key, enckey_len,
					sizeof(alg.buf)), -1);
	
		len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

		HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_CRYPT,
				  (void *)&alg, len), -1);

	}

	HIP_IFE((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1);

 out_err:

	return err;
}

/**
 * hip_xfrm_state_delete - delete the Security Association
 * @param peer_addr Peer IP address
 * @param spi Security Parameter Index
 *
 * @return 0 if successful
 */
int hip_xfrm_state_delete(struct rtnl_handle *rth,
                          struct in6_addr *peer_addr, __u32 spi,
                          int preferred_family,
                          int sport, int dport)
{
	struct
	{
		struct nlmsghdr n;
		struct xfrm_usersa_id xsid;
		char buf[RTA_BUF_SIZE];
	} req;
	struct xfrm_encap_tmpl encap;
	char *idp = NULL;
	int err = 0;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsid));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_DELSA;
	//req.xsid.family = preferred_family;

	if (IN6_IS_ADDR_V4MAPPED(peer_addr))
	{
		HIP_DEBUG("IPV4 SA deletion\n");
				req.xsid.daddr.a4 = peer_addr->s6_addr32[3];
				req.xsid.family = AF_INET;
	}
	else
	{
		HIP_DEBUG("IPV6 SA deletion\n");
		memcpy(&req.xsid.daddr, peer_addr, sizeof(req.xsid.daddr));
				req.xsid.family = preferred_family;
	}

	HIP_DEBUG("sport %d, dport %d\n", sport, dport);
	
        /** @todo Fill in information for UDP-NAT SAs. */
	if (req.xsid.family == AF_INET && (sport || dport))
	{
		HIP_DEBUG("FILLING UDP Port info while deleting\n");
		xfrm_fill_encap(&encap, (sport ? sport : HIP_NAT_UDP_PORT), 
			(dport ? dport : HIP_NAT_UDP_PORT), peer_addr);
		HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                                  (void *)&encap, sizeof(encap)), -1);
	}


	req.xsid.spi = htonl(spi);
	if (spi) req.xsid.proto = IPPROTO_ESP;

	HIP_DEBUG("deleting xfrm state with spi 0x%x\n", spi);
	HIP_HEXDUMP("peer addr: ", &req.xsid.daddr, sizeof(req.xsid.daddr));
	HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1, "netlink_talk() failed!\n");

out_err:
	return err;
}

void hip_delete_sa(u32 spi, struct in6_addr *peer_addr,
                   struct in6_addr *dst_addr,
                   int family, int sport, int dport)
{
	// Ignore the dst_addr, because xfrm accepts only one address.
	// dst_addr is used only in pfkeyapi.c
	HIP_DEBUG("spi=0x%x\n", spi);
	HIP_DEBUG_IN6ADDR("daddr", peer_addr);

	hip_xfrm_state_delete(hip_xfrmapi_nl_ipsec, peer_addr, spi, family,
	                      sport, dport);
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit)
{
	uint32_t spi;
	get_random_bytes(&spi, sizeof(uint32_t));
	return spi; /* XX FIXME: REWRITE USING XFRM */
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
		    int direction, int update,
		    int sport, int dport) {
			// hip_portpair_t *sa_info) {
	/* XX FIX: how to deal with the direction? */

	int err = 0, enckey_len, authkey_len;
	int aalg = ealg;
	int cmd = update ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;

	HIP_ASSERT(spi);

	HIP_DEBUG("%s SA\n", (update ? "updating" : "adding new"));

	HIP_DEBUG_HIT("src_hit", src_hit);
	HIP_DEBUG_HIT("dst_hit", dst_hit);
	HIP_DEBUG_IN6ADDR("saddr", saddr);
	HIP_DEBUG_IN6ADDR("daddr", daddr);

	authkey_len = hip_auth_key_length_esp(aalg);
	enckey_len = hip_enc_key_length(ealg);

	HIP_IFEL((enckey_len < 0 || authkey_len < 0), 1,
		 "Bad enc or auth key len\n");

	/* XX CHECK: is there some kind of range for the SPIs ? */
	if (!already_acquired)
		get_random_bytes(spi, sizeof(uint32_t));

	HIP_IFE(hip_xfrm_state_modify(hip_xfrmapi_nl_ipsec, cmd,
				      saddr, daddr, 
				      src_hit, dst_hit, *spi,
				      ealg, enckey, enckey_len, aalg,
				      authkey, authkey_len, AF_INET6,
				      sport, dport), 1);
				      
 out_err:
	return err;
}

int hip_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
			  struct in6_addr *src_addr,
			  struct in6_addr *dst_addr, u8 proto,
			  int use_full_prefix, int update)
{
	int err = 0;
	u8 prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;
	int cmd = update ? XFRM_MSG_UPDPOLICY : XFRM_MSG_NEWPOLICY;

	/* XX FIXME: remove the proto argument */

	HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, cmd,
				       dst_hit, src_hit,
				       src_addr, dst_addr,
				       XFRM_POLICY_IN, proto, prefix,
				       AF_INET6), -1);
	HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, cmd,
				       src_hit, dst_hit,
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

	hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, dst_hit, src_hit,
			       XFRM_POLICY_IN, proto, prefix, AF_INET6);
	hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, src_hit, dst_hit,
			       XFRM_POLICY_OUT, proto, prefix, AF_INET6);
}

void hip_delete_default_prefix_sp_pair() {
	hip_hit_t src_hit, dst_hit;
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* See the comment in hip_setup_sp_prefix_pair() */
	set_hit_prefix(&src_hit);
	set_hit_prefix(&dst_hit);

	hip_delete_hit_sp_pair(&src_hit, &dst_hit, 0, 0);
}

int hip_setup_default_sp_prefix_pair() {
	int err = 0;
#ifndef CONFIG_HIP_BUGGYPREFIX
	hip_hit_t src_hit, dst_hit;
	struct in6_addr ip;

	memset(&ip, 0, sizeof(hip_hit_t));
	memset(&src_hit, 0, sizeof(hip_hit_t));
	memset(&dst_hit, 0, sizeof(hip_hit_t));

	/* The OUTGOING and INCOMING policy is set to the generic value */
	set_hit_prefix(&src_hit);
	set_hit_prefix(&dst_hit);

	HIP_IFE(hip_setup_hit_sp_pair(&src_hit, &dst_hit, &ip, &ip, 0, 0, 0),
		-1);
#endif
 out_err:
	return err;
}

#endif /* ! CONFIG_HIP_PFKEY */
