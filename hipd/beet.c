#include "beet.h"

/* FIXME: the family at the moment is set to be AF_INET6 */
static int preferred_family = AF_INET6;



/**
 * Functions for adding ip address
 */




static struct idxmap *idxmap[16];

unsigned ll_name_to_index(const char *name)
{
        static char ncache[16];
        static int icache;
        struct idxmap *im;
        int i;

        if (name == NULL)
                return 0;
        if (icache && strcmp(name, ncache) == 0)
                return icache;
        for (i=0; i<16; i++) {
                for (im = idxmap[i]; im; im = im->next) {
                        if (strcmp(im->name, name) == 0) {
                                icache = im->index;
                                strcpy(ncache, name);
                                return im->index;
                        }
                }
        }

        return if_nametoindex(name);
}

int get_unsigned(unsigned *val, const char *arg, int base)
{
        unsigned long res;
        char *ptr;

        if (!arg || !*arg)
                return -1;
        res = strtoul(arg, &ptr, base);
        if (!ptr || ptr == arg || *ptr || res > UINT_MAX)
                return -1;
        *val = res;
        return 0;
}



int get_addr_1(inet_prefix *addr, const char *name, int family)
{
        const char *cp;
        unsigned char *ap = (unsigned char*)addr->data;
        int i;

        memset(addr, 0, sizeof(*addr));

        if (strcmp(name, "default") == 0 ||
            strcmp(name, "all") == 0 ||
            strcmp(name, "any") == 0) {
                if (family == AF_DECnet)
                        return -1;
                addr->family = family;
                addr->bytelen = (family == AF_INET6 ? 16 : 4);
                addr->bitlen = -1;
                return 0;
        }

        if (strchr(name, ':')) {
                addr->family = AF_INET6;
                if (family != AF_UNSPEC && family != AF_INET6)
                        return -1;
                if (inet_pton(AF_INET6, name, addr->data) <= 0)
                        return -1;
                addr->bytelen = 16;
                addr->bitlen = -1;
                return 0;
        }




        addr->family = AF_INET;
        if (family != AF_UNSPEC && family != AF_INET)
                return -1;
        addr->bytelen = 4;
        addr->bitlen = -1;
        for (cp=name, i=0; *cp; cp++) {
                if (*cp <= '9' && *cp >= '0') {
                        ap[i] = 10*ap[i] + (*cp-'0');
                        continue;
                }
                if (*cp == '.' && ++i <= 3)
                        continue;
                return -1;
        }
        return 0;
}



int get_prefix_1(inet_prefix *dst, char *arg, int family)
{
        int err;
        unsigned plen;
        char *slash;

        memset(dst, 0, sizeof(*dst));

        if (strcmp(arg, "default") == 0 ||
            strcmp(arg, "any") == 0 ||
            strcmp(arg, "all") == 0) {
                if (family == AF_DECnet)
                        return -1;
                dst->family = family;
                dst->bytelen = 0;
                dst->bitlen = 0;
                return 0;
        }

        slash = strchr(arg, '/');
        if (slash)
               *slash = 0;

        err = get_addr_1(dst, arg, family);
        if (err == 0) {
                switch(dst->family) {
                        case AF_INET6:
                                dst->bitlen = 128;
                                break;
                        case AF_DECnet:
                                dst->bitlen = 16;
                                break;
                        default:
                        case AF_INET:
                                dst->bitlen = 32;
                 }
                if (slash) {
                        if (get_unsigned(&plen, slash+1, 0) || plen > dst->bitlen) {
                                err = -1;
                                goto done;
                        }
                        dst->flags |= PREFIXLEN_SPECIFIED;
                        dst->bitlen = plen;
                }
        }
done:
        if (slash)
                *slash = '/';
        return err;
}


int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
        int len = RTA_LENGTH(4);
        struct rtattr *rta;
        if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
                fprintf(stderr,"addattr32: Error! max allowed bound %d exceeded\n",maxlen);
                return -1;
        }
        rta = NLMSG_TAIL(n);
        rta->rta_type = type;
        rta->rta_len = len;
        memcpy(RTA_DATA(rta), &data, 4);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
        return 0;
}



int iproute_modify(int cmd, int flags, int family, char *ip, char *dev)
{
        struct hip_nl_handle rth;
        struct {
                struct nlmsghdr         n;
                struct rtmsg            r;
                char                    buf[1024];
        } req1;
        inet_prefix dst;
        int dst_ok = 0;
        int idx;
        memset(&req1, 0, sizeof(req1));

        req1.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        req1.n.nlmsg_flags = NLM_F_REQUEST|flags;
        req1.n.nlmsg_type = cmd;
        req1.r.rtm_family = family;
        req1.r.rtm_table = RT_TABLE_MAIN;
        req1.r.rtm_scope = RT_SCOPE_NOWHERE;

        if (cmd != RTM_DELROUTE) {
                req1.r.rtm_protocol = RTPROT_BOOT;
                req1.r.rtm_scope = RT_SCOPE_UNIVERSE;
                req1.r.rtm_type = RTN_UNICAST;
        }

	HIP_DEBUG("Setting %s as route for %s device with family %d\n", ip, dev, family);
        get_prefix_1(&dst, ip, req1.r.rtm_family);
        //if (req.r.rtm_family == AF_UNSPEC)
                //req.r.rtm_family = dst.family;
        req1.r.rtm_dst_len = dst.bitlen;
        dst_ok = 1;
        if (dst.bytelen)
        addattr_l(&req1.n, sizeof(req1), RTA_DST, &dst.data, dst.bytelen);
	if (hip_netlink_open(&rth, 0, NETLINK_ROUTE) < 0)
                exit(1);

         if ((idx = ll_name_to_index(dev)) == 0) {
                 fprintf(stderr, "Cannot find device \"%s\"\n", dev);
                 return -1;
         }
         addattr32(&req1.n, sizeof(req1), RTA_OIF, idx);


 /*               if (req1.r.rtm_type == RTN_LOCAL ||
                    req1.r.rtm_type == RTN_BROADCAST ||
                    req1.r.rtm_type == RTN_NAT ||
                    req1.r.rtm_type == RTN_ANYCAST)
                        req1.r.rtm_table = RT_TABLE_LOCAL;
                if (req1.r.rtm_type == RTN_LOCAL ||
                    req1.r.rtm_type == RTN_NAT)
                        req1.r.rtm_scope = RT_SCOPE_HOST;
                else if (req1.r.rtm_type == RTN_BROADCAST ||
                         req1.r.rtm_type == RTN_MULTICAST ||
                         req1.r.rtm_type == RTN_ANYCAST)
                        req1.r.rtm_scope = RT_SCOPE_LINK;
                else if (req1.r.rtm_type == RTN_UNICAST ||
                         req1.r.rtm_type == RTN_UNSPEC) {
                        if (cmd == RTM_DELROUTE)
                                req1.r.rtm_scope = RT_SCOPE_NOWHERE;
                        else    req1.r.rtm_scope = RT_SCOPE_LINK;

                        }
*/
        if (netlink_talk(&rth, &req1.n, 0, 0, NULL, NULL, NULL) < 0)
                exit(2);

        return 0;
}

int ipaddr_modify(int cmd, int family, char *ip, char *dev )
{
        struct hip_nl_handle rth;
        struct {
                struct nlmsghdr         n;
                struct ifaddrmsg        ifa;
                char                    buf[256];
        } req;
        char  *lcl_arg = NULL;
        inet_prefix lcl;
        int local_len = 0;
        inet_prefix addr;
        memset(&req, 0, sizeof(req));

        req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = cmd;
        req.ifa.ifa_family = family; 

        lcl_arg = ip;
	HIP_DEBUG("IP got %s\n", ip);
	get_prefix_1(&lcl, ip, req.ifa.ifa_family);
        addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);
        local_len = lcl.bytelen;
	// FIXED : prefix now adds - Abi
	if (req.ifa.ifa_prefixlen == 0)
                req.ifa.ifa_prefixlen = lcl.bitlen;

        if (hip_netlink_open(&rth, 0, NETLINK_ROUTE) < 0)
                exit(1);

        if ((req.ifa.ifa_index = ll_name_to_index(dev)) == 0) {
                fprintf(stderr, "Cannot find device \"%s\"\n", dev);
                return -1;
	}
        if (netlink_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
                exit(2);

	return 0;
}

int hip_add_iface_local_hit(const hip_hit_t *local_hit)
{
	int err = 0;
	char *hit_str = NULL;

	HIP_IFE((!(hit_str = hip_convert_hit_to_str(local_hit, 1))), -1);

	HIP_DEBUG("Adding HIT: %s\n", hit_str);

	HIP_IFE(ipaddr_modify(RTM_NEWADDR, AF_INET6, hit_str,
			      HIP_HIT_DEV), -1);

 out_err:

	if (hit_str)
		HIP_FREE(hit_str);
	
	return err;
}

int hip_add_iface_local_route(const hip_hit_t *local_hit)
{
	int err = 0;
	char *hit_str = NULL;

	HIP_IFE((!(hit_str = hip_convert_hit_to_str(local_hit, 1))), -1);

	HIP_DEBUG("Adding local route: %s\n", hit_str);
	
	HIP_IFE(iproute_modify(RTM_NEWROUTE,  NLM_F_CREATE|NLM_F_EXCL, AF_INET6, hit_str,
			      HIP_HIT_DEV), -1);

 out_err:

	if (hit_str)
		HIP_FREE(hit_str);
	
	
	return err;
}

/**
 * Functions for setting up dummy interface
 */

int get_ctl_fd(void)
{
        int s_errno;
        int fd;

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        s_errno = errno;
        fd = socket(PF_PACKET, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        fd = socket(PF_INET6, SOCK_DGRAM, 0);
        if (fd >= 0)
                return fd;
        errno = s_errno;
        perror("Cannot create control socket");
        return -1;
}


int do_chflags(const char *dev, __u32 flags, __u32 mask)
{
        struct ifreq ifr;
        int fd;
        int err;

        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        fd = get_ctl_fd();
        if (fd < 0)
                return -1;
        err = ioctl(fd, SIOCGIFFLAGS, &ifr);
        if (err) {
                perror("SIOCGIFFLAGS");
                close(fd);
                return -1;
        }
        if ((ifr.ifr_flags^flags)&mask) {
                ifr.ifr_flags &= ~mask;
                ifr.ifr_flags |= mask&flags;
                err = ioctl(fd, SIOCSIFFLAGS, &ifr);
                if (err)
                        perror("SIOCSIFFLAGS");
        }
        close(fd);
        return err;
}


int set_up_device(char *dev, int up)
{
	int err = -1;
	__u32 mask = 0;
	__u32 flags = 0;
	
	if(up == 1){
		mask |= IFF_UP;
		flags |= IFF_UP;
	} else {
		mask |= IFF_UP;
		flags &= ~IFF_UP;
	}
	
	err = do_chflags(dev, flags, mask);			
	printf("setting %s done\n", dev);
	return err;	 
}




/**
 * Functions for setting up SA/SP
 */


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

	/* Hardcoded for AF_INET6 or 128???*/
	sel->prefixlen_d = HIP_HIT_PREFIX_LEN;
	/* Hardcoded for AF_INET6 */
	sel->prefixlen_s = HIP_HIT_PREFIX_LEN;

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
