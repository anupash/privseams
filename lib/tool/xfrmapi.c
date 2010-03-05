/**
 * @file libhiptool/xfrmapi.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Management of IPsec security policies and associations with the
 * Linux-specific XFRM interface (eXtensible FRaMework). Please refer to e.g.  <a
 * href="http://ols.fedoraproject.org/OLS/Reprints-2004/Reprint-Miyazawa-OLS2004.pdf">IPv6
 * IPsec and Mobile IPv6 implementation of Linux</a> for an
 * introduction to XFRM.
 *
 * @brief Management of IPsec security policies and associations with the XFRM interface
 *
 * @author Miika Komu <miika@iki.fi>
 */
/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/tool/nlink.h"

#include "xfrmapi.h"

#ifndef CONFIG_HIP_PFKEY

#define RTA_BUF_SIZE     2048

/* New OSes have this, but older ones don't */
#ifndef XFRM_MODE_BEET
#  define XFRM_MODE_BEET 4
#endif

#define XFRM_TMPLS_BUF_SIZE 1024
#define XFRM_ALGO_KEY_BUF_SIZE 512


/* For receiving netlink IPsec events (acquire, expire, etc);
 * thread unfriendly! */
struct rtnl_handle *hip_xfrmapi_nl_ipsec;

int hip_xfrmapi_beet;
int hip_xfrmapi_sa_default_prefix;

char **e_algo_names;
char **a_algo_names;

/* Mappings from HIP to XFRM algo names < 2.6.19 */
char *e_algo_names_old[] =
{"reserved",   "aes",         "des3_ede", "des3_ede",
 "blowfish", "cipher_null", "cipher_null"};
char *a_algo_names_old[] =
{"reserved", "sha1", "sha1", "md5",
 "sha1",   "sha1", "md5"};

/* Mappings from HIP to XFRM algo names >= 2.6.19 */
char *e_algo_names_new[] =
{"reserved",        "cbc(aes)",         "cbc(des3_ede)", "cbc(des3_ede)",
 "cbc(blowfish)", "ecb(cipher_null)", "ecb(cipher_null)"};
char *a_algo_names_new[] =
{"reserved",     "hmac(sha1)", "hmac(sha1)", "hmac(md5)",
 "hmac(sha1)", "hmac(sha1)", "hmac(md5)"};


/**
 * modify a Security Policy
 * @param cmd command. %XFRM_MSG_NEWPOLICY | %XFRM_MSG_UPDPOLICY
 * @param id_our Source ID or LSI
 * @param id_peer Peer ID or LSI
 * @param tmpl_saddr source IP address
 * @param tmpl_daddr dst IP address
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 *
 * @return 0 if successful, else < 0
 */
static int hip_xfrm_policy_modify(struct rtnl_handle *rth, int cmd,
                                  const struct in6_addr *id_our,
                                  const struct in6_addr *id_peer,
                                  const struct in6_addr *tmpl_saddr,
                                  const struct in6_addr *tmpl_daddr,
                                  int dir, uint8_t proto, uint8_t id_prefix,
                                  int preferred_family)
{
    struct {
        struct nlmsghdr             n;
        struct xfrm_userpolicy_info xpinfo;
        char                        buf[RTA_BUF_SIZE];
    } req;
    char tmpls_buf[XFRM_TMPLS_BUF_SIZE];
    int tmpls_len  = 0, err = 0;
    unsigned flags = 0;
    struct xfrm_user_tmpl *tmpl;

    memset(&req, 0, sizeof(req));
    memset(&tmpls_buf, 0, sizeof(tmpls_buf));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xpinfo));
    req.n.nlmsg_flags = NLM_F_REQUEST | flags;
    req.n.nlmsg_type  = cmd;

    xfrm_init_lft(&req.xpinfo.lft);

    /* Direction */
    req.xpinfo.dir = dir;

    /* SELECTOR <--> HITs  SELECTOR <--> LSIs*/
    HIP_IFE(xfrm_fill_selector(&req.xpinfo.sel, id_peer, id_our, 0,
                               id_prefix, 0, 0, preferred_family), -1);

    /* TEMPLATE */
    tmpl = (struct xfrm_user_tmpl *) ((char *) tmpls_buf);

    if (IN6_IS_ADDR_V4MAPPED(tmpl_saddr) || IN6_IS_ADDR_V4MAPPED(tmpl_daddr)) {
        HIP_DEBUG("IPv4 address found in tmpl policy\n");
        tmpl->family = AF_INET;
    } else {
        tmpl->family = preferred_family;
    }


    /* The mode has to be BEET */
    if (proto) {
        tmpl->mode     = XFRM_MODE_BEET;
        tmpl->id.proto = proto;
    }

    tmpl->aalgos   = (~(uint32_t) 0);
    tmpl->ealgos   = (~(uint32_t) 0);
    tmpl->calgos   = (~(uint32_t) 0);
    tmpl->optional = 0;     /* required */
    tmpls_len     += sizeof(*tmpl);
    if (tmpl_saddr && tmpl_daddr) {
        if (tmpl->family == AF_INET) {
            tmpl->saddr.a4    = tmpl_saddr->s6_addr32[3];
            tmpl->id.daddr.a4 = tmpl_daddr->s6_addr32[3];
        } else {
            memcpy(&tmpl->saddr, tmpl_saddr, sizeof(tmpl->saddr));
            memcpy(&tmpl->id.daddr, tmpl_daddr, sizeof(tmpl->id.daddr));
        }
    }

    addattr_l(&req.n, sizeof(req), XFRMA_TMPL,
              (void *) tmpls_buf, tmpls_len);

    if (req.xpinfo.sel.family == AF_UNSPEC) {
        req.xpinfo.sel.family = AF_INET6;
    }

    {
        /*void *x = malloc(sizeof(req.n) * 10);
         * memcpy(x, &req.n, sizeof(req.n));*/
        HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
                 "netlink_talk failed\n");
        ///if (x)
        //free(x);
    }

out_err:

    return err;
}

/**
 * Flush all IPsec Security Associations
 *
 * @param rth a rtnl_handle containing a netlink socket
 * @return zero on success and non-zero on failure
 */
static int hip_xfrm_sa_flush(struct rtnl_handle *rth)
{
    struct {
        struct nlmsghdr          n;
        struct xfrm_usersa_flush xfs;
    } req;
    int err = 0;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xfs));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_FLUSHSA;
    req.xfs.proto     = IPPROTO_ESP;

    HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
             "SA flush failed\n");

out_err:

    return err;
}

/**
 * Flush all IPsec Security Policies
 *
 * @param rth a rtnl_handle containing a netlink socket
 * @return zero on success and non-zero on failure
 */
static int hip_xfrm_policy_flush(struct rtnl_handle *rth)
{
    struct {
        struct nlmsghdr n;
    } req;
    int err = 0;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(0);
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_FLUSHPOLICY;

    HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
             "Policy flush failed\n");

out_err:

    return err;
}

/**
 * delete a Security Policy
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @param hit_our Source HIT
 * @param hit_peer Peer HIT
 *
 * @return 0 if successful, negative on error
 */
static int hip_xfrm_policy_delete(struct rtnl_handle *rth,
                                  const struct in6_addr *hit_our,
                                  const struct in6_addr *hit_peer,
                                  const int dir, const uint8_t proto,
                                  const uint8_t hit_prefix,
                                  const int preferred_family)
{
    struct {
        struct nlmsghdr           n;
        struct xfrm_userpolicy_id xpid;
    } req;
    int err = 0;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xpid));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_DELPOLICY;

    req.xpid.dir      = dir;

    /* SELECTOR <--> HITs */
    HIP_IFE(xfrm_fill_selector(&req.xpid.sel, hit_peer, hit_our, 0,
                               hit_prefix, 0, 0, preferred_family), -1);
/*
 *      if (req.xpid.sel.family == AF_UNSPEC)
 *              req.xpid.sel.family = AF_INET6;
 */
    HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
             "No associated policies to be deleted\n");

out_err:

    return err;
}

/**
 * modify a Security Association
 *
 * @param cmd command. %XFRM_MSG_NEWSA | %XFRM_MSG_UPDSA
 * @param id_our Source HIT or LSI
 * @param id_peer Peer HIT or LSI
 * @param tmpl_saddr source IP address
 * @param tmpl_daddr dst IP address
 *
 * @return 0 if successful, negative on error
 */
static int hip_xfrm_state_modify(struct rtnl_handle *rth,
                                 const int cmd, const struct in6_addr *saddr,
                                 const struct in6_addr *daddr,
                                 const struct in6_addr *src_id,
                                 const struct in6_addr *dst_id,
                                 const uint32_t spi, const int ealg,
                                 const struct hip_crypto_key *enckey,
                                 const int enckey_len,
                                 const int aalg,
                                 const struct hip_crypto_key *authkey,
                                 const int authkey_len,
                                 const int preferred_family,
                                 const int sport, const int dport)
{
    int err = 0;
    struct xfrm_encap_tmpl encap;
    struct {
        struct nlmsghdr         n;
        struct xfrm_usersa_info xsinfo;
        char                    buf[RTA_BUF_SIZE];
    } req;

    HIP_DEBUG("hip_xfrm_state_modify() invoked.\n");
    HIP_DEBUG("sport %d, dport %d\n", sport, dport);
    HIP_DEBUG_IN6ADDR("saddr in sa", saddr);
    HIP_DEBUG_IN6ADDR("daddr in sa", daddr);

    memset(&req, 0, sizeof(req));

    if (IN6_IS_ADDR_V4MAPPED(saddr) || IN6_IS_ADDR_V4MAPPED(daddr)) {
        req.xsinfo.saddr.a4    = saddr->s6_addr32[3];
        req.xsinfo.id.daddr.a4 = daddr->s6_addr32[3];
        req.xsinfo.family      = AF_INET;
    } else {
        memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
        memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
        req.xsinfo.family = preferred_family;
    }

    req.n.nlmsg_len     = NLMSG_LENGTH(sizeof(req.xsinfo));
    req.n.nlmsg_flags   = NLM_F_REQUEST;
    req.n.nlmsg_type    = cmd;

    xfrm_init_lft(&req.xsinfo.lft);

    req.xsinfo.mode     = XFRM_MODE_BEET;
    req.xsinfo.id.proto = IPPROTO_ESP;

    //memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
    //memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
    req.xsinfo.id.spi   = htonl(spi);

    /* Selector */
    HIP_IFE(xfrm_fill_selector(&req.xsinfo.sel, src_id, dst_id,
                               0, hip_xfrmapi_sa_default_prefix, 0, 0,
                               AF_INET6), -1);
    if (req.xsinfo.family == AF_INET && (sport || dport)) {
        xfrm_fill_encap(&encap, (sport ? sport : hip_get_local_nat_udp_port()),
                        (dport ? dport : hip_get_peer_nat_udp_port()), saddr);
        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                          (void *) &encap, sizeof(encap)), -1);
    }

    {
        struct {
            struct xfrm_algo algo;
            char             buf[XFRM_ALGO_KEY_BUF_SIZE];
        } alg;
        char *e_name = e_algo_names[ealg];
        char *a_name = a_algo_names[aalg];
        int len;

        HIP_ASSERT(ealg < sizeof(e_algo_names));
        HIP_ASSERT(aalg < sizeof(a_algo_names));

        memset(alg.buf, 0, sizeof(alg.buf));

        /* XFRMA_ALG_AUTH */
        memset(&alg, 0, sizeof(alg));
        HIP_IFE(xfrm_algo_parse((void *) &alg, XFRMA_ALG_AUTH, a_name,
                                authkey->key, authkey_len,
                                sizeof(alg.buf)), -1);
        len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

        HIP_IFE((addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_AUTH,
                           (void *) &alg, len)), -1);

        /* XFRMA_ALG_CRYPT */
        memset(&alg, 0, sizeof(alg));
        HIP_IFE(xfrm_algo_parse((void *) &alg, XFRMA_ALG_CRYPT, e_name,
                                enckey->key, enckey_len,
                                sizeof(alg.buf)), -1);

        len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_CRYPT,
                          (void *) &alg, len), -1);
    }

    HIP_IFE((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1);

out_err:

    return err;
}

/**
 * delete a Security Association
 *
 * @param peer_addr Peer IP address
 * @param spi Security Parameter Index
 *
 * @return 0 on success or negative on error
 */
static int hip_xfrm_state_delete(struct rtnl_handle *rth,
                                 const struct in6_addr *peer_addr, uint32_t spi,
                                 const int preferred_family,
                                 const int sport, const int dport)
{
    struct {
        struct nlmsghdr       n;
        struct xfrm_usersa_id xsid;
        char                  buf[RTA_BUF_SIZE];
    } req;
    struct xfrm_encap_tmpl encap;
    int err = 0;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xsid));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_DELSA;
    //req.xsid.family = preferred_family;

    if (IN6_IS_ADDR_V4MAPPED(peer_addr)) {
        HIP_DEBUG("IPV4 SA deletion\n");
        req.xsid.daddr.a4 = peer_addr->s6_addr32[3];
        req.xsid.family   = AF_INET;
    } else {
        HIP_DEBUG("IPV6 SA deletion\n");
        memcpy(&req.xsid.daddr, peer_addr, sizeof(req.xsid.daddr));
        req.xsid.family = preferred_family;
    }

    HIP_DEBUG("sport %d, dport %d\n", sport, dport);

    /** @todo Fill in information for UDP-NAT SAs. */
    if (req.xsid.family == AF_INET && (sport || dport)) {
        HIP_DEBUG("FILLING UDP Port info while deleting\n");
        xfrm_fill_encap(&encap, (sport ? sport : hip_get_local_nat_udp_port()),
                        (dport ? dport : hip_get_peer_nat_udp_port()),
                        peer_addr);
        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                          (void *) &encap, sizeof(encap)), -1);
    }


    req.xsid.spi = htonl(spi);
    if (spi) {
        req.xsid.proto = IPPROTO_ESP;
    }

    HIP_DEBUG("deleting xfrm state with spi 0x%x\n", spi);
    HIP_HEXDUMP("SA peer addr: ", &req.xsid.daddr, sizeof(req.xsid.daddr));
    HIP_IFEL((netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0), -1,
             "netlink_talk() failed!\n");

out_err:
    return err;
}

/**
 * Calculate the prefix length depending on identifier type (LSI or HIT)
 *
 * @param src_id the identifier: a HIT or an LSI in IPv6 mapped format
 * @param use_full_prefix can be used to override prefix calculatation
 *                        and revert to maximum size prefix
 * @return the size of the calculated prefix
 */
static int hip_calc_sp_prefix(const struct in6_addr *src_id,
                              int use_full_prefix)
{
    uint8_t prefix;

    if (IN6_IS_ADDR_V4MAPPED(src_id)) {
        HIP_DEBUG("ipv4 address mapped as ipv6\n");
        prefix = (use_full_prefix) ? 32 : HIP_LSI_PREFIX_LEN;
    } else {
        prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;
    }

    return prefix;
}

/**
 * Set the netlink socket to control IPsec
 *
 * @param rtnl_handle netlink socket containing an initialized netlink socket
 */
void hip_xfrm_set_nl_ipsec(struct rtnl_handle *nl_ipsec)
{
    hip_xfrmapi_nl_ipsec = nl_ipsec;
}

/**
 * Set the IPsec mode number (depends on linux kernel version)
 *
 * @param beet the IPsec mode number for BEET
 * @note this function can also be used to change to TUNNEL mode instead of BEET
 */
void hip_xfrm_set_beet(int beet)
{
    hip_xfrmapi_beet = beet;
}

/**
 * Set default prefix length for HITs
 *
 * @param len the default prefix length (max 128)
 */
void hip_xfrm_set_default_sa_prefix_len(int len)
{
    hip_xfrmapi_sa_default_prefix = len;
}

/**
 * Set algorithm names (according to linux kernel version)
 *
 * @param 0 to use old naming convention and 1 for new
 */
void hip_xfrm_set_algo_names(int new_algo_names)
{
    e_algo_names = (new_algo_names ? e_algo_names_new : e_algo_names_old);
    a_algo_names = (new_algo_names ? a_algo_names_new : a_algo_names_old);
}

/**
 * A wrapper to hip_xfrm_policy_flush()
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_policy()
{
    return hip_xfrm_policy_flush(hip_xfrmapi_nl_ipsec);
}

/**
 * A wrapper to hip_xfrm_sa_flush()
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_sa()
{
    return hip_xfrm_sa_flush(hip_xfrmapi_nl_ipsec);
}

/**
 * delete a Security Association
 *
 * @param spi the SPI number distinguishing the SA
 * @param peer_addr the destination address for the SA
 * @param not_used not used
 * @param direction HIP_SPI_DIRECTION_OUT or HIP_SPI_DIRECTION_IN
 * @param entry corresponding host association
 */
void hip_delete_sa(const uint32_t spi, const struct in6_addr *peer_addr,
                   const struct in6_addr *not_used,
                   const int direction, hip_ha_t *entry)
{
    in_port_t sport, dport;

    // Ignore the dst_addr, because xfrm accepts only one address.
    // dst_addr is used only in pfkeyapi.c
    _HIP_DEBUG("spi=0x%x\n", spi);
    _HIP_DEBUG_IN6ADDR("SA daddr", peer_addr);

    if (direction == HIP_SPI_DIRECTION_OUT) {
        sport = entry->local_udp_port;
        dport = entry->peer_udp_port;
        entry->outbound_sa_count--;
        if (entry->outbound_sa_count < 0) {
            HIP_ERROR("Warning: out sa count negative\n");
            entry->outbound_sa_count = 0;
        }
    } else {
        sport = entry->peer_udp_port;
        dport = entry->local_udp_port;
        entry->inbound_sa_count--;
        if (entry->inbound_sa_count < 0) {
            HIP_ERROR("Warning: in sa count negative\n");
            entry->inbound_sa_count = 0;
        }
    }

    hip_xfrm_state_delete(hip_xfrmapi_nl_ipsec, peer_addr, spi, AF_INET6,
                          sport, dport);
}

/**
 * select a random SPI number
 *
 * @param srchit source HIT of the SA
 * @param dsthit destination HIT of the SA
 * @return a random SPI number
 * @todo rewrite using XFRM to avoid collisions?
 */
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit)
{
    uint32_t spi;
    get_random_bytes(&spi, sizeof(uint32_t));
    return spi;
}

/**
 * Add a Security Association for IPsec ESP
 *
 * @param saddr outer source address of the SA
 * @param daddr outer destination address of the SA
 * @param src_hit inner source address of the SA (source HIT)
 * @param dst_hit outer destination address of the SA (destination HIT)
 * @param spi SPI number for the SA
 * @param ealg encryption algorithm for ESP
 * @param enckey encryption key for ESP
 * @param authkey authentication key for ESP
 * @param already_acquired currently unused
 * @param direction the direction of the SA (HIP_SPI_DIRECTION_OUT or HIP_SPI_DIRECTION_IN)
 * @param update zero if new SA or one if an old SA
 * @param entry corresponding host association
 * @return zero on success and non-zero on error
 * @note IPv4 addresses in IPv6 mapped format
 * @note If you make changes to this function, please change also
 * hipd/user_ipsec_sadb_api.c:hip_userspace_ipsec_add_sa() and
 * pfkeyapi.c:add_sa()
 */
uint32_t hip_add_sa(const struct in6_addr *saddr,
                    const struct in6_addr *daddr,
                    const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    const uint32_t spi,
                    const int ealg,
                    const struct hip_crypto_key *enckey,
                    const struct hip_crypto_key *authkey,
                    const int already_acquired,
                    const int direction,
                    const int update,
                    hip_ha_t *entry)
{
    int err  = 0, enckey_len, authkey_len;
    int aalg = ealg;
    int cmd  = update ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;
    in_port_t sport, dport;

    HIP_ASSERT(spi != 0);
    HIP_ASSERT(entry);

    HIP_IFEL((entry->disable_sas == 1), 0,
             "SA creation disabled\n");

    if (direction == HIP_SPI_DIRECTION_OUT) {
        sport = entry->local_udp_port;
        dport = entry->peer_udp_port;
        entry->outbound_sa_count++;
    } else {
        sport = entry->peer_udp_port;
        dport = entry->local_udp_port;
        entry->inbound_sa_count++;
    }

    authkey_len = hip_auth_key_length_esp(aalg);
    enckey_len  = hip_enc_key_length(ealg);

    HIP_IFEL((enckey_len < 0 || authkey_len < 0), 1,
             "Bad enc or auth key len\n");

#if 0
    /* XX CHECK: is there some kind of range for the SPIs ? */
    if (!already_acquired) {
        get_random_bytes(spi, sizeof(uint32_t));
    }
#endif

    HIP_DEBUG("************************************\n");
    HIP_DEBUG("%s SA\n", (update ? "updating" : "adding new"));
    HIP_DEBUG_HIT("src_hit", src_hit);
    HIP_DEBUG_HIT("dst_hit", dst_hit);
    HIP_DEBUG_IN6ADDR("saddr", saddr);
    HIP_DEBUG_IN6ADDR("daddr", daddr);

    _HIP_DEBUG("sport %d\n", sport);
    _HIP_DEBUG("dport %d\n", dport);
    HIP_DEBUG("direction %d\n", direction);
    HIP_DEBUG("SPI=0x%x\n", spi);
    HIP_DEBUG("************************************\n");

    HIP_IFE(hip_xfrm_state_modify(hip_xfrmapi_nl_ipsec, cmd,
                                  saddr, daddr,
                                  src_hit, dst_hit, spi,
                                  ealg, enckey, enckey_len, aalg,
                                  authkey, authkey_len, AF_INET6,
                                  sport, dport), 1);

out_err:
    return err;
}

/**
 * set up a pair of security policies
 *
 * @param src_id  source HIT
 * @param dst_id destination HIT
 * @param src_addr source IP address
 * @param dst_addr destination IP address
 * @param proto protocol for the SP (IPPROTO_ESP)
 * @param use_full_prefix one if we should use /128 prefix for HITs
 *                        or zero otherwise
 * @param update zero if the the SP is new or one otherwise
 * @note  IPv4 addresses in IPv6 mapped format
 */
int hip_setup_hit_sp_pair(const struct in6_addr *src_id,
                          const struct in6_addr *dst_id,
                          const struct in6_addr *src_addr,
                          const struct in6_addr *dst_addr,
                          uint8_t proto,
                          int use_full_prefix,
                          int update)
{
    HIP_DEBUG("Start\n");

    int err   = 0;
    uint8_t prefix = hip_calc_sp_prefix(src_id, use_full_prefix);
    int cmd   = update ? XFRM_MSG_UPDPOLICY : XFRM_MSG_NEWPOLICY;

    /* XX FIXME: remove the proto argument */
    HIP_DEBUG("hip_setup_hit_sp_pair\n");
    HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, cmd,
                                   dst_id, src_id,
                                   src_addr, dst_addr,
                                   XFRM_POLICY_IN, proto, prefix,
                                   AF_INET6), -1);

    HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, cmd,
                                   src_id, dst_id,
                                   dst_addr, src_addr,
                                   XFRM_POLICY_OUT, proto, prefix,
                                   AF_INET6), -1);
    HIP_DEBUG("End\n");
out_err:
    return err;
}

/**
 * delete a pair of Security Policies
 *
 * @param src_hit source HIT for the SP
 * @param dst_hit destination HIT for the SP
 * @param proto the protocol (IPPROTO_ESP)
 * @param use_full_prefix one if we should use /128 prefix for HITs
 *                        or zero otherwise
 */
void hip_delete_hit_sp_pair(const hip_hit_t *src_hit,
                            const hip_hit_t *dst_hit,
                            const uint8_t proto,
                            const int use_full_prefix)
{
    uint8_t prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

    hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, dst_hit, src_hit,
                           XFRM_POLICY_IN, proto, prefix, AF_INET6);
    hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, src_hit, dst_hit,
                           XFRM_POLICY_OUT, proto, prefix, AF_INET6);
}

/**
 * delete the default Security Policy pair that triggers base exchanges
 *
 */
void hip_delete_default_prefix_sp_pair()
{
    hip_hit_t src_hit, dst_hit;
    memset(&src_hit, 0, sizeof(hip_hit_t));
    memset(&dst_hit, 0, sizeof(hip_hit_t));

    /* See the comment in hip_setup_sp_prefix_pair() */
    set_hit_prefix(&src_hit);
    set_hit_prefix(&dst_hit);

    hip_delete_hit_sp_pair(&src_hit, &dst_hit, 0, 0);
}

/**
 * add the default security policy pair (based on HIT prefix) that
 * triggers all base exchanges
 *
 * @return zero on success and negative on failure
 */
int hip_setup_default_sp_prefix_pair()
{
    int err = 0;
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
out_err:
    return err;
}

#endif /* ! CONFIG_HIP_PFKEY */
