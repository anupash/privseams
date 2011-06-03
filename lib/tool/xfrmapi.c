/**
 * @file
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

#define _BSD_SOURCE

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/keylen.h"
#include "lib/core/prefix.h"
#include "nlink.h"
#include "xfrmapi.h"


#define RTA_BUF_SIZE     2048

/* New OSes have this, but older ones don't */
#ifndef XFRM_MODE_BEET
#define XFRM_MODE_BEET 4
#endif

#define XFRM_TMPLS_BUF_SIZE 1024
#define XFRM_ALGO_KEY_BUF_SIZE 512


/* For receiving netlink IPsec events (acquire, expire, etc);
 * thread unfriendly! */
static struct rtnl_handle *hip_xfrmapi_nl_ipsec;

static int hip_xfrmapi_beet;
static int hip_xfrmapi_sa_default_prefix;

static const char *const *e_algo_names;
static const char *const *a_algo_names;

/* Mappings from HIP to XFRM algo names < 2.6.19 */
static const char *const E_ALGO_NAMES_OLD[] = {
    "reserved",
    "aes",
    "des3_ede",
    "des3_ede",
    "blowfish",
    "cipher_null",
    "cipher_null"
};
static const char *const A_ALGO_NAMES_OLD[] = {
    "reserved",
    "sha1",
    "sha1",
    "md5",
    "sha1",
    "sha1",
    "md5"
};

/* Mappings from HIP to XFRM algo names >= 2.6.19 */
static const char *const E_ALGO_NAMES_NEW[] = {
    "reserved",
    "cbc(aes)",
    "cbc(des3_ede)",
    "cbc(des3_ede)",
    "cbc(blowfish)",
    "ecb(cipher_null)",
    "ecb(cipher_null)"
};
static const char *const A_ALGO_NAMES_NEW[] = {
    "reserved",
    "hmac(sha1)",
    "hmac(sha1)",
    "hmac(md5)",
    "hmac(sha1)",
    "hmac(sha1)",
    "hmac(md5)"
};


/**
 * fill the port numbers for the UDP tunnel for IPsec
 *
 * @param encap xfrm_encap_tmpl structure
 * @param sport source port
 * @param dport destination port
 * @param oa the destination address of the tunnel in IPv6-mapped format
 * @return 0
 */
static int hip_xfrm_fill_encap(struct xfrm_encap_tmpl *encap,
                               const int sport,
                               const int dport,
                               const struct in6_addr *oa)
{
    encap->encap_type  = HIP_UDP_ENCAP_ESPINUDP;
    encap->encap_sport = htons(sport);
    encap->encap_dport = htons(dport);
    encap->encap_oa.a4 = oa->s6_addr32[3];
    return 0;
}

/**
 * Fill in the selector. Selector is bound to HITs.
 *
 * @param sel pointer to xfrm_selector to be filled in
 * @param id_our Source HIT or LSI, if the last is defined
 * @param id_peer Peer HIT or LSI, if the last is defined
 * @param proto inclusive protocol filter (zero for any protocol)
 * @param id_prefix Length of the identifier's prefix
 * @param preferred_family address family filter (AF_INET6 for HITs)
 * @return 0
 */
static int hip_xfrm_fill_selector(struct xfrm_selector *sel,
                                  const struct in6_addr *id_our,
                                  const struct in6_addr *id_peer,
                                  const uint8_t proto, const uint8_t id_prefix,
                                  const int preferred_family)
{
    struct in_addr in_id_our, in_id_peer;

    if (IN6_IS_ADDR_V4MAPPED(id_our)) {
        sel->family = AF_INET;
        IPV6_TO_IPV4_MAP(id_our, &in_id_our);
        IPV6_TO_IPV4_MAP(id_peer, &in_id_peer);
        memcpy(&sel->daddr, &in_id_our, sizeof(sel->daddr));
        memcpy(&sel->saddr, &in_id_peer, sizeof(sel->saddr));
    } else {
        sel->family = preferred_family;
        memcpy(&sel->daddr, id_peer, sizeof(sel->daddr));
        memcpy(&sel->saddr, id_our, sizeof(sel->saddr));
    }

    if (proto) {
        HIP_DEBUG("proto = %d\n", proto);
        sel->proto = proto;
    }

    sel->prefixlen_d = id_prefix;
    sel->prefixlen_s = id_prefix;

    return 0;
}

/**
 * initialize the lft
 *
 * @param lft pointer to the lft struct to be initialized
 *
 * @return 0
 */
static int hip_xfrm_init_lft(struct xfrm_lifetime_cfg *lft)
{
    lft->soft_byte_limit   = XFRM_INF;
    lft->hard_byte_limit   = XFRM_INF;
    lft->soft_packet_limit = XFRM_INF;
    lft->hard_packet_limit = XFRM_INF;

    return 0;
}

/**
 * parse a crypto algorithm name and its key into an xfrm_algo structure
 *
 * @param alg the resulting xfrm_algo structure (caller allocates)
 * @param name the name of the crypto algorithm
 * @param key the key for the given algorithm
 * @param key_len the length of the key in bits
 * @param max maximum size for a key in the xfrm_algo structure
 * @return zero
 */
static int hip_xfrm_algo_parse(struct xfrm_algo *alg, const char *name,
                               const unsigned char *key, const int key_len,
                               const int max)
{
    int len  = 0;
    int slen = key_len;

    strncpy(alg->alg_name, name, sizeof(alg->alg_name));

    len = slen;
    if (len > 0) {
        if (len > max) {
            HIP_ERROR("\"ALGOKEY\" makes buffer overflow\n", key);
            return -1;
        }
        memcpy(alg->alg_key, key, key_len * 8);
    }

    alg->alg_key_len = len * 8;

    return 0;
}

/**
 * modify a Security Policy
 * @param cmd command. %XFRM_MSG_NEWPOLICY | %XFRM_MSG_UPDPOLICY
 * @param id_our Source ID or LSI
 * @param id_peer Peer ID or LSI
 * @param tmpl_saddr source IP address
 * @param tmpl_daddr dst IP address
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @param rth
 * @param proto
 * @param id_prefix
 * @param preferred_family
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
    } req                       = { { 0 } };
    struct xfrm_user_tmpl tmpl  = { { { 0 } } };
    int                   err   = 0;
    unsigned              flags = 0;

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xpinfo));
    req.n.nlmsg_flags = NLM_F_REQUEST | flags;
    req.n.nlmsg_type  = cmd;

    hip_xfrm_init_lft(&req.xpinfo.lft);

    /* Direction */
    req.xpinfo.dir = dir;

    /* SELECTOR <--> HITs  SELECTOR <--> LSIs*/
    HIP_IFE(hip_xfrm_fill_selector(&req.xpinfo.sel, id_peer, id_our, 0,
                                   id_prefix, preferred_family), -1);

    if (IN6_IS_ADDR_V4MAPPED(tmpl_saddr) || IN6_IS_ADDR_V4MAPPED(tmpl_daddr)) {
        HIP_DEBUG("IPv4 address found in tmpl policy\n");
        tmpl.family = AF_INET;
    } else {
        tmpl.family = preferred_family;
    }


    /* The mode has to be BEET */
    if (proto) {
        tmpl.mode     = XFRM_MODE_BEET;
        tmpl.id.proto = proto;
    }

    tmpl.aalgos   = ~(uint32_t) 0;
    tmpl.ealgos   = ~(uint32_t) 0;
    tmpl.calgos   = ~(uint32_t) 0;
    tmpl.optional = 0;     /* required */

    if (tmpl_saddr && tmpl_daddr) {
        if (tmpl.family == AF_INET) {
            tmpl.saddr.a4    = tmpl_saddr->s6_addr32[3];
            tmpl.id.daddr.a4 = tmpl_daddr->s6_addr32[3];
        } else {
            memcpy(&tmpl.saddr, tmpl_saddr, sizeof(tmpl.saddr));
            memcpy(&tmpl.id.daddr, tmpl_daddr, sizeof(tmpl.id.daddr));
        }
    }

    addattr_l(&req.n, sizeof(req), XFRMA_TMPL, &tmpl, sizeof(tmpl));

    if (req.xpinfo.sel.family == AF_UNSPEC) {
        req.xpinfo.sel.family = AF_INET6;
    }

    HIP_IFEL(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0,
             -1, "netlink_talk failed\n");

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
    } req   = { { 0 } };
    int err = 0;

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xfs));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_FLUSHSA;
    req.xfs.proto     = IPPROTO_ESP;

    HIP_IFEL(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0, -1,
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
    } req   = { { 0 } };
    int err = 0;

    req.n.nlmsg_len   = NLMSG_LENGTH(0);
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_FLUSHPOLICY;

    HIP_IFEL(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0, -1,
             "Policy flush failed\n");

out_err:
    return err;
}

/**
 * delete a Security Policy
 * @param dir SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 * @param hit_our Source HIT
 * @param hit_peer Peer HIT
 * @param rth
 * @param hit_prefix
 * @param preferred_family
 *
 * @return 0 if successful, negative on error
 */
static int hip_xfrm_policy_delete(struct rtnl_handle *rth,
                                  const struct in6_addr *hit_our,
                                  const struct in6_addr *hit_peer,
                                  const int dir,
                                  const uint8_t hit_prefix,
                                  const int preferred_family)
{
    struct {
        struct nlmsghdr           n;
        struct xfrm_userpolicy_id xpid;
    } req   = { { 0 } };
    int err = 0;

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xpid));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_DELPOLICY;

    req.xpid.dir = dir;

    /* SELECTOR <--> HITs */
    HIP_IFE(hip_xfrm_fill_selector(&req.xpid.sel, hit_peer, hit_our, 0,
                                   hit_prefix, preferred_family), -1);
    HIP_IFEL(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0, -1,
             "Security policy deletion failed.\n");

out_err:
    return err;
}

/**
 * modify a Security Association
 *
 * @param cmd command. %XFRM_MSG_NEWSA | %XFRM_MSG_UPDSA
 * @param rth
 * @param saddr source IP address
 * @param daddr destination IP address
 * @param src_id Source HIT or LSI
 * @param dst_id Peer HIT or LSI
 * @param spi
 * @param ealg
 * @param enckey
 * @param enckey_len
 * @param aalg
 * @param authkey
 * @param authkey_len
 * @param preferred_family
 * @param sport
 * @param dport
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
    int                    err = 0;
    struct xfrm_encap_tmpl encap;
    struct {
        struct nlmsghdr         n;
        struct xfrm_usersa_info xsinfo;
        char                    buf[RTA_BUF_SIZE];
    } req = { { 0 } };

    HIP_DEBUG("sport %d, dport %d\n", sport, dport);
    HIP_DEBUG_IN6ADDR("saddr in sa", saddr);
    HIP_DEBUG_IN6ADDR("daddr in sa", daddr);

    if (IN6_IS_ADDR_V4MAPPED(saddr) || IN6_IS_ADDR_V4MAPPED(daddr)) {
        req.xsinfo.saddr.a4    = saddr->s6_addr32[3];
        req.xsinfo.id.daddr.a4 = daddr->s6_addr32[3];
        req.xsinfo.family      = AF_INET;
    } else {
        memcpy(&req.xsinfo.saddr, saddr, sizeof(req.xsinfo.saddr));
        memcpy(&req.xsinfo.id.daddr, daddr, sizeof(req.xsinfo.id.daddr));
        req.xsinfo.family = preferred_family;
    }

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xsinfo));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = cmd;

    hip_xfrm_init_lft(&req.xsinfo.lft);

    req.xsinfo.mode     = XFRM_MODE_BEET;
    req.xsinfo.id.proto = IPPROTO_ESP;

    req.xsinfo.id.spi = htonl(spi);

    /* Selector */
    HIP_IFE(hip_xfrm_fill_selector(&req.xsinfo.sel, src_id, dst_id,
                                   0, hip_xfrmapi_sa_default_prefix,
                                   AF_INET6), -1);
    if (req.xsinfo.family == AF_INET && (sport || dport)) {
        hip_xfrm_fill_encap(&encap,
                            (sport ? sport : hip_get_local_nat_udp_port()),
                            (dport ? dport : hip_get_peer_nat_udp_port()),
                            saddr);
        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                          &encap, sizeof(encap)), -1);
    }

    {
        struct {
            struct xfrm_algo algo;
            char             buf[XFRM_ALGO_KEY_BUF_SIZE];
        } alg                    = { { { 0 } } };
        const char *const e_name = e_algo_names[ealg];
        const char *const a_name = a_algo_names[aalg];
        int               len;

        HIP_ASSERT(ealg < (int) sizeof(e_algo_names));
        HIP_ASSERT(aalg < (int) sizeof(a_algo_names));

        /* XFRMA_ALG_AUTH */
        HIP_IFE(hip_xfrm_algo_parse((void *) &alg, a_name,
                                    authkey->key, authkey_len,
                                    sizeof(alg.buf)), -1);
        len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_AUTH, &alg, len),
                -1);

        /* XFRMA_ALG_CRYPT */
        memset(&alg, 0, sizeof(alg));
        HIP_IFE(hip_xfrm_algo_parse((void *) &alg, e_name,
                                    enckey->key, enckey_len,
                                    sizeof(alg.buf)), -1);

        len = sizeof(struct xfrm_algo) + alg.algo.alg_key_len;

        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ALG_CRYPT,
                          &alg, len), -1);
    }

    HIP_IFE(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0, -1);

out_err:
    return err;
}

/**
 * delete a Security Association
 *
 * @param peer_addr Peer IP address
 * @param spi Security Parameter Index
 * @param rth
 * @param preferred_family
 * @param sport
 * @param dport
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
    } req = { { 0 } };
    struct xfrm_encap_tmpl encap;
    int                    err = 0;

    req.n.nlmsg_len   = NLMSG_LENGTH(sizeof(req.xsid));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type  = XFRM_MSG_DELSA;

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
        hip_xfrm_fill_encap(&encap,
                            (sport ? sport : hip_get_local_nat_udp_port()),
                            (dport ? dport : hip_get_peer_nat_udp_port()),
                            peer_addr);
        HIP_IFE(addattr_l(&req.n, sizeof(req.buf), XFRMA_ENCAP,
                          &encap, sizeof(encap)), -1);
    }


    req.xsid.spi = htonl(spi);
    if (spi) {
        req.xsid.proto = IPPROTO_ESP;
    }

    HIP_DEBUG("deleting xfrm state with spi 0x%x\n", spi);
    HIP_HEXDUMP("SA peer addr: ", &req.xsid.daddr, sizeof(req.xsid.daddr));
    HIP_IFEL(netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL) < 0, -1,
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
        prefix = use_full_prefix ? 32 : HIP_LSI_PREFIX_LEN;
    } else {
        prefix = use_full_prefix ? 128 : HIP_HIT_PREFIX_LEN;
    }

    return prefix;
}

/**
 * Set the netlink socket to control IPsec
 *
 * @param nl_ipsec netlink socket containing an initialized netlink socket
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
 * @param new_algo_names 0 to use old naming convention and 1 for new
 */
void hip_xfrm_set_algo_names(int new_algo_names)
{
    e_algo_names = new_algo_names ? E_ALGO_NAMES_NEW : E_ALGO_NAMES_OLD;
    a_algo_names = new_algo_names ? A_ALGO_NAMES_NEW : A_ALGO_NAMES_OLD;
}

/**
 * A wrapper to hip_xfrm_policy_flush()
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_policy(void)
{
    return hip_xfrm_policy_flush(hip_xfrmapi_nl_ipsec);
}

/**
 * A wrapper to hip_xfrm_sa_flush()
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_sa(void)
{
    return hip_xfrm_sa_flush(hip_xfrmapi_nl_ipsec);
}

/**
 * delete a Security Association
 *
 * @param spi the SPI number distinguishing the SA
 * @param peer_addr the destination address for the SA
 * @param direction HIP_SPI_DIRECTION_OUT or HIP_SPI_DIRECTION_IN
 * @param entry corresponding host association
 */
void hip_delete_sa(const uint32_t spi, const struct in6_addr *peer_addr,
                   const int direction, struct hip_hadb_state *entry)
{
    // Ignore the dst_addr, because xfrm accepts only one address.
    if (direction == HIP_SPI_DIRECTION_OUT && entry->outbound_sa_count > 0) {
        hip_xfrm_state_delete(hip_xfrmapi_nl_ipsec, peer_addr, spi, AF_INET6,
                              entry->local_udp_port, entry->peer_udp_port);
        entry->outbound_sa_count--;

        HIP_DEBUG("outbound IPsec SA deleted\n");
    } else if (direction == HIP_SPI_DIRECTION_IN &&
               entry->inbound_sa_count > 0) {
        hip_xfrm_state_delete(hip_xfrmapi_nl_ipsec, peer_addr, spi, AF_INET6,
                              entry->peer_udp_port, entry->local_udp_port);
        entry->inbound_sa_count--;

        HIP_DEBUG("inbound IPsec SA deleted\n");
    } else {
        HIP_DEBUG("No IPsec SA set up yet\n");
    }
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
 * @param direction the direction of the SA (HIP_SPI_DIRECTION_OUT or HIP_SPI_DIRECTION_IN)
 * @param entry corresponding host association
 * @return zero on success and non-zero on error
 * @note IPv4 addresses in IPv6 mapped format
 * @note If you make changes to this function, please change also
 * hipd/user_ipsec_sadb_api.c:hip_userspace_ipsec_add_sa().
 */
uint32_t hip_add_sa(const struct in6_addr *saddr,
                    const struct in6_addr *daddr,
                    const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    const uint32_t spi,
                    const int ealg,
                    const struct hip_crypto_key *enckey,
                    const struct hip_crypto_key *authkey,
                    const int direction,
                    struct hip_hadb_state *entry)
{
    int       err  = 0, enckey_len, authkey_len;
    int       aalg = ealg;
    in_port_t sport, dport;

    HIP_ASSERT(spi != 0);
    HIP_ASSERT(entry);

    HIP_IFEL(entry->disable_sas == 1, 0,
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

    HIP_IFEL(enckey_len < 0 || authkey_len < 0, 1,
             "Bad enc or auth key len\n");

    HIP_DEBUG("************************************\n");
    HIP_DEBUG_HIT("src_hit", src_hit);
    HIP_DEBUG_HIT("dst_hit", dst_hit);
    HIP_DEBUG_IN6ADDR("saddr", saddr);
    HIP_DEBUG_IN6ADDR("daddr", daddr);

    HIP_DEBUG("direction %d\n", direction);
    HIP_DEBUG("SPI=0x%x\n", spi);
    HIP_DEBUG("************************************\n");

    HIP_IFE(hip_xfrm_state_modify(hip_xfrmapi_nl_ipsec, XFRM_MSG_NEWSA,
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
 * @note  IPv4 addresses in IPv6 mapped format
 */
int hip_setup_hit_sp_pair(const struct in6_addr *src_id,
                          const struct in6_addr *dst_id,
                          const struct in6_addr *src_addr,
                          const struct in6_addr *dst_addr,
                          uint8_t proto,
                          int use_full_prefix)
{
    int     err    = 0;
    uint8_t prefix = hip_calc_sp_prefix(src_id, use_full_prefix);

    /* XX FIXME: remove the proto argument */
    HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, XFRM_MSG_NEWPOLICY,
                                   dst_id, src_id,
                                   src_addr, dst_addr,
                                   XFRM_POLICY_IN, proto, prefix,
                                   AF_INET6), -1);

    HIP_IFE(hip_xfrm_policy_modify(hip_xfrmapi_nl_ipsec, XFRM_MSG_NEWPOLICY,
                                   src_id, dst_id,
                                   dst_addr, src_addr,
                                   XFRM_POLICY_OUT, proto, prefix,
                                   AF_INET6), -1);

out_err:
    return err;
}

/**
 * delete a pair of Security Policies
 *
 * @param src_hit source HIT for the SP
 * @param dst_hit destination HIT for the SP
 * @param use_full_prefix one if we should use /128 prefix for HITs
 *                        or zero otherwise
 */
void hip_delete_hit_sp_pair(const hip_hit_t *src_hit,
                            const hip_hit_t *dst_hit,
                            const int use_full_prefix)
{
    uint8_t prefix = use_full_prefix ? 128 : HIP_HIT_PREFIX_LEN;

    hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, dst_hit, src_hit,
                           XFRM_POLICY_IN, prefix, AF_INET6);
    hip_xfrm_policy_delete(hip_xfrmapi_nl_ipsec, src_hit, dst_hit,
                           XFRM_POLICY_OUT, prefix, AF_INET6);
}

/**
 * delete the default Security Policy pair that triggers base exchanges
 *
 */
void hip_delete_default_prefix_sp_pair(void)
{
    hip_hit_t src_hit = { { { 0 } } }, dst_hit = { { { 0 } } };

    /* See the comment in hip_setup_sp_prefix_pair() */
    set_hit_prefix(&src_hit);
    set_hit_prefix(&dst_hit);

    hip_delete_hit_sp_pair(&src_hit, &dst_hit, 0);
}

/**
 * add the default security policy pair (based on HIT prefix) that
 * triggers all base exchanges
 *
 * @return zero on success and negative on failure
 */
int hip_setup_default_sp_prefix_pair(void)
{
    int             err     = 0;
    hip_hit_t       src_hit = { { { 0 } } }, dst_hit = { { { 0 } } };
    struct in6_addr ip      = { { { 0 } } };

    /* The OUTGOING and INCOMING policy is set to the generic value */
    set_hit_prefix(&src_hit);
    set_hit_prefix(&dst_hit);

    HIP_IFE(hip_setup_hit_sp_pair(&src_hit, &dst_hit, &ip, &ip, 0, 0), -1);

out_err:
    return err;
}
