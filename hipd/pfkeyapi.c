/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Hipd wrapper interface to access PFKEY APIs
 *
 * @author Diego Beltrami <diego.beltrami@gmail.com>
 *
 * @todo test this!
 * @see lib/tool/xfrmapi.c for the wrappers for XFRM API
 */

/* required for caddr_t */
#define _BSD_SOURCE

#include <lib/ipsec/pfkeyv2.h>
#include <linux/ipsec.h>

#include "config.h"
#include "lib/ipsec/libpfkey.h"
#include "pfkeyapi.h"
#include "lib/core/hip_udp.h"
#include "lib/core/keylen.h"
#include "lib/tool/pfkeysadb.h"

// FIXME: This must be turned to BEET when BEET will be supported by pfkey as well
#define HIP_IPSEC_DEFAULT_MODE IPSEC_MODE_BEET

/**
 * Given an in6_addr, this function correctly fills in a sock_addr (needs to be already allocated!)
 *
 * @param s_addr the output argument
 * @param addr the input argument
 */
static void get_sock_addr_from_in6(struct sockaddr *s_addr, const struct in6_addr *addr)
{
    memset(s_addr, 0, sizeof(struct sockaddr_storage));

    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        s_addr->sa_family = AF_INET;
        memcpy(hip_cast_sa_addr(s_addr), &addr->s6_addr32[3], hip_sa_addr_len(s_addr));
    } else {
        s_addr->sa_family = AF_INET6;
        memcpy(hip_cast_sa_addr(s_addr), addr, hip_sa_addr_len(s_addr));
    }
}

/**
 * Flush all IPsec Security Policies
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_policy(void)
{
    int so, len, err = 0;
    HIP_DEBUG("\n");
    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_DEBUG("FLushing all SP's\n");
    HIP_IFEBL(((len = pfkey_send_spdflush(so)) < 0), -1,
              pfkey_close(so), "ERROR in flushing policies %s\n", ipsec_strerror());
    HIP_DEBUG("FLushing all SP's was successful\n");
    return len;
out_err:
    HIP_ERROR("FLushing all SP's\n");
    return err;
}

/**
 * Flush all IPsec Security Associations
 *
 * @return zero on success and negative on error
 */
int hip_flush_all_sa(void)
{
    int so, len, err = 0;
    HIP_DEBUG("\n");
    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_DEBUG("Flushing all SA's\n");
    HIP_IFEBL(((len = pfkey_send_flush(so, SADB_SATYPE_ESP)) < 0), -1,
              pfkey_close(so), "ERROR in flushing policies %s\n", ipsec_strerror());
    return len;
out_err:
    return err;
}

/**
 * delete a Security Association
 *
 * @param spi the SPI number distinguishing the SA
 * @param peer_addr the destination address for the SA (unused)
 * @param not_used not used
 * @param direction HIP_SPI_DIRECTION_OUT or HIP_SPI_DIRECTION_IN
 * @param entry corresponding host association
 */
void hip_delete_sa(const uint32_t spi, const struct in6_addr *peer_addr,
                   const struct in6_addr *dst_addr,
                   const int direction, hip_ha_t *entry)
{
    int so, len, err = 0;
    struct sockaddr_storage ss_addr, dd_addr;
    struct sockaddr *saddr;
    struct sockaddr *daddr;
    in_port_t sport, dport;

    /* @todo: sport and dport should be used! */

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

    saddr = (struct sockaddr *) &ss_addr;
    daddr = (struct sockaddr *) &dd_addr;

    HIP_DEBUG("\n");
    HIP_DEBUG("spi=0x%x\n", spi);
    HIP_DEBUG_IN6ADDR("peer_addr", peer_addr);
    HIP_DEBUG_IN6ADDR("dst_addr", dst_addr);
    // Sanity check
    HIP_IFEL((!peer_addr || !dst_addr), -1, "Addresses not valid when deleting SA's\n");

    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    get_sock_addr_from_in6(saddr, peer_addr);
    get_sock_addr_from_in6(daddr, dst_addr);

    HIP_IFEBL(((len = pfkey_send_delete(so, SADB_SATYPE_ESP,  HIP_IPSEC_DEFAULT_MODE, saddr, daddr, spi)) < 0), -1,
              pfkey_close(so), "ERROR in deleting sa %s", ipsec_strerror());
out_err:
    return;
}

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
 * xfrmapi.c:add_sa()
 */
uint32_t hip_add_sa(const struct in6_addr *saddr, const struct in6_addr *daddr,
                    const struct in6_addr *src_hit, const struct in6_addr *dst_hit,
                    const uint32_t spi, const int ealg,
                    const struct hip_crypto_key *enckey,
                    const struct hip_crypto_key *authkey,
                    const int already_acquired,
                    const int direction, const int update,
                    hip_ha_t *entry)
{
    int so, len, err = 0, e_keylen, a_keylen;
    int aalg              = ealg;
    u_int wsize           = 4; /* XXX static size of window */
    struct sockaddr_storage ss_addr, dd_addr;
    struct sockaddr *s_saddr;
    struct sockaddr *d_saddr;
    uint32_t reqid        = 0;
    u_int32_t seq         = 0;
    u_int flags           = 0; // always zero
    u_int64_t lifebyte    = 0, lifetime = 0;
    //u_int8_t l_natt_type = HIP_UDP_ENCAP_ESPINUDP_NON_IKE;
    u_int8_t l_natt_type  = HIP_UDP_ENCAP_ESPINUDP;
    // FIXME: this parameter maybe should be related to some esp parameters (according to racoon source code)
    u_int16_t l_natt_frag = 0;
    /* Mappings from HIP to PFKEY algo names */
    u_int e_types[]       = {SADB_EALG_NULL,    SADB_X_EALG_AESCBC, SADB_EALG_3DESCBC, SADB_EALG_3DESCBC,
                             SADB_X_EALG_BLOWFISHCBC, SADB_EALG_NULL,     SADB_EALG_NULL};
    u_int a_algos[]       = {SADB_AALG_NONE, SADB_AALG_SHA1HMAC, SADB_AALG_SHA1HMAC, SADB_AALG_MD5HMAC,
                             SADB_AALG_SHA1HMAC,   SADB_AALG_SHA1HMAC, SADB_AALG_MD5HMAC};
    u_int e_type          = e_types[ealg];
    u_int a_type          = a_algos[aalg];
    in_port_t sport       = entry->local_udp_port;
    in_port_t dport       = entry->peer_udp_port;

    HIP_IFEL((entry->disable_sas == 1), 0,
             "SA creation disabled\n");

    a_keylen = hip_auth_key_length_esp(ealg);
    e_keylen = hip_enc_key_length(ealg);

    get_random_bytes(&reqid, sizeof(uint32_t));
    get_random_bytes(&seq, sizeof(uint32_t));

    HIP_DEBUG("\n");
    HIP_DEBUG_HIT("src_hit", src_hit);
    HIP_DEBUG_HIT("dst_hit", dst_hit);
    HIP_DEBUG_IN6ADDR("saddr", saddr);
    HIP_DEBUG_IN6ADDR("daddr", daddr);
    HIP_IFEL((!saddr || !daddr), 1, "Addresses not valid when adding SA's\n");

    HIP_IFEL(((so = pfkey_open()) < 0), 1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    s_saddr = (struct sockaddr *) &ss_addr;
    d_saddr = (struct sockaddr *) &dd_addr;
    get_sock_addr_from_in6(s_saddr, saddr);
    get_sock_addr_from_in6(d_saddr, daddr);

    if (direction == HIP_SPI_DIRECTION_OUT) {
        entry->outbound_sa_count++;
    } else {
        entry->inbound_sa_count++;
    }


    // NOTE: port numbers remains in host representation
    if (update) {
        if (sport) {
            // pfkey_send_update_nat when update = 1 and sport != 0
            HIP_IFEBL(((len = pfkey_send_update_nat(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
                                                    s_saddr, d_saddr, spi, reqid, wsize,
                                                    (void *) enckey, e_type, e_keylen,
                                                    a_type, a_keylen, flags,
                                                    0, lifebyte, lifetime, 0, seq,
                                                    l_natt_type, sport, dport, NULL,
                                                    l_natt_frag)) < 0),
                      1, pfkey_close(so), "ERROR in updating sa for nat: %s\n", ipsec_strerror());
        } else {
            // pfkey_send_update when update = 1 and sport == 0
            HIP_IFEBL(((len = pfkey_send_update(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
                                                s_saddr, d_saddr, spi, reqid, wsize,
                                                (void *) enckey, e_type, e_keylen,
                                                a_type, a_keylen, flags,
                                                0, lifebyte, lifetime, 0, seq)) < 0),
                      1, pfkey_close(so), "ERROR in updating sa: %s\n", ipsec_strerror());
        }
    } else {
        if (sport) {
            // pfkey_send_add_nat when update = 0 and sport != 0
            HIP_IFEBL(((len = pfkey_send_add_nat(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
                                                 s_saddr, d_saddr, spi, reqid, wsize,
                                                 (void *) enckey, e_type, e_keylen,
                                                 a_type, a_keylen, flags,
                                                 0, lifebyte, lifetime, 0, seq,
                                                 l_natt_type, sport, dport, NULL,
                                                 l_natt_frag)) < 0),
                      1, pfkey_close(so), "ERROR in adding sa for nat: %s\n", ipsec_strerror());
        } else {
            // pfkey_send_add when update = 0 and sport == 0
            HIP_IFEBL(((len = pfkey_send_add(so, SADB_SATYPE_ESP, HIP_IPSEC_DEFAULT_MODE,
                                             s_saddr, d_saddr, spi, reqid, wsize,
                                             (void *) enckey, e_type, e_keylen,
                                             a_type, a_keylen, flags,
                                             0, lifebyte, lifetime, 0, seq)) < 0),
                      1, pfkey_close(so), "ERROR in adding sa: %s\n", ipsec_strerror());
        }
    }

    return 0;

out_err:
    return err;
}

/**
 * modify an IPsec policy using PFKEY
 *
 * @param so the PF_KEY socket
 * @param src_hit source HIT
 * @param prefs source preferences
 * @param dst_hit destination HIT
 * @param prefd destination preferences
 * @param src_addr source address
 * @param dst_addr destination address
 * @param proto the protocol
 * @param cmd add or del
 * @param direction input or output direction
 * @return zero on success and non-zero on error
 */
static int hip_pfkey_policy_modify(int so, const hip_hit_t *src_hit, u_int prefs,
                                   const hip_hit_t *dst_hit, u_int prefd,
                                   const struct in6_addr *src_addr,
                                   const struct in6_addr *dst_addr,
                                   uint8_t proto, int cmd, int direction)
{
    int err                  = 0;
    struct sockaddr_storage ss_addr, dd_addr, ss_hit, dd_hit;
    struct sockaddr *s_saddr = NULL, *s_shit;
    struct sockaddr *d_saddr = NULL, *d_shit;
    caddr_t policy           = NULL;
    int policylen            = 0;
    int len                  = 0;
    u_int mode;
    HIP_DEBUG("\n");
    // Sanity check
    HIP_IFEL((src_hit == NULL || dst_hit == NULL), -1, "Invalid hit's\n");

    if (src_addr) {     // could happen with the delete
        s_saddr = (struct sockaddr *) &ss_addr;
        get_sock_addr_from_in6(s_saddr, src_addr);
    }

    if (dst_addr) {     // could happen with the delete
        d_saddr = (struct sockaddr *) &dd_addr;
        get_sock_addr_from_in6(d_saddr, dst_addr);
    }

    s_shit = (struct sockaddr *) &ss_hit;
    get_sock_addr_from_in6(s_shit, src_hit);
    d_shit = (struct sockaddr *) &dd_hit;
    get_sock_addr_from_in6(d_shit, dst_hit);
    if (proto) {
        mode = HIP_IPSEC_DEFAULT_MODE;
    } else {
        mode = IPSEC_MODE_TRANSPORT;
    }

    HIP_IFEL((getsadbpolicy(&policy, &policylen, direction, s_saddr, d_saddr, mode, cmd) < 0),
             -1, "Error in building the policy\n");

    if (cmd == SADB_X_SPDUPDATE) {
        HIP_IFEL((len = pfkey_send_spdupdate(so, s_shit, prefs, d_shit, prefd,
                                             proto, policy, policylen, 0) < 0), -1,
                 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
    } else if (cmd == SADB_X_SPDADD) {
        HIP_IFEL((len = pfkey_send_spdadd(so, s_shit, prefs, d_shit, prefd,
                                          proto, policy, policylen, 0) < 0), -1,
                 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
    } else {      // SADB_X_SPDDELETE
        HIP_IFEL((len = pfkey_send_spddelete(so, s_shit, prefs, d_shit, prefd,
                                             proto, policy, policylen, 0) < 0), -1,
                 "libipsec failed send_x4 (%s)\n", ipsec_strerror());
    }

    return len;
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
int hip_setup_hit_sp_pair(const hip_hit_t *src_hit,
                          const hip_hit_t *dst_hit,
                          const struct in6_addr *src_addr,
                          const struct in6_addr *dst_addr,
                          uint8_t proto,
                          int use_full_prefix,
                          int update)
{
    int so, err = 0;
    uint8_t prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;
    int cmd   = update ? SADB_X_SPDUPDATE : SADB_X_SPDADD;

    HIP_DEBUG("\n");
    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_DEBUG("Adding a pair of SP\n");

    HIP_IFEBL((hip_pfkey_policy_modify(so, dst_hit, prefix, src_hit,
                                       prefix, src_addr, dst_addr,
                                       proto, cmd, IPSEC_DIR_INBOUND) < 0),
              -1, pfkey_close(so), "ERROR in %s the inbound policy\n", update ? "updating" : "adding");

    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_IFEBL((hip_pfkey_policy_modify(so, src_hit, prefix, dst_hit,
                                       prefix, dst_addr, src_addr,
                                       proto, cmd, IPSEC_DIR_OUTBOUND) < 0),
              -1, pfkey_close(so), "ERROR in %s the outbound policy\n", update ? "updating" : "adding");
    return 0;
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
void hip_delete_hit_sp_pair(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                            const uint8_t proto, const int use_full_prefix)
{
    int so, err = 0;
    uint8_t prefix = (use_full_prefix) ? 128 : HIP_HIT_PREFIX_LEN;

    HIP_DEBUG("\n");
    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_IFEBL((hip_pfkey_policy_modify(so, dst_hit, prefix, src_hit,
                                       prefix, NULL, NULL,
                                       proto, SADB_X_SPDDELETE, IPSEC_DIR_INBOUND) < 0),
              -1, pfkey_close(so), "ERROR in deleting the inbound policy\n");

    HIP_IFEL(((so = pfkey_open()) < 0), -1, "ERROR in opening pfkey socket: %s\n", ipsec_strerror());

    HIP_IFEBL((hip_pfkey_policy_modify(so, src_hit, prefix, dst_hit,
                                       prefix, NULL, NULL,
                                       proto, SADB_X_SPDDELETE, IPSEC_DIR_OUTBOUND) < 0),
              -1, pfkey_close(so), "ERROR in deleting the outbound policy\n");
out_err:
    return;
}

/**
 * delete the default Security Policy pair that triggers base exchanges
 *
 */
void hip_delete_default_prefix_sp_pair(void)
{
    // Currently unused
    HIP_DEBUG("\n");
}

/**
 * add the default security policy pair (based on HIT prefix) that
 * triggers all base exchanges
 *
 * @return zero on success and negative on failure
 */
int hip_setup_default_sp_prefix_pair(void)
{
    // currently this function is not needed
    HIP_DEBUG("\n");
    return 0;
}
