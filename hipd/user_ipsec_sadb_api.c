/**
 * @file firewall/user_ipsec_sadb_api.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Provides the API used by the hipd to set up and maintain the
 * userspace IPsec state in the hipfw.
 *
 * @brief API used by the hipd to set up and maintain userspace IPsec state
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 **/

#include "user_ipsec_sadb_api.h"
#include "lib/core/esp_prot_common.h"
#include "user_ipsec_hipd_msg.h"
#include "lib/core/debug.h"
#include "lib/core/icomm.h"
#include "user.h"


/** generic send function used to send the below created messages
 *
 * @param	msg the message to be sent
 * @return	0, if correct, else != 0
 */
static int hip_userspace_ipsec_send_to_fw(const struct hip_common *msg)
{
    struct sockaddr_in6 hip_firewall_addr;
    struct in6_addr loopback = in6addr_loopback;
    int err                  = 0;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_firewall_addr.sin6_family = AF_INET6;
    hip_firewall_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_firewall_addr.sin6_addr, &loopback);

    err = hip_sendto_user(msg, (struct sockaddr *) &hip_firewall_addr);
    if (err < 0) {
        HIP_ERROR("sending of message to firewall failed\n");

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("sending of message to firewall successful\n");

        // this is needed if we want to use HIP_IFEL
        err = 0;
    }

out_err:
    return err;
}

/** adds a new SA entry for the specified direction to the sadb in userspace ipsec
 * @note  If you make changes to this function, please change also hip_add_sa()
 *
 * @param	src_addr outer globally routable source ip address
 * @param	dst_addr outer globally routable destination ip address
 * @param	inner_src_addr inner source address
 * @param	inner_dst_addr inner destination address
 * @param	spi ipsec spi for demultiplexing
 * @param	ealg crypto transform to be used for the SA
 * @param	enc_key raw encryption key
 * @param	auth_key raw authentication key
 * @param	retransmission notification if this event derives from a retransmission
 * @param	direction represents inbound or outbound direction
 * @param	update notification if this event derives from an update
 * @param	entry host association entry for this connection
 * @return	0, if correct, otherwise -1
 */
uint32_t hip_userspace_ipsec_add_sa(const struct in6_addr *saddr,
                                    const struct in6_addr *daddr,
                                    const struct in6_addr *src_hit,
                                    const struct in6_addr *dst_hit,
                                    const uint32_t spi, const int ealg,
                                    const struct hip_crypto_key *enckey,
                                    const struct hip_crypto_key *authkey,
                                    const int retransmission,
                                    const int direction, const int update,
                                    hip_ha_t *entry)
{
    struct hip_common *msg = NULL;
    in_port_t sport, dport;
    int err                = 0;

    HIP_ASSERT(spi != 0);

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

    HIP_IFEL(!(msg = create_add_sa_msg(saddr, daddr, src_hit, dst_hit, spi, ealg, enckey,
                                       authkey, retransmission, direction, update, entry)), -1,
             "failed to create add_sa message\n");

    HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

out_err:
    return err;
}

/** deletes the specified SA entry from the sadb in userspace ipsec
 *
 * @param	spi ipsec spi for demultiplexing
 * @param	src_addr outer globally routable source ip address
 * @param	dst_addr outer globally routable destination ip address
 * @param	family protocol family of above addresses
 * @param	src_port local port for this host association
 * @param	dst_port peer port for this host association
 */
void hip_userspace_ipsec_delete_sa(const uint32_t spi,
                                   const struct in6_addr *not_used,
                                   const struct in6_addr *dst_addr,
                                   const int direction,
                                   hip_ha_t *entry)
{
    struct hip_common *msg = NULL;
    in_port_t sport, dport;
    int err                = 0;

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

    HIP_IFEL(!(msg = create_delete_sa_msg(spi, not_used, dst_addr, AF_INET6, sport, dport)),
             -1, "failed to create delete_sa message\n");

    HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

out_err:
    return;
}

/** flushes all SA entries in the sadb in userspace ipsec
 *
 * @return	0, if correct, else != 0
 */

int hip_userspace_ipsec_flush_all_sa(void)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    HIP_IFEL(!(msg = create_flush_all_sa_msg()), -1,
             "failed to create delete_sa message\n");

    HIP_IFEL(hip_userspace_ipsec_send_to_fw(msg), -1, "failed to send msg to fw\n");

out_err:
    return err;
}

/**
 * Not implemented
 *
 * @note security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets
 **/
int hip_userspace_ipsec_setup_hit_sp_pair(const hip_hit_t *src_hit,
                                          const hip_hit_t *dst_hit,
                                          const struct in6_addr *src_addr,
                                          const struct in6_addr *dst_addr,
                                          const uint8_t proto,
                                          const int use_full_prefix,
                                          const int update)
{
    /* if called anywhere in hipd code, we pretend to have had a successful
     * operation */
    return 0;
}

/**
 * Not implemented
 *
 * @note security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets
 **/
void hip_userspace_ipsec_delete_hit_sp_pair(const hip_hit_t *src_hit,
                                            const hip_hit_t *dst_hit,
                                            const uint8_t proto,
                                            const int use_full_prefix)
{
    // nothing to do here
}

/**
 * Not implemented
 *
 * @note: security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets
 **/
int hip_userspace_ipsec_flush_all_policy(void)
{
    /* if called anywhere in hipd code, we pretend to have had a successful
     * operation */
    return 0;
}

/**
 * Not implemented
 *
 * @note: security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could delete the iptables rules here instead of at firewall exit
 **/
void hip_userspace_ipsec_delete_default_prefix_sp_pair(void)
{
    // nothing to do here
}

/**
 * Not implemented
 *
 * @note: security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could set up the iptables rules here instead of at firewall init
 **/
int hip_userspace_ipsec_setup_default_sp_prefix_pair(void)
{
    /* if called anywhere in hipd code, we pretend to have had a successful
     * operation */
    return 0;
}
