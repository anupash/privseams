/**
 * @file firewall/lsi.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file provides translation between HITs and LSIs. Outgoing
 * LSI-based packets are all captured, translated to HIT-based packets
 * and reinjected back to the networking stack for delivery. Incoming
 * HIT-based packets are either passed as they are or translated to
 * LSI-based packets depending on destination transport port. If there
 * is an IPv6 application listening on the destination port, the
 * packet is passed as it is. Otherwise, the packet is translated to
 * the corresponding LSIs. See the following document for more technical
 * details:
 *
 * <a href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>
 *
 * @brief Local-Scope Identifier (LSI) input and output processing
 *
 * @author Teresa Finez
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "cache.h"
#include "cache_port.h"
#include "firewall.h"
#include "firewalldb.h"
#include "lsi.h"
#include "lib/core/builder.h"
#include "lib/core/message.h"

#define BUFSIZE HIP_MAX_PACKET

/**
 * build a message for hipd to trigger a base exchange
 *
 * @param src_hit an optional source HIT for the I1
 * @param dst_hit a destination HIT for the I1
 * @param src_lsi an optional source LSI (corresponding to a local HIT)
 * @param dst_lsi a destination LSI for the I1
 * @param src_ip  an optional source IP address for the I1
 * @param dst_ip  a destination IP for the I1
 * @return        zero on success or negative on error

 * @note Many of the parameters are optional, but at least a
 * destination LSI, HIT or IP (for opportunistic BEX) must to be
 * provided
 */
int hip_trigger_bex(const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    struct in6_addr *src_lsi,
                    struct in6_addr *dst_lsi,
                    struct in6_addr *src_ip,
                    struct in6_addr *dst_ip)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(!dst_hit && !dst_ip, -1,
             "neither destination hit nor ip provided\n");

    /* NOTE: we need this sequence in order to process the incoming
     * message correctly */

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_BEX, 0),
             -1, "build hdr failed\n");

    /* destination HIT, LSI or IP are obligatory */
    if (dst_hit) {
        HIP_DEBUG_HIT("dst_hit: ", dst_hit);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_hit),
                                          HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* source HIT is optional */
    if (src_hit) {
        HIP_DEBUG_HIT("src_hit: ", src_hit);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_hit),
                                          HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* destination LSI is obligatory */
    if (dst_lsi) {
        HIP_DEBUG_IN6ADDR("dst lsi: ", dst_lsi);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_lsi),
                                          HIP_PARAM_LSI,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* source LSI is optional */
    if (src_lsi) {
        HIP_DEBUG_IN6ADDR("src lsi: ", src_lsi);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_lsi),
                                          HIP_PARAM_LSI,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* if no destination HIT is provided, at least destination IP must
       exist */
    if (dst_ip) {
        HIP_DEBUG_IN6ADDR("dst_ip: ", dst_ip);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_ip),
                                          HIP_PARAM_IPV6_ADDR,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_IPV6_ADDR failed\n");
    }

    /* this again is optional */
    if (src_ip) {
        HIP_DEBUG_IN6ADDR("src_ip: ", src_ip);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_ip),
                                          HIP_PARAM_IPV6_ADDR,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_IPV6_ADDR failed\n");
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
    HIP_DEBUG("Send_recv msg succeed \n");

out_err:
    if (msg) {
        HIP_FREE(msg);
    }
    return err;
}

/**
 * Checks if the packet is a reinjection
 *
 * @param ip_src      pointer to the source address
 * @return            1 if the dst id is a local lsi
 *                    0 otherwise
 */
int hip_is_packet_lsi_reinjection(hip_lsi_t *lsi)
{
    hip_lsi_t *local_lsi;
    int err = 0;
    HIP_IFEL(!(local_lsi = hip_fw_get_default_lsi()), -1,
             "Failed to get default LSI");
    if (local_lsi->s_addr == lsi->s_addr) {
        err = 1;
    } else {
        err = 0;
    }
    HIP_DEBUG_LSI("local lsi", local_lsi);
    HIP_DEBUG("Reinjection: %d\n", err);
out_err:
    return err;
}

/**
 * get the state of the bex for a pair of ip addresses.
 *
 * @param src_ip       input for finding the correct entries
 * @param dst_ip       input for finding the correct entries
 * @param src_hit      output data of the correct entry
 * @param dst_hit      output data of the correct entry
 * @param src_lsi      output data of the correct entry
 * @param dst_lsi      output data of the correct entry
 * @return             the state of the bex if the entry is found
 *                     otherwise returns -1
 */
int hip_get_bex_state_from_LSIs(hip_lsi_t       *src_lsi,
                                hip_lsi_t       *dst_lsi,
                                struct in6_addr *src_ip,
                                struct in6_addr *dst_ip,
                                struct in6_addr *src_hit,
                                struct in6_addr *dst_hit)
{
    int err = 0, res = -1;
    struct hip_tlv_common *current_param = NULL;
    struct hip_common *msg               = NULL;
    struct hip_hadb_user_info_state *ha;

    HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
             -1, "Building of daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
        ha = hip_get_param_contents_direct(current_param);

        if ((ipv4_addr_cmp(dst_lsi, &ha->lsi_our) == 0)  &&
            (ipv4_addr_cmp(src_lsi, &ha->lsi_peer) == 0)) {
            *src_hit = ha->hit_peer;
            *dst_hit = ha->hit_our;
            *src_ip  = ha->ip_peer;
            *dst_ip  = ha->ip_our;
            res      = ha->state;
            break;
        } else if ((ipv4_addr_cmp(src_lsi, &ha->lsi_our) == 0)  &&
                   (ipv4_addr_cmp(dst_lsi, &ha->lsi_peer) == 0)) {
            *src_hit = ha->hit_our;
            *dst_hit = ha->hit_peer;
            *src_ip  = ha->ip_our;
            *dst_ip  = ha->ip_peer;
            res      = ha->state;
            break;
        }
    }

out_err:
    if (msg) {
        HIP_FREE(msg);
    }
    return res;
}

/**
 * Analyzes first whether the ipv6 packet belongs to an ipv6 socket.
 * If not, it then analyzes whether the packet belongs to an
 * ipv4 socket with an LSI as IP address.
 * If not LSI data either, reinjects as ipv4 data.
 *
 * @param m           pointer to the packet
 * @param ip_src      ipv6 source address
 * @param ip_dst      ipv6 destination address
 * @return            1 if translation not done
 *                    0 if packet reinjected with lsis as addresses
 */

int hip_fw_handle_incoming_hit(const ipq_packet_msg_t *m,
                               const struct in6_addr *ip_src,
                               const struct in6_addr *ip_dst,
                               const int lsi_support)
{
    int err                                    = 0;
    int verdict                                = 1;
    int ip_hdr_size                            = 0;
    int portDest                               = 0;
    int process_as_lsi                         = 0;
    char *proto                                = NULL;
    hip_lsi_t lsi_our                          = {0};
    hip_lsi_t lsi_peer                         = {0};
    struct in6_addr src_addr, dst_addr;
    struct in_addr src_v4, dst_v4;
    struct ip6_hdr *ip6_hdr                    = (struct ip6_hdr *) m->payload;
    firewall_port_cache_hl_t *port_cache_entry = NULL;

    ip_hdr_size = sizeof(struct ip6_hdr);

    switch (ip6_hdr->ip6_nxt) {
    case IPPROTO_UDP:
        portDest = ((struct udphdr *) ((m->payload) + ip_hdr_size))->dest;
        proto    = "udp6";
        break;
    case IPPROTO_TCP:
        portDest = ((struct tcphdr *) ((m->payload) + ip_hdr_size))->dest;
        proto    = "tcp6";
        break;
    case IPPROTO_ICMPV6:
        HIP_DEBUG("ICMPv6 packet\n");
        //goto out_err;
        break;
    default:
        HIP_DEBUG("Unhandled packet %d\n", ip6_hdr->ip6_nxt);
        //goto out_err;
        break;
    }

    /* port caching */
    port_cache_entry = hip_firewall_port_cache_db_match(portDest,
                                                        ip6_hdr->ip6_nxt);

    if (port_cache_entry &&
        (port_cache_entry->traffic_type ==
         FIREWALL_PORT_CACHE_IPV6_TRAFFIC)) {
        verdict = 1;
        HIP_DEBUG("Cached port, accepting\n");
        goto out_err;
    }

    if (lsi_support) {
        /* Currently preferring LSIs over opp. connections */
        process_as_lsi = 1;
    } else {
        HIP_ASSERT(1);
    }

    HIP_IFEL(hip_firewall_cache_db_match(ip_dst, ip_src,
                                         &lsi_our, &lsi_peer,
                                         &dst_addr, &src_addr,
                                         NULL),
             -1, "Failed to obtain from cache\n");

    if (process_as_lsi) {
        HIP_DEBUG("Trying lsi transformation\n");
        HIP_DEBUG_LSI("lsi_our: ", &lsi_our);
        HIP_DEBUG_LSI("lsi_peer: ", &lsi_peer);
        IPV4_TO_IPV6_MAP(&lsi_our, &src_addr);
        IPV4_TO_IPV6_MAP(&lsi_peer, &dst_addr);
        HIP_IFEL(hip_reinject_packet(&dst_addr, &src_addr, m, 6, 1), -1,
                 "Failed to reinject with LSIs\n");
        HIP_DEBUG("Successful LSI transformation.\n");

        if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) {
            verdict = 1;             /* broadcast: dst may be ipv4 or ipv6 */
        } else {
            verdict = 0;             /* drop original */
        }
    } else {
        HIP_DEBUG("Trying sys opp transformation\n");
        IPV6_TO_IPV4_MAP(&src_addr, &src_v4);
        IPV6_TO_IPV4_MAP(&dst_addr, &dst_v4);
        HIP_DEBUG_IN6ADDR("ip_src: ", &src_addr);
        HIP_DEBUG_IN6ADDR("ip_dst: ", &dst_addr);
        HIP_IFEL(hip_reinject_packet(&src_addr, &dst_addr, m, 6, 1), -1,
                 "Failed to reinject with IP addrs\n");
        HIP_DEBUG("Successfull sysopp transformation. Drop orig\n");
        verdict = 0;
    }

out_err:

    if (err) {
        return 1;         /* Accept original */
    } else {
        return verdict;
    }
}

/**
 * Checks if the outgoing packet with lsis has already ESTABLISHED the Base Exchange
 * with the peer host. In case the BEX is not done, it triggers it. Otherwise, it looks up
 * in the local database the necessary information for doing the packet reinjection with HITs.
 *
 * @param m           pointer to the packet
 * @param lsi_src     source LSI
 * @param lsi_dst     destination LSI
 * @return            err during the BEX
 */
int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *lsi_src,
                               struct in_addr *lsi_dst)
{
    int err = 0, state_ha, new_fw_entry_state;
    struct in6_addr src_lsi, dst_lsi;
    struct in6_addr src_hit, dst_hit;
    struct in6_addr src_ip, dst_ip;
    firewall_hl_t *entry_peer = NULL;

    if (lsi_dst) {
        HIP_DEBUG_LSI("lsi dst", lsi_dst);
    }

    memset(&src_lsi, 0, sizeof(struct in6_addr));
    memset(&dst_lsi, 0, sizeof(struct in6_addr));
    memset(&src_hit, 0, sizeof(struct in6_addr));
    memset(&dst_hit, 0, sizeof(struct in6_addr));
    memset(&src_ip, 0, sizeof(struct in6_addr));
    memset(&dst_ip, 0, sizeof(struct in6_addr));

    /* get the corresponding ip address for this lsi,
     * as well as the current ha state */
    if (hip_firewall_cache_db_match(NULL, NULL, lsi_src, lsi_dst,
                                    &src_ip, &dst_ip, &state_ha)) {
        HIP_DEBUG("No HA found yet\n");
    }

    entry_peer = (firewall_hl_t *) hip_firewall_ip_db_match(&dst_ip);
    if (entry_peer) {
        HIP_DEBUG("IP db match\n");
        /* if the firewall entry is still undefined
         * check whether the base exchange has been established */
        if (entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT) {
            /* find the correct state for the fw entry state */
            if (state_ha == HIP_STATE_ESTABLISHED) {
                new_fw_entry_state = FIREWALL_STATE_BEX_ESTABLISHED;
            } else if ((state_ha == HIP_STATE_FAILED)  ||
                       (state_ha == HIP_STATE_CLOSING) ||
                       (state_ha == HIP_STATE_CLOSED)) {
                new_fw_entry_state = FIREWALL_STATE_BEX_NOT_SUPPORTED;
            } else {
                new_fw_entry_state = FIREWALL_STATE_BEX_DEFAULT;
            }

            /* update fw entry state accordingly */
            hip_firewall_update_entry(NULL, NULL, NULL, &dst_ip,
                                      FIREWALL_STATE_BEX_ESTABLISHED);

            /* reobtain the entry in case it has been updated */
            entry_peer = hip_firewall_ip_db_match(&dst_ip);
        }

        /* decide whether to reinject the packet */
        if (entry_peer->bex_state == FIREWALL_STATE_BEX_ESTABLISHED) {
            HIP_IFEL(hip_reinject_packet(&entry_peer->hit_our,
                                         &entry_peer->hit_peer,
                                         m, 4, 0),
                     -1, "Failed to reinject\n");
        }
    } else {
        HIP_DEBUG("no ip db match\n");
        /* add default entry in the firewall db */
        HIP_IFEL(hip_firewall_add_default_entry(&dst_ip), -1,
                 "Adding of fw entry failed\n");

        /* Check if bex is already established: server case.
         * Get current connection state from hipd */
        state_ha = hip_get_bex_state_from_LSIs(lsi_src, lsi_dst,
                                               &src_ip, &dst_ip,
                                               &src_hit, &dst_hit);

        if ((state_ha == -1)                     ||
            (state_ha == HIP_STATE_NONE)         ||
            (state_ha == HIP_STATE_UNASSOCIATED)) {
            /* initialize bex */
            IPV4_TO_IPV6_MAP(lsi_src, &src_lsi);
            IPV4_TO_IPV6_MAP(lsi_dst, &dst_lsi);
            HIP_IFEL(hip_trigger_bex(&src_hit, &dst_hit, &src_lsi,
                                     &dst_lsi, NULL, NULL),
                     -1, "Base Exchange Trigger failed\n");
            /* update fw db entry */
            HIP_IFEL(hip_firewall_update_entry(&src_hit, &dst_hit,
                                               lsi_dst, &dst_ip,
                                               FIREWALL_STATE_BEX_DEFAULT), -1,
                     "Failed to update fw entry\n");
        }
        if (state_ha == HIP_STATE_ESTABLISHED) {
            /* update fw db entry */
            HIP_IFEL(hip_firewall_update_entry(&src_hit, &dst_hit,
                                               lsi_dst, &dst_ip,
                                               FIREWALL_STATE_BEX_ESTABLISHED),
                     -1, "Failed to update fw entry\n");

            HIP_IFEL(hip_reinject_packet(&src_hit, &dst_hit, m, 4, 0),
                     -1, "Reinject failed\n");
        }
    }
out_err:
    return err;
}

/**
 * Ask hipd the HIT of the peer corresponding to the give IP address. Works
 * similarly to the hip_request_peer_hit_from_hipd() function.
 *
 * @param peer_ip IP address of the peer
 * @param peer_hit write the HIT of the peer to this output variable
 * @param local_hit local HIT being used
 * @param src_tcp_port TCP source port
 * @param dst_tcp_port TCP destination port
 * @param fallback unused variable
 * @param reject unused variable
 *
 * @note the TCP ports are relevant only for the TCP extensions for opp. mode
 * @todo remove fallback and reject variables
 */
int hip_request_peer_hit_from_hipd_at_firewall(const struct in6_addr *peer_ip,
                                               struct in6_addr *peer_hit,
                                               const struct in6_addr *local_hit,
                                               in_port_t *src_tcp_port,
                                               in_port_t *dst_tcp_port,
                                               int *fallback,
                                               int *reject)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    *fallback = 1;
    *reject   = 0;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0),
             -1, "build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg, (void *) (local_hit),
                                      HIP_PARAM_HIT_LOCAL,
                                      sizeof(struct in6_addr)),
             -1, "build param HIP_PARAM_HIT  failed\n");

    HIP_IFEL(hip_build_param_contents(msg, (void *) (peer_ip),
                                      HIP_PARAM_IPV6_ADDR_PEER,
                                      sizeof(struct in6_addr)),
             -1, "build param HIP_PARAM_IPV6_ADDR failed\n");

    /* this message has to be delivered with the async socket because
     * opportunistic mode responds asynchronously */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_async_sock),
             -1, "send msg failed\n");

    _HIP_DEBUG("send_recv msg succeed\n");

out_err:
    if (msg) {
        free(msg);
    }
    return err;
}

/**
 * Executes the packet reinjection
 *
 *
 * @param src_hit              ipv6 source address
 * @param dst_hit              ipv6 destination address
 * @param m                    pointer to the packet
 * @param ipOrigTraffic        type of Traffic (IPv4 or IPv6)
 * @param incoming             packet direction
 * @return                     err during the reinjection
 */
int hip_reinject_packet(const struct in6_addr *src_hit,
                        const struct in6_addr *dst_hit,
                        const ipq_packet_msg_t *m,
                        const int ipOrigTraffic,
                        const int incoming)
{
    int err              = 0;
    int ip_hdr_size      = 0;
    int packet_length    = 0;
    int protocol         = 0;
    int ttl              = 0;
    uint8_t *msg              = NULL;
    struct icmphdr *icmp = NULL;

    if (ipOrigTraffic == 4) {
        struct ip *iphdr = (struct ip *) m->payload;
        ip_hdr_size = (iphdr->ip_hl * 4);
        protocol    = iphdr->ip_p;
        ttl         = iphdr->ip_ttl;
        HIP_DEBUG_LSI("Ipv4 address src ", &(iphdr->ip_src));
        HIP_DEBUG_LSI("Ipv4 address dst ", &(iphdr->ip_dst));
    } else {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *) m->payload;
        ip_hdr_size = sizeof(struct ip6_hdr);         //Fixed size
        protocol    = ip6_hdr->ip6_nxt;
        ttl         = ip6_hdr->ip6_hlim;
        HIP_DEBUG_IN6ADDR("Orig packet src address: ", &(ip6_hdr->ip6_src));
        HIP_DEBUG_IN6ADDR("Orig packet dst address: ", &(ip6_hdr->ip6_dst));
        HIP_DEBUG_IN6ADDR("New packet src address:", src_hit);
        HIP_DEBUG_IN6ADDR("New packet dst address: ", dst_hit);
    }

    if (m->data_len <= (BUFSIZE - ip_hdr_size)) {
        packet_length = m->data_len - ip_hdr_size;
        HIP_DEBUG("packet size smaller than buffer size\n");
    } else {
        packet_length = BUFSIZE - ip_hdr_size;
        HIP_DEBUG("HIP packet size greater than buffer size\n");
    }

    _HIP_DEBUG("Reinject packet packet length (%d)\n", packet_length);
    _HIP_DEBUG("      Protocol %d\n", protocol);
    _HIP_DEBUG("      ipOrigTraffic %d \n", ipOrigTraffic);

    /* Note: using calloc to zero memory region here because I think
     * firewall_send_incoming_pkt() calculates checksum
     * from too long region sometimes. See bug id 874 */
    msg = (uint8_t *) calloc((packet_length + sizeof(struct ip)), 1);
    memcpy(msg, (m->payload) + ip_hdr_size, packet_length);

    if (protocol == IPPROTO_ICMP && incoming) {
        icmp = (struct icmphdr *) msg;
        HIP_DEBUG("incoming ICMP type=%d code=%d\n",
                  icmp->type, icmp->code);
        /* Manually built due to kernel messed up with the
         * ECHO_REPLY message. Kernel was building an answer
         * message with equals @src and @dst*/
        if (icmp->type == ICMP_ECHO) {
            icmp->type = ICMP_ECHOREPLY;
            err        = hip_firewall_send_outgoing_pkt(dst_hit, src_hit,
                                                        msg, packet_length,
                                                        protocol);
        } else {
            err = hip_firewall_send_incoming_pkt(src_hit, dst_hit,
                                                 msg, packet_length,
                                                 protocol, ttl);
        }
    } else {
        if (incoming) {
            HIP_DEBUG("Firewall send to the kernel an incoming packet\n");
            err = hip_firewall_send_incoming_pkt(src_hit,
                                                 dst_hit, msg,
                                                 packet_length,
                                                 protocol, ttl);
        } else {
            HIP_DEBUG("Firewall send to the kernel an outgoing packet\n");
            err = hip_firewall_send_outgoing_pkt(src_hit,
                                                 dst_hit, msg,
                                                 packet_length,
                                                 protocol);
        }
    }

    if (msg) {
        HIP_FREE(msg);
    }
    return err;
}
