/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
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

#define _BSD_SOURCE

#include <libipq.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "lib/core/builder.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "cache.h"
#include "port_bindings.h"
#include "firewall.h"
#include "lsi.h"
#include "reinject.h"


#define BUFSIZE HIP_MAX_PACKET

#define PROTO_STRING_MAX    16

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
                    const hip_lsi_t *src_lsi,
                    const hip_lsi_t *dst_lsi,
                    const struct in6_addr *src_ip,
                    const struct in6_addr *dst_ip)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(!dst_hit && !dst_ip && !dst_lsi,
             -1, "no destination hit, ip or lsi provided\n");

    /* NOTE: we need this sequence in order to process the incoming
     * message correctly */

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_TRIGGER_BEX, 0),
             -1, "build hdr failed\n");

    /* destination HIT, LSI or IP is obligatory */
    if (dst_hit) {
        HIP_DEBUG_HIT("dst_hit: ", dst_hit);
        HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* source HIT is optional */
    if (src_hit) {
        HIP_DEBUG_HIT("src_hit: ", src_hit);
        HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* destination HIT, LSI or IP is obligatory */
    if (dst_lsi) {
        HIP_DEBUG_INADDR("dst lsi: ", dst_lsi);
        HIP_IFEL(hip_build_param_contents(msg, dst_lsi, HIP_PARAM_LSI,
                                          sizeof(hip_lsi_t)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* source LSI is optional */
    if (src_lsi) {
        HIP_DEBUG_INADDR("src lsi: ", src_lsi);
        HIP_IFEL(hip_build_param_contents(msg, src_lsi, HIP_PARAM_LSI,
                                          sizeof(hip_lsi_t)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* destination HIT, LSI or IP is obligatory */
    if (dst_ip) {
        HIP_DEBUG_IN6ADDR("dst_ip: ", dst_ip);
        HIP_IFEL(hip_build_param_contents(msg, dst_ip, HIP_PARAM_IPV6_ADDR,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_IPV6_ADDR failed\n");
    }

    /* this again is optional */
    if (src_ip) {
        HIP_DEBUG_IN6ADDR("src_ip: ", src_ip);
        HIP_IFEL(hip_build_param_contents(msg, src_ip, HIP_PARAM_IPV6_ADDR,
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
        free(msg);
    }
    return err;
}

/**
 * Checks if the packet is a reinjection
 *
 * @param lsi         pointer to the source address
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
        const struct ip *iphdr = (const struct ip *) m->payload;
        ip_hdr_size = (iphdr->ip_hl * 4);
        protocol    = iphdr->ip_p;
        ttl         = iphdr->ip_ttl;
        HIP_DEBUG_LSI("Ipv4 address src ", &(iphdr->ip_src));
        HIP_DEBUG_LSI("Ipv4 address dst ", &(iphdr->ip_dst));
    } else {
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *) m->payload;
        ip_hdr_size = sizeof(struct ip6_hdr);         //Fixed size
        protocol    = ip6_hdr->ip6_nxt;
        ttl         = ip6_hdr->ip6_hlim;
        HIP_DEBUG_IN6ADDR("Orig packet src address: ", &(ip6_hdr->ip6_src));
        HIP_DEBUG_IN6ADDR("Orig packet dst address: ", &(ip6_hdr->ip6_dst));
        HIP_DEBUG_IN6ADDR("New packet src address:", src_hit);
        HIP_DEBUG_IN6ADDR("New packet dst address: ", dst_hit);
    }

    if ((int)m->data_len <= (BUFSIZE - ip_hdr_size)) {
        packet_length = m->data_len - ip_hdr_size;
        HIP_DEBUG("packet size smaller than buffer size\n");
    } else {
        packet_length = BUFSIZE - ip_hdr_size;
        HIP_DEBUG("HIP packet size greater than buffer size\n");
    }

    /* Note: using calloc to zero memory region here because I think
     * firewall_send_incoming_pkt() calculates checksum for TCP
     * from too long region sometimes (padding issue?) */
    msg = calloc((packet_length + sizeof(struct ip)), 1);
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
        free(msg);
    }
    return err;
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
 * @param lsi_support lsi support
 * @return            1 if translation not done
 *                    0 if packet reinjected with lsis as addresses
 */

int hip_fw_handle_incoming_hit(const ipq_packet_msg_t *m,
                               const struct in6_addr *ip_src,
                               const struct in6_addr *ip_dst,
                               const int lsi_support)
{
    int err                                               = 0;
    int verdict                                           = 1;
    int ip_hdr_size                                       = 0;
    int portDest                                          = 0;
    fw_cache_hl_t *entry                                  = NULL;
    enum hip_port_binding port_traffic_type = HIP_PORT_INFO_UNKNOWN;
    const struct ip6_hdr *ip6_hdr                         = NULL;
    struct in6_addr src_addr, dst_addr;

    ip6_hdr = (const struct ip6_hdr *) m->payload;
    ip_hdr_size = sizeof(struct ip6_hdr);

    switch (ip6_hdr->ip6_nxt) {
    case IPPROTO_UDP:
        portDest = ((const struct udphdr *) ((m->payload) + ip_hdr_size))->dest;
        break;
    case IPPROTO_TCP:
        portDest = ((const struct tcphdr *) ((m->payload) + ip_hdr_size))->dest;
        break;
    case IPPROTO_ICMPV6:
        HIP_DEBUG("ICMPv6 packet\n");
        break;
    default:
        HIP_DEBUG("Unhandled packet %d\n", ip6_hdr->ip6_nxt);
        break;
    }

    port_traffic_type = hip_port_bindings_get(ip6_hdr->ip6_nxt,
                                          portDest);

    if (port_traffic_type == HIP_PORT_INFO_IPV6BOUND) {
        HIP_DEBUG("Port %d is bound to an IPv6 address -> accepting packet\n", portDest);
        verdict = 1;
    } else if (port_traffic_type == HIP_PORT_INFO_IPV6UNBOUND) {
        HIP_DEBUG("Port %d is unbound or bound to an IPv4 address -> looking up in cache\n", portDest);
        HIP_IFEL(!(entry = hip_firewall_cache_db_match(ip_dst, ip_src,
                                                       FW_CACHE_HIT, 1)),
                 -1, "Failed to obtain from cache\n");

        /* Currently preferring LSIs over opp. connections */
        if (lsi_support) {
            HIP_DEBUG("Trying lsi transformation\n");
            HIP_DEBUG_LSI("lsi_our: ", &entry->lsi_our);
            HIP_DEBUG_LSI("lsi_peer: ", &entry->lsi_peer);
            IPV4_TO_IPV6_MAP(&entry->lsi_our, &dst_addr);
            IPV4_TO_IPV6_MAP(&entry->lsi_peer, &src_addr);
            HIP_IFEL(hip_reinject_packet(&src_addr, &dst_addr, m, 6, 1), -1,
                     "Failed to reinject with LSIs\n");
            HIP_DEBUG("Successful LSI transformation.\n");

            if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) {
                verdict = 1;             /* broadcast: dst may be ipv4 or ipv6 */
            } else {
                verdict = 0;             /* drop original */
            }
        } else {
            HIP_DEBUG("Trying sys opp transformation\n");
            HIP_DEBUG_IN6ADDR("ip_src: ", &entry->ip_peer);
            HIP_DEBUG_IN6ADDR("ip_dst: ", &entry->ip_our);
            HIP_IFEL(hip_reinject_packet(&entry->ip_peer, &entry->ip_our, m, 6, 1),
                     -1, "Failed to reinject with IP addrs\n");
            HIP_DEBUG("Successfull sysopp transformation. Drop orig\n");
            verdict = 0;
        }
    } else {
        HIP_DIE("hip_port_bindings_get() returned unknown return value %d\n", port_traffic_type);
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
    int err = 0;
    fw_cache_hl_t *entry_peer = NULL;

    if (lsi_dst) {
        HIP_DEBUG_LSI("lsi dst", lsi_dst);
    }

    entry_peer = hip_firewall_cache_db_match(lsi_src, lsi_dst, FW_CACHE_LSI, 1);

    if (!entry_peer) {
        HIP_IFEL(hip_trigger_bex(NULL, NULL, lsi_src, lsi_dst, NULL, NULL),
                 -1, "Base Exchange Trigger failed\n");
    } else if (entry_peer->state == HIP_STATE_NONE ||
               entry_peer->state == HIP_STATE_UNASSOCIATED) {
        HIP_IFEL(hip_trigger_bex(&entry_peer->hit_our,
                                 &entry_peer->hit_peer,
                                 &entry_peer->lsi_our,
                                 &entry_peer->lsi_peer,
                                 NULL, NULL),
                 -1, "Base Exchange Trigger failed\n");
    } else if (entry_peer->state == HIP_STATE_ESTABLISHED) {
        HIP_IFEL(hip_reinject_packet(&entry_peer->hit_our,
                                     &entry_peer->hit_peer,
                                     m, 4, 0),
                 -1, "Reinject failed\n");
    }

out_err:
    return err;
}
