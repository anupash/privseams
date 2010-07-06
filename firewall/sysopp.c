/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * System-based opportunistic mode for HIP. In contrast to the library-based
 * opportunistic mode, this code hooks by iptables instead of LD_PRELOAD.
 * See the following papers for more information:
 *
 * - <a href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>
 * - <a href="http://www.iki.fi/miika/docs/ccnc09.pdf">
 * Miika Komu and Janne Lindqvist, Leap-of-Faith Security is Enough
 * for IP Mobility, 6th Annual IEEE Consumer
 * Communications & Networking Conference IEEE CCNC 2009, Las Vegas,
 * Nevada, January 2009</a>
 *
 * @brief System-based opportunistic mode for HIP
 * @author Teresa Finez
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include <arpa/inet.h>
#include <sys/socket.h>

#include "lib/core/builder.h"
#include "lib/core/hostid.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "cache.h"
#include "firewall.h"
#include "helpers.h"
#include "lsi.h"
#include "sysopp.h"

/**
 * flush iptables rules for system-based opportunistic mode
 */
void hip_fw_flush_system_based_opp_chains(void)
{
    system_print("iptables -F HIPFWOPP-INPUT");
    system_print("iptables -F HIPFWOPP-OUTPUT");
}

/**
 * Ask hipd to contact a peer in opportunistic mode
 *
 * @param peer_ip IP address of the peer
 * @param local_hit local HIT to use
 *
 */
static int hip_fw_trigger_opportunistic_bex(const struct in6_addr *peer_ip,
                                            const struct in6_addr *local_hit)
{
    struct hip_common *msg = NULL;
    int err = 0;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_PEER_HIT, 0),
             -1, "build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg, local_hit,
                                      HIP_PARAM_HIT_LOCAL,
                                      sizeof(struct in6_addr)),
             -1, "build param HIP_PARAM_HIT  failed\n");

    HIP_IFEL(hip_build_param_contents(msg, peer_ip,
                                      HIP_PARAM_IPV6_ADDR_PEER,
                                      sizeof(struct in6_addr)),
             -1, "build param HIP_PARAM_IPV6_ADDR failed\n");

    /* this message has to be delivered with the async socket because
     * opportunistic mode responds asynchronously */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_async_sock),
             -1, "send msg failed\n");

out_err:
    if (msg) {
        free(msg);
    }
    return err;
}

/**
 * Add a by-pass rule to skip opportunistic processing for a peer
 * that was found non-HIP capable. Offers a significant speed up.
 *
 * @param ctx the packet context
 * @param verdict the verdict to assign for the packet
 */
static void hip_fw_add_non_hip_peer(const hip_fw_context_t *ctx,
                                    const int verdict)
{
    char command[64];
    char addr_str[INET_ADDRSTRLEN];
    struct in_addr addr_v4;

    IPV6_TO_IPV4_MAP(&ctx->dst, &addr_v4);

    if (!inet_ntop(AF_INET, &addr_v4, addr_str,
                   sizeof(struct sockaddr_in))) {
        HIP_ERROR("inet_ntop() failed\n");
        return;
    }

    HIP_DEBUG("Adding rule for non-hip-capable peer: %s\n", addr_str);

    snprintf(command, sizeof(command),
             "iptables -I HIPFWOPP-INPUT -s %s -j %s",
             addr_str, verdict ? "ACCEPT" : "DROP");
    system_print(command);

    snprintf(command, sizeof(command),
             "iptables -I HIPFWOPP-OUTPUT -d %s -j %s",
             addr_str, verdict ? "ACCEPT" : "DROP");
    system_print(command);

    /* The cache entry is no longer necessary. Let's free it. */
    hip_firewall_cache_db_del_entry(&ctx->src, &ctx->dst, FW_CACHE_IP);
}

/**
 * Checks if the outgoing packet has already ESTABLISHED
 * the Base Exchange with the peer host. In case the BEX
 * is not done, it triggers it. Otherwise, it looks up
 * in the local database the necessary information for
 * doing the packet reinjection with HITs.
 *
 * @param *ctx  the contect of the packet
 * @param default_verdict default verdict for the packet
 * @return      the verdict for the packet
 */
int hip_fw_handle_outgoing_system_based_opp(const hip_fw_context_t *ctx,
                                            const int default_verdict)
{
    fw_cache_hl_t *entry_peer = NULL;
    int verdict;

    HIP_DEBUG("\n");

    if (hip_firewall_cache_db_match(&ctx->dst, &ctx->src, FW_CACHE_IP, 0)) {
        /* Peer is src and we are dst on an outgoing packet. */
        HIP_DEBUG("Packet is reinjection.\n");
        return 1;
    }

    entry_peer = hip_firewall_cache_db_match(&ctx->src, &ctx->dst,
                                             FW_CACHE_IP, 1);

    if (entry_peer) {
        if (entry_peer->state == HIP_STATE_ESTABLISHED &&
            !ipv6_addr_cmp(hip_fw_get_default_hit(), &entry_peer->hit_our)) {
            hip_reinject_packet(&entry_peer->hit_our, &entry_peer->hit_peer,
                                ctx->ipq_packet, 4, 0);
            verdict = 0;
        } else if (entry_peer->state == HIP_STATE_FAILED) {
            hip_fw_add_non_hip_peer(ctx, default_verdict);
            verdict = default_verdict;
        } else {
            verdict = 0;
        }
    } else {
        HIP_DEBUG("Initiate bex at firewall\n");
        hip_fw_trigger_opportunistic_bex(&ctx->dst, hip_fw_get_default_hit());
        verdict = 0;
    }

    return verdict;
}

/**
 * based on the parameters in a message, assign the HITs and IP addresses
 * to a given firewall entry
 *
 * @param msg the message containing HITs and IP addresses
 * @return zero on success or negative on error
 */
int hip_fw_sys_opp_set_peer_hit(const struct hip_common *msg)
{
    int err = 0, state;
    hip_hit_t *local_hit, *peer_hit;
    struct in6_addr *peer_addr;
    struct in6_addr *local_addr;

    local_hit  = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
    peer_hit   = hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
    local_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_LOCAL);
    peer_addr  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);

    if (peer_hit) {
        state = HIP_STATE_ESTABLISHED;
    } else {
        state = HIP_STATE_FAILED;
    }

    hip_firewall_cache_update_entry(local_addr, peer_addr,
                                    local_hit, peer_hit, state);

    return err;
}
