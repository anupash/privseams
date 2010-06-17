/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
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
#include "firewall.h"
#include "firewalldb.h"
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
 * Gets the state of the bex for a pair of ip addresses.
 * @param src_ip    input for finding the correct entries
 * @param dst_ip    input for finding the correct entries
 * @param src_hit   output data of the correct entry
 * @param dst_hit   output data of the correct entry
 * @param src_lsi   output data of the correct entry
 * @param dst_lsi   output data of the correct entry
 *
 * @return  the state of the bex if the entry is found
 *          otherwise returns -1
 */
static int hip_get_bex_state_from_IPs(const struct in6_addr *src_ip,
                               const struct in6_addr *dst_ip,
                               struct in6_addr *src_hit,
                               struct in6_addr *dst_hit,
                               hip_lsi_t *src_lsi,
                               hip_lsi_t *dst_lsi)
{
    int err = 0, res = -1;
    struct hip_tlv_common *current_param = NULL;
    struct hip_common *msg               = NULL;
    struct hip_hadb_user_info_state *ha  = NULL;

    HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_HA_INFO, 0),
             -1, "Building of daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1,
             "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
        ha = hip_get_param_contents_direct(current_param);

        if ((ipv6_addr_cmp(dst_ip, &ha->ip_our) == 0) &&
            (ipv6_addr_cmp(src_ip, &ha->ip_peer) == 0)) {
            memcpy(src_hit, &ha->hit_peer, sizeof(struct in6_addr));
            memcpy(dst_hit, &ha->hit_our, sizeof(struct in6_addr));
            memcpy(src_lsi, &ha->lsi_peer, sizeof(hip_lsi_t));
            memcpy(dst_lsi, &ha->lsi_our, sizeof(hip_lsi_t));
            res = ha->state;
            break;
        } else if ((ipv6_addr_cmp(src_ip, &ha->ip_our) == 0) &&
                   (ipv6_addr_cmp(dst_ip, &ha->ip_peer) == 0)) {
            memcpy(src_hit, &ha->hit_our, sizeof(struct in6_addr));
            memcpy(dst_hit, &ha->hit_peer, sizeof(struct in6_addr));
            memcpy(src_lsi, &ha->lsi_our, sizeof(hip_lsi_t));
            memcpy(dst_lsi, &ha->lsi_peer, sizeof(hip_lsi_t));
            res = ha->state;
            break;
        }
    }

out_err:
    if (msg) {
        free(msg);
    }
    return res;
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
}

/**
 * Checks if the outgoing packet has already ESTABLISHED
 * the Base Exchange with the peer host. In case the BEX
 * is not done, it triggers it. Otherwise, it looks up
 * in the local database the necessary information for
 * doing the packet reinjection with HITs.
 *
 * @param *ctx  the contect of the packet
 * @return      the verdict for the packet
 */
int hip_fw_handle_outgoing_system_based_opp(const hip_fw_context_t *ctx,
                                            const int default_verdict)
{
    int state_ha, new_fw_entry_state;
    hip_lsi_t src_lsi, dst_lsi;
    struct in6_addr src_hit, dst_hit;
    firewall_hl_t *entry_peer = NULL;
    struct sockaddr_in6 all_zero_hit;
    int verdict = default_verdict;

    HIP_DEBUG("\n");

    //get firewall db entry
    entry_peer = hip_firewall_ip_db_match(&ctx->dst);
    if (entry_peer) {
        //if the firewall entry is still undefined
        //check whether the base exchange has been established
        if (entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT) {
            //get current connection state from hipd
            state_ha = hip_get_bex_state_from_IPs(&ctx->src,
                                                  &ctx->dst,
                                                  &src_hit,
                                                  &dst_hit,
                                                  &src_lsi,
                                                  &dst_lsi);

            //find the correct state for the fw entry state
            HIP_DEBUG("HA state %d\n", state_ha);
            if (state_ha == HIP_STATE_ESTABLISHED) {
                new_fw_entry_state = FIREWALL_STATE_BEX_ESTABLISHED;
            } else if ((state_ha == HIP_STATE_FAILED)  ||
                       (state_ha == HIP_STATE_CLOSING) ||
                       (state_ha == HIP_STATE_CLOSED)) {
                new_fw_entry_state = FIREWALL_STATE_BEX_NOT_SUPPORTED;
            } else {
                new_fw_entry_state = FIREWALL_STATE_BEX_DEFAULT;
            }

            HIP_DEBUG("New state %d\n", new_fw_entry_state);
            //update fw entry state accordingly
            hip_firewall_update_entry(&src_hit, &dst_hit, &dst_lsi,
                                      &ctx->dst, new_fw_entry_state);

            //reobtain the entry in case it has been updated
            entry_peer = hip_firewall_ip_db_match(&ctx->dst);
        }

        //decide what to do with the packet
        if (entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT) {
            verdict = 0;
        } else if (entry_peer->bex_state == FIREWALL_STATE_BEX_NOT_SUPPORTED) {
            hip_fw_add_non_hip_peer(ctx, verdict);
            verdict = default_verdict;
        } else if (entry_peer->bex_state == FIREWALL_STATE_BEX_ESTABLISHED) {
            if (&entry_peer->hit_our                       &&
                (ipv6_addr_cmp(hip_fw_get_default_hit(),
                               &entry_peer->hit_our) == 0)) {
                hip_reinject_packet(&entry_peer->hit_our,
                                    &entry_peer->hit_peer,
                                    ctx->ipq_packet, 4, 0);
                verdict = 0;
            } else {
                verdict = default_verdict;
            }
        }
    } else {
        /* add default entry in the firewall db */
        hip_firewall_add_default_entry(&ctx->dst);

        /* get current connection state from hipd */
        state_ha = hip_get_bex_state_from_IPs(&ctx->src, &ctx->dst,
                                              &src_hit, &dst_hit,
                                              &src_lsi, &dst_lsi);
        if (state_ha == -1) {
            hip_hit_t *def_hit = hip_fw_get_default_hit();
            HIP_DEBUG("Initiate bex at firewall\n");
            memset(&all_zero_hit, 0, sizeof(struct sockaddr_in6));
            hip_fw_trigger_opportunistic_bex(&ctx->dst, def_hit);
            verdict = 0;
        } else if (state_ha == HIP_STATE_ESTABLISHED) {
            if (!ipv6_addr_cmp(&src_hit, hip_fw_get_default_hit())) {
                HIP_DEBUG("is local hit\n");
                hip_firewall_update_entry(&src_hit, &dst_hit,
                                          &dst_lsi, &ctx->dst,
                                          FIREWALL_STATE_BEX_ESTABLISHED);
                hip_reinject_packet(&src_hit, &dst_hit, ctx->ipq_packet, 4, 0);
                verdict = 0;
            } else {
                verdict = default_verdict;
            }
        } else if ((state_ha == HIP_STATE_FAILED)  ||
                   (state_ha == HIP_STATE_CLOSING) ||
                   (state_ha == HIP_STATE_CLOSED)) {
            verdict = default_verdict;
        } else {
            verdict = 0;
        }
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
    hip_lsi_t *local_addr;

    local_hit  = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
    peer_hit   = hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
    local_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_LOCAL);
    peer_addr  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);

    if (peer_hit) {
        state = FIREWALL_STATE_BEX_ESTABLISHED;
    } else {
        state = FIREWALL_STATE_BEX_NOT_SUPPORTED;
    }

    hip_firewall_update_entry(local_hit, peer_hit,
                              local_addr, peer_addr, state);

    return err;
}
