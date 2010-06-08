/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Processing for CLOSE control packets
 *
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include <stdlib.h>

#include "config.h"
#include "close.h"
#include "lib/core/common_defines.h"
#include "lib/core/hip_udp.h"
#include "lib/core/performance.h"

/**
 * send a HIP close packet to a peer
 *
 * @param entry the host association with the peer
 * @param opaque a nonce to be included in the CLOSE
 * @return zero on success or negative on error
 */
static int hip_xmit_close(hip_ha_t *entry, void *opaque)
{
    int err                      = 0, mask = 0;
    int delete_ha_info           = *(int *) ((uint8_t *)opaque + sizeof(hip_hit_t));
    hip_hit_t *peer              = (hip_hit_t *) opaque;
    struct hip_common *msg_close = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_CLOSE_SEND, PERF_CLOSE_COMPLETE\n");
    hip_perf_start_benchmark( perf_set, PERF_CLOSE_SEND );
    hip_perf_start_benchmark( perf_set, PERF_CLOSE_COMPLETE );
#endif

    if (peer) {
        HIP_DEBUG_HIT("Peer HIT to be closed", peer);
    }

    if (peer && !ipv6_addr_any(peer) &&
        memcmp(&entry->hit_peer, peer, sizeof(hip_hit_t))) {
        HIP_DEBUG("Peer HIT did not match, ignoring.\n");
        goto out_err;
    }

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
    hip_oppipdb_delentry(&(entry->peer_addr));
#endif

    if (!(entry->state == HIP_STATE_ESTABLISHED) && delete_ha_info) {
        HIP_DEBUG("Not sending CLOSE message, invalid hip state " \
                  "in current host association. State is %s.\n",
                  hip_state_str(entry->state));
        err = hip_del_peer_info_entry(entry);
        goto out_err;
    } else if (!(entry->state == HIP_STATE_ESTABLISHED) && !delete_ha_info) {
        HIP_DEBUG("Not sending CLOSE message, invalid hip state "     \
                  "in current host association. And NOT deleting the mapping. State is %s.\n",
                  hip_state_str(entry->state));
        goto out_err;
    }

    HIP_DEBUG("State is ESTABLISHED in current host association, sending " \
              "CLOSE message to peer.\n");

    hip_firewall_set_bex_data(HIP_MSG_FW_UPDATE_DB,
                              entry,
                              &entry->hit_our,
                              &entry->hit_peer);

    HIP_IFE(!(msg_close = hip_msg_alloc()), -ENOMEM);

    hip_build_network_hdr(msg_close,
                          HIP_CLOSE,
                          mask,
                          &entry->hit_our,
                          &entry->hit_peer);

    /********ECHO (SIGNED) **********/

    get_random_bytes(entry->echo_data, sizeof(entry->echo_data));

    HIP_IFEL(hip_build_param_echo(msg_close, entry->echo_data, sizeof(entry->echo_data), 1, 1),
             -1,
             "Failed to build echo param.\n");

    /************* HMAC ************/
    HIP_IFEL(hip_build_param_hmac_contents(msg_close, &entry->hip_hmac_out),
             -1,
             "Building of HMAC failed.\n");
    /********** Signature **********/
    HIP_IFEL(entry->sign(entry->our_priv_key, msg_close),
             -EINVAL,
             "Could not create signature.\n");

    HIP_IFEL(hip_send_pkt(NULL, &entry->peer_addr,
                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                          entry->peer_udp_port, msg_close, entry, 0),
             -ECOMM, "Sending CLOSE message failed.\n");

    entry->state = HIP_STATE_CLOSING;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_CLOSE_SEND\n");
    hip_perf_stop_benchmark( perf_set, PERF_CLOSE_SEND );
    hip_perf_write_benchmark( perf_set, PERF_CLOSE_SEND );
#endif

out_err:
    if (msg_close) {
        free(msg_close);
    }

    return err;
}

/**
 * a wrapper to send a close message to a peer
 *
 * @param msg a message containing a peer HIT to which to send close
 * @param delete_ha_info a nonce parameter for the CLOSE message
 * @return zero on success or negative on error
 */
int hip_send_close(struct hip_common *msg,
                   int delete_ha_info)
{
    int err                            = 0, retry, n;
    char *opaque                       = NULL;
    hip_hit_t *hit                     = NULL;
    struct sockaddr_in6 sock_addr;
    struct hip_common *msg_to_firewall = NULL;

    HIP_DEBUG("msg=%p\n", msg);

    HIP_IFEL(!(opaque = malloc(sizeof(hip_hit_t) + sizeof(int))),
             -1, "failed to allocate memory");

    if (msg) {
        hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
    }

    memset(opaque, 0, sizeof(hip_hit_t) + sizeof(int));

    if (hit) {
        memcpy(opaque, hit, sizeof(hip_hit_t));
    }

    memcpy(opaque + sizeof(hip_hit_t), &delete_ha_info, sizeof(int));


    HIP_IFEL(hip_for_each_ha(&hip_xmit_close, (void *) opaque),
             -1, "Failed to reset all HAs\n");

    /* send msg to firewall to reset
     * the db entries there too */
    msg_to_firewall = hip_msg_alloc();
    hip_msg_init(msg_to_firewall);
    HIP_IFE(hip_build_user_hdr(msg_to_firewall,
                               HIP_MSG_RESET_FIREWALL_DB, 0), -1);
    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;

    for (retry = 0; retry < 3; retry++) {
        n = hip_sendto_user(msg_to_firewall, (struct sockaddr *) &sock_addr);
        if (n <= 0) {
            HIP_ERROR("resetting firewall db failed (round %d)\n",
                      retry);
            HIP_DEBUG("Sleeping few seconds to wait for fw\n");
            sleep(2);
        } else {
            HIP_DEBUG("resetof  firewall db ok (sent %d bytes)\n",
                      n);
            break;
        }
    }

out_err:
    if (msg_to_firewall) {
        free(msg_to_firewall);
    }
    if (opaque) {
        free(opaque);
    }
    return err;
}

/**
 * hip_close_check_packet
 *
 * Check whether a received control packet is valid or not.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_close_check_packet(UNUSED const uint8_t packet_type,
                           UNUSED const uint32_t ha_state,
                           struct hip_packet_context *ctx)
{
    int err = 0;
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE\n");
    hip_perf_start_benchmark( perf_set, PERF_HANDLE_CLOSE );
#endif

    HIP_IFEL(ipv6_addr_any(&(ctx->input_msg)->hitr), -1,
             "Received NULL receiver HIT in CLOSE. Dropping\n");

    HIP_IFEL(!hip_controls_sane(ntohs(ctx->input_msg->control), 0), -1,
             "Received illegal controls in CLOSE: 0x%x. Dropping\n",
             ntohs(ctx->input_msg->control));

    HIP_IFEL(!ctx->hadb_entry, -1,
             "No entry in host association database when receiving R2." \
             "Dropping.\n");

    /* verify HMAC */
    if (ctx->hadb_entry->is_loopback) {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg, &(ctx->hadb_entry)->hip_hmac_out),
                 -ENOENT, "HMAC validation on close failed.\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg, &(ctx->hadb_entry)->hip_hmac_in),
                 -ENOENT, "HMAC validation on close failed.\n");
    }

    /* verify signature */
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key, ctx->input_msg), -EINVAL,
             "Verification of close signature failed.\n");

out_err:
    if (err) {
        ctx->error = err;
    }
    return err;
}

/**
 * hip_close_create_response
 *
 * Create an response (CLOSE_ACK) for a received CLOSE packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_close_create_response(UNUSED const uint8_t packet_type,
                              UNUSED const uint32_t ha_state,
                              struct hip_packet_context *ctx)
{
    int err = 0, echo_len;
    uint16_t mask = HIP_PACKET_CTRL_ANON;
    struct hip_echo_request *request;

    HIP_IFE(!(ctx->output_msg = hip_msg_alloc()), -ENOMEM);

    HIP_IFEL(!(request =
                 hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_REQUEST_SIGN)),
             -1, "No echo request under signature.\n");

    echo_len = hip_get_param_contents_len(request);

    hip_build_network_hdr(ctx->output_msg,
                        HIP_CLOSE_ACK,
                        mask,
                        &(ctx->hadb_entry)->hit_our,
                        &(ctx->hadb_entry)->hit_peer);

    HIP_IFEL(hip_build_param_echo(ctx->output_msg, request + 1,
                                echo_len, 1, 0), -1,
           "Failed to build echo param.\n");

    /************* HMAC ************/
    HIP_IFEL(hip_build_param_hmac_contents(ctx->output_msg,
                                         &(ctx->hadb_entry)->hip_hmac_out),
           -1, "Building of HMAC failed.\n");

    /********** Signature **********/
    HIP_IFEL(ctx->hadb_entry->sign(ctx->hadb_entry->our_priv_key,
                                 ctx->output_msg),
           -EINVAL,
           "Could not create signature.\n");

out_err:
    if (err) {
        ctx->error = err;
    }
    return err;
}

/**
 * hip_close_create_response
 *
 * Send a before generated CLOSE_ACK packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_close_send_response(UNUSED const uint8_t packet_type,
                            UNUSED const uint32_t ha_state,
                            struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_IFEL(hip_send_pkt(NULL,
                          &(ctx->hadb_entry)->peer_addr,
                          hip_get_local_nat_udp_port(),
                          ctx->hadb_entry->peer_udp_port,
                          ctx->output_msg,
                          ctx->hadb_entry,
                          0),
             -ECOMM, "Sending CLOSE ACK message failed.\n");

    ctx->hadb_entry->state = HIP_STATE_CLOSED;

    HIP_DEBUG("CLOSED.\n");

/* If this host has a relay hashtable, i.e. the host is a HIP UDP relay or RVS,
 * then we need to delete the relay record matching the sender's HIT. */
#ifdef CONFIG_HIP_RVS
    if (hip_relay_get_status()) {
        hip_relrec_t dummy;
        memcpy(&(dummy.hit_r), &(ctx->input_msg->hits),
               sizeof(ctx->input_msg->hits));
        hip_relht_rec_free_doall(&dummy);
        /* Check that the element really got deleted. */
        if (hip_relht_get(&dummy) == NULL) {
            HIP_DEBUG_HIT("Deleted relay record for HIT",
                          &(ctx->input_msg->hits));
        }
    }
#endif

    HIP_IFEL(hip_del_peer_info_entry(ctx->hadb_entry),
             -1,
             "Deleting peer info failed.\n");
out_err:
    if (ctx->output_msg) {
        free(ctx->output_msg);
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE\n");
    hip_perf_stop_benchmark( perf_set, PERF_HANDLE_CLOSE );
    hip_perf_write_benchmark( perf_set, PERF_HANDLE_CLOSE );
#endif

    return err;
}

/**
 * hip_close_ack_check_packet
 *
 * Check whether a received CLOSE_ACK packet is valid or not.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_close_ack_check_packet(UNUSED const uint8_t packet_type,
                               UNUSED const uint32_t ha_state,
                               struct hip_packet_context *ctx)
{
    int err = 0;
    uint16_t mask = HIP_PACKET_CTRL_ANON;
    struct hip_echo_request *echo_resp = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE_ACK\n");
    hip_perf_start_benchmark( perf_set, PERF_HANDLE_CLOSE_ACK );
#endif

    HIP_IFEL(ipv6_addr_any(&ctx->input_msg->hitr), -1,
            "Received NULL receiver HIT in CLOSE ACK. Dropping\n");

    if (!hip_controls_sane(ntohs(ctx->input_msg->control), mask)) {
        HIP_ERROR("Received illegal controls in CLOSE ACK: 0x%x. Dropping\n",
                ntohs(ctx->input_msg->control));
        goto out_err;
    }

    /* verify ECHO */
    HIP_IFEL(!(echo_resp =
                   hip_get_param(ctx->input_msg, HIP_PARAM_ECHO_RESPONSE_SIGN)),
             -1, "Echo response not found\n");
    HIP_IFEL(memcmp(echo_resp + 1, ctx->hadb_entry->echo_data,
                    sizeof(ctx->hadb_entry->echo_data)),
             -1,
             "Echo response did not match request\n");

    /* verify HMAC */
    if (ctx->hadb_entry->is_loopback) {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                        &ctx->hadb_entry->hip_hmac_out),
                 -ENOENT,
                 "HMAC validation on close ack failed\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                        &ctx->hadb_entry->hip_hmac_in),
                 -ENOENT,
                 "HMAC validation on close ack failed\n");
    }
    /* verify signature */
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key,
                                     ctx->input_msg),
             -EINVAL,
             "Verification of close ack signature failed\n");

out_err:
    if (err) {
        ctx->error = err;
    }
    return err;
}

/**
 * hip_close_ack_handle_packet
 *
 * Handle a received and checked CLOSE_ACK packet. If a hadb entry exists, the
 * host association state will be set to HIP_STATE_CLOSED.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx Pointer to the packet context, containing all
 *                    information for the packet handling
 *                    (received message, source and destination address, the
 *                    ports and the corresponding entry from the host
 *                    association database).
 *
 * @return zero on success, non-negative on error.
 */
int hip_close_ack_handle_packet(UNUSED const uint8_t packet_type,
                                UNUSED const uint32_t ha_state,
                                struct hip_packet_context *ctx)
{
    int err = 0;

    HIP_IFEL(!ctx->hadb_entry, -1,
             "No entry in host association database when receiving R2." \
             "Dropping.\n");

    ctx->hadb_entry->state = HIP_STATE_CLOSED;

    HIP_DEBUG("CLOSED\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* Check and remove the IP of the peer from the opp non-HIP database */
    hip_oppipdb_delentry(&ctx->hadb_entry->peer_addr);
#endif

    HIP_IFEL(hip_del_peer_info(&ctx->hadb_entry->hit_our,
                               &ctx->hadb_entry->hit_peer),
             -1, "Deleting peer info failed\n");
out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE_ACK, PERF_CLOSE_COMPLETE\n");
    hip_perf_stop_benchmark( perf_set, PERF_HANDLE_CLOSE_ACK );
    hip_perf_write_benchmark( perf_set, PERF_HANDLE_CLOSE_ACK );
    hip_perf_stop_benchmark( perf_set, PERF_CLOSE_COMPLETE );
    hip_perf_write_benchmark( perf_set, PERF_CLOSE_COMPLETE );
#endif

    return err;
}

/**
 * tear down a host association after close procedure
 *
 * @param ha the corresponding host association
 * @return zero on success or negative on error
 */
int hip_purge_closing_ha(hip_ha_t *ha, UNUSED void *opaque)
{
    int err = 0;

    if ((ha->state == HIP_STATE_CLOSING || ha->state == HIP_STATE_CLOSED)) {
        if (ha->purge_timeout <= 0) {
            HIP_DEBUG("Purging HA (state=%d)\n", ha->state);
            HIP_IFEL(hip_del_peer_info(&ha->hit_our, &ha->hit_peer), -1,
                     "Deleting peer info failed.\n");
        } else {
            ha->purge_timeout--;
        }
    }

out_err:
    return err;
}
