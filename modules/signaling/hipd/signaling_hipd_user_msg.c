/*
 * signaling_hipd_user_msg.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include <string.h>

#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/debug.h"
#include "lib/core/modularization.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "lib/core/message.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/netdev.h"
#include "hipd/user.h"

#include "modules/signaling/lib/signaling_common_builder.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

/** Generic send function used to send to the firewall.
 *
 * @param msg       the message to be sent
 * @param block     set to 0 if no answer is expected,
 *                  set to 1 if function should block and wait for an answer
 * @return          0 on success, negative on error
 */
static int signaling_hipd_send_to_fw(struct hip_common *msg, const int block)
{
    struct sockaddr_in6 hip_fw_addr;
    struct sockaddr_in6 resp_addr;
    struct in6_addr loopback = in6addr_loopback;
    int err                  = 0;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_fw_addr.sin6_addr, &loopback);

    err = hip_sendto_user(msg, (struct sockaddr *) &hip_fw_addr);
    if (err < 0) {
        HIP_ERROR("Sending message to firewall failed\n");

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("Sending message to firewall successful\n");

        // this is needed if we want to use HIP_IFEL
        err = 0;
    }

    if (block) {
        HIP_DEBUG("Waiting for response on msg type %d\n", hip_get_msg_type(msg));
        HIP_IFEL(hip_read_user_control_msg(hip_user_sock, msg, &resp_addr),
                 -1, "Could not receive response on connection request\n");

    }

out_err:
    return err;
}

/**
 * HIPD should send a HIP_MSG_SIGNALING_REQUEST_CONNECTION message to the firewall,
 * only when it is the responder to a new connection.
 * By sending a HIP_MSG_SIGNALING_REQUEST_CONNECTION with the received application
 * context to the firewall, HIPD notifies the firewall of the new connection and
 * request the local application context for this connection.
 * The local application context must be included in the R2 or UPDATE response resp.
 *
 * @note This function blocks until the firewall has sent its response with the local application context in it.
 *
 * @param src_hit       src hit of the new incoming connection
 * @param dst_hit       dst hit of the new incoming connection
 * @param remote_ctx    the received connection context for the new incoming connection
 *
 * @return          0 on sucess, negative on error
  */
int signaling_send_connection_context_request(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                                              const struct signaling_connection_context *remote_ctx) {
    int err = 0;

    /* Allocate, build and send a message of type
     * HIP_MSG_SIGNALING_REQUEST_CONNECTION to the hipfw,
     * containing the receive application context */
    struct hip_common *msg = NULL;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_REQUEST_CONNECTION, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, remote_ctx, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT, sizeof(struct signaling_connection_context)),
             -1, "build connection context failed \n");

    HIP_DEBUG("Sending connection context request for following context to HIPF:\n");
    signaling_connection_context_print(remote_ctx, "");
    HIP_IFEL(signaling_hipd_send_to_fw(msg, 1), -1, "failed to send/recv connection request to fw\n");

    /* We expect the corresponding local application context in the response. */
    HIP_IFEL(signaling_handle_connection_context(msg, NULL),
             -1, "Failed to process connection confirmation from hipfw/oslayer \n");

out_err:
    free(msg);
    return err;
}

/**
 * Send a confirmation about the establishment of a new connection to the hipfw/oslayer.
 * This is the answer to a previous connection request from the hipfw/oslayer.
 *
 * @param hits      the source hit of the new connection (our local hit)
 * @param hitr      the remote hit of the new connection
 * @param appinfo   the application context for which the connection has been established
 *
 * @return          0 on success, negative on error
 */
int signaling_send_connection_confirmation(hip_hit_t *hits, hip_hit_t *hitr, const struct signaling_connection_context *ctx)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    /* Build and send a HIP_MSG_SIGNALING_CONFIRM_CONNECTION message.
     * The message must identify the connection that has been established,
     * i.e. include HITs and application context. */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)),
            -1, "alloc memory for adding scdb entry\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CONFIRM_CONNECTION, 0), -1,
              "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hits,
                                      HIP_PARAM_HIT,
                                      sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hitr,
                                      HIP_PARAM_HIT,
                                      sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, ctx, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT, sizeof(struct signaling_connection_context)),
             -1, "build connection context failed \n");

    HIP_IFEL(signaling_hipd_send_to_fw(msg, 0), -1, "failed to send add scdb-msg to fw\n");

out_err:
    free(msg);
    return err;
}

/**
 * This functions receives and handles a message of type HIP_MSG_SIGNALING_CONNECTION_CONFIRMATION
 * from the firewall. This message is sent as the answer to a previous
 * HIP_MSG_SIGNALING_CONNECTION_REQUEST message from hipd to hipfw.
 * This message contains the local application context for the new connection.
 * We have to save the application context to our local state, so that it can
 * be included in an R2 or UPDATE later.
 *
 * @param msg   the answer from the firewall
 *
 * @return 0 on success, negative on error
 */
int signaling_handle_connection_context(struct hip_common *msg,
                                        UNUSED struct sockaddr_in6 *src) {
    int err                                 = 0;
    const hip_hit_t *our_hit                = NULL;
    const hip_hit_t *peer_hit               = NULL;
    struct signaling_hipd_state *sig_state  = NULL;
    const struct hip_tlv_common *param      = NULL;
    hip_ha_t *entry                         = NULL;

    signaling_get_hits_from_msg(msg, &our_hit, &peer_hit);
    HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
             -1, "hadb entry has not been set up\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT)),
             -1, "Missing application_context parameter\n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    HIP_IFEL(signaling_copy_connection_context(&sig_state->ctx, (const struct signaling_connection_context *) (param + 1)),
             -1, "Could not copy connection context\n");

    HIP_DEBUG("Saved connection context from hipfw for R2:\n");
    signaling_connection_context_print(&sig_state->ctx, "");

out_err:
    return err;
}

/**
 * This function receives and handles a messages of type HIP_MSG_SIGNALING_REQUEST_CONNECTION,
 * from the firewall. This message means, that the firewall wants the HIPD
 * to establish a new connection for the context contained in the message.
 *
 * We have to check whether to trigger a BEX or an UPDATE and do it.
 *   a) BEX:    We save the connection context to include it in the I2 later.
 *   b) UPDATE: We save the connection context and send the UPDATE right away.
 *
 * @param msg the message from the firewall
 *
 * @return 0 on success
 */
int signaling_handle_connection_request(struct hip_common *msg,
                                        struct sockaddr_in6 *src) {
    const hip_hit_t *our_hit    = NULL;
    const hip_hit_t *peer_hit   = NULL;
    const struct hip_tlv_common *param;

    hip_ha_t *entry = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    int err = 0;

    /* Determine if we already have an association */
    signaling_get_hits_from_msg(msg, &our_hit, &peer_hit);
    entry = hip_hadb_find_byhits(our_hit, peer_hit);

    /* Now check whether we need to trigger a BEX or an UPDATE */
    if(entry) {   // UPDATE
        /* save application context to our local state */
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");
        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT)),
                 -1, "Missing application_context parameter\n");
        signaling_param_application_context_print((const struct signaling_param_app_context *) param);
        // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
        HIP_IFEL(signaling_copy_connection_context(&sig_state->ctx, (const struct signaling_connection_context *) (param + 1)),
                 -1, "Could not copy connection context\n");

        /* now trigger the UPDATE */
        HIP_IFEL(signaling_trigger_bex_update(msg),
                 -1, "Failed triggering first bex update.\n");

        HIP_DEBUG("Triggered UPDATE for following connection context:\n");
        signaling_connection_context_print(&sig_state->ctx, "");

    } else {       // BEX
        HIP_DEBUG("Triggering BEX \n");
        // trigger bex since we intercepted the packet before it could be handled by the hipfw
        HIP_IFEL(hip_netdev_trigger_bex_msg(msg, src),
                 -1, "Netdev could not trigger the BEX\n");
        // have to do this after triggering BEX since there is no state before
        HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "hadb entry has not been set up\n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");
        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT)),
                 -1, "Missing application_context parameter\n");
        // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
        HIP_IFEL(signaling_copy_connection_context(&sig_state->ctx, (const struct signaling_connection_context *) (param + 1)),
                 -1, "Could not copy connection context\n");

        HIP_DEBUG("Started new BEX for following connection context:\n");
        signaling_connection_context_print(&sig_state->ctx, "");
    }

out_err:
    return err;
}
