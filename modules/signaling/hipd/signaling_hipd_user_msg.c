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

/** generic send function used to send the below created messages
 *
 * @param msg   the message to be sent
 * @return      0, if correct, else != 0
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
        hip_read_user_control_msg(hip_user_sock, msg, &resp_addr);
        HIP_DUMP_MSG(msg);
    }

out_err:
    return err;
}

/**
 * Send a confirmation about the establishment of a new connection to the hipfw/oslayer.
 * This is the answer to a previous connection request from the hipfw/oslayer.
 *
 * @param hits      the source hit of the new connection (our local hit)
 * @param hitr      the remote hit of the new connection
 * @param appinfo   the local application context for which the application has been established
 *
 * @return          0 on success, negative on error
 */
int signaling_send_connection_confirmation(hip_hit_t *hits, hip_hit_t *hitr, const struct signaling_param_app_context *appinfo)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    /* Build the user message */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)),
            -1, "alloc memory for adding scdb entry\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CONFIRM_CONNECTION, 0), -1,
              "build hdr failed\n");

     /* Include Hits */
    HIP_IFEL(hip_build_param_contents(msg, hits,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");

    HIP_IFEL(hip_build_param_contents(msg, hitr,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");

    /* Include appinfo parameter (copy it...) */
    hip_build_param(msg, appinfo);

    /* Send */
    HIP_IFEL(signaling_hipd_send_to_fw(msg, 0), -1, "failed to send add scdb-msg to fw\n");

out_err:
    free(msg);
    return err;
}

/**
 * This function is part of the HIPD interface towards the firewall.
 * It receives and handles a message of type HIP_MSG_SIGNALING_REQUEST_CONNECTION,
 * send by the firewall. This message means, that the firewall wants the HIPD
 * to establish a new connection for the context contained in the message.
 *
 * We have to check whether to trigger a BEX or an UPDATe and do it.
 *   a) BEX:    We save the connection context to include it in the I2 later.
 *   b) UPDATE: We copy the connection context and send the UPDATE right away.
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
    param = hip_get_param(msg, HIP_PARAM_HIT);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        peer_hit = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(peer_hit)) {
            peer_hit = NULL;
        } else {
            HIP_DEBUG_HIT("got dest hit:", peer_hit);
        }
    }
    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        our_hit = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(our_hit)) {
            our_hit = NULL;
        } else {
            HIP_DEBUG_HIT("got src hit:", our_hit);
        }
    }
    entry = hip_hadb_find_byhits(our_hit, peer_hit);

    /* Now check whether we need to trigger a BEX or an UPDATE */
    if(entry) {   // UPDATE
        HIP_DEBUG("Triggering UPDATE \n");
        HIP_IFEL(signaling_trigger_bex_update(msg),
                 -1, "Failed triggering first bex update.\n");
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
        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO)),
                 -1, "Missing application_context parameter\n");
        signaling_param_application_context_print((const struct signaling_param_app_context *) param);
        signaling_init_connection_context(&sig_state->ctx);
        sig_state->ctx.src_port     = ntohs(((const struct signaling_param_app_context *) param)->src_port);
        sig_state->ctx.dest_port    = ntohs(((const struct signaling_param_app_context *) param)->dest_port);
        HIP_IFEL(signaling_build_application_context((const struct signaling_param_app_context *) param, &sig_state->ctx.app_ctx),
                 -1, "Failed to transform app ctx param to internal app ctx\n");
        signaling_connection_context_print(&sig_state->ctx);
    }

out_err:
    return err;
}
