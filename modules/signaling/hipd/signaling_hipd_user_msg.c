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
#include "hipd/hadb.h"
#include "hipd/netdev.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"


/*
 * Handles a trigger for a bex update sent by the firewall.
 *
 * Either we have to initiate a bex update exchange with the other party,
 * or we tell the firewall that the new connection is allowed.
 *
 * Comment: Connection tracking in hipd is not implemented yet,
 *          so we always start a new exchange of updates.
 */
UNUSED int signaling_handle_bex_update_trigger(struct hip_common *msg, UNUSED struct sockaddr_in6 *src) {
    int err = 0;

    HIP_DEBUG("Received request for new connection (trigger bex update). \n");

    /*
     * Do connection tracking here ...
     */


    /* Need to do a complete update bex. */
    HIP_IFEL(signaling_trigger_bex_update(msg),
            -1, "Failed triggering first bex update.\n");

out_err:
    return err;
}

/**
 * This function is part of the HIPD interface towards the firewall.
 * It receives and handles the trigger_new_connection message,
 * send by the firewall upon new connection attempts.
 * We have to check whether to trigger a BEX or an UPDATe and do it.
 *   a) BEX:    We save the connection context to include it in the I2 later.
 *   b) UPDATE: We copy the connection context and send the UPDATE right away.
 *
 * @param msg the message send by the firewall
 *
 * @return 0 on success
 */
int signaling_handle_new_connection_trigger(struct hip_common *msg,
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
