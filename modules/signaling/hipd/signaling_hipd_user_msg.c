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

#include "modules/signaling/lib/signaling_prot_common.h"
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
int signaling_handle_bex_update_trigger(struct hip_common *msg, UNUSED struct sockaddr_in6 *src) {
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

/* Saves the ports from the trigger_bex_msg to global state */
int signaling_handle_bex_trigger(struct hip_common *msg,
                                 UNUSED struct sockaddr_in6 *src) {
    const hip_hit_t *our_hit        = NULL, *peer_hit  = NULL;
    uint16_t src_port = 0, dest_port = 0;
    const struct hip_tlv_common *param;

    hip_ha_t *entry = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    int err = 0;

    /* Need to get source and destination hit first to lookup state from hadb */
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

    /* Now lookup state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "Failed to retrieve hadb entry, cannot save port state.\n");

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling ports\n");

    /* If we got some state, save the ports and hits to it */
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    if(param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APPINFO) {
        src_port = ntohs(((const struct signaling_param_app_context *) param)->src_port);
        dest_port = ntohs(((const struct signaling_param_app_context *) param)->dest_port);
        sig_state->ctx.src_port = src_port;
        sig_state->ctx.dest_port = dest_port;
        HIP_DEBUG("Saved connection information for I2.\n");
        HIP_DEBUG("\tsrc port: %d dest port: %d \n", sig_state->ctx.src_port, sig_state->ctx.dest_port);
    }

out_err:
    return err;
}
