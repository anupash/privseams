/*
 * signaling_hipd_user_msg.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/debug.h"
#include "lib/core/modularization.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "hipd/hadb.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "signaling_state.h"
#include "signaling_hipd_user_msg.h"

/* Saves the ports from the trigger_bex_msg to global state */
int signaling_handle_bex_ports(struct hip_common *msg,
                               UNUSED struct sockaddr_in6 *src) {
    const hip_hit_t *our_hit        = NULL, *peer_hit  = NULL;
    uint16_t src_port = 0, dest_port = 0;
    const struct hip_tlv_common *param;

    hip_ha_t *entry = NULL;
    struct signaling_port_state *port_state = NULL;
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

    HIP_IFEL(!(port_state = (struct signaling_port_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_port_state")),
                 -1, "failed to retrieve state for signaling ports\n");

    /* If we got some state, save the ports to it */
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_PORTINFO);
    if(param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_PORTINFO) {
        src_port = ntohs(((const struct signaling_param_portinfo *) param)->srcport);
        dest_port = ntohs(((const struct signaling_param_portinfo *) param)->destport);
        port_state->src_port = src_port;
        port_state->dest_port = dest_port;
        HIP_DEBUG("Saved ports for I2. src: %d dest: %d \n", port_state->src_port, port_state->dest_port);
    }

out_err:
    return err;
}
