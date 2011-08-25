/*
 * signaling_state.h
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#ifndef HIP_HIPD_SIGNALING_STATE_H
#define HIP_HIPD_SIGNALING_STATE_H

#include "lib/core/modularization.h"
#include "lib/core/protodefs.h"

/* Identifies a specific connection */
struct signaling_state_connection {
    hip_hit_t src_hit;
    hip_hit_t dest_hit;
    uint16_t src_port;
    uint16_t dest_port;
};

struct signaling_state {
    struct signaling_state_connection connection;
};

int signaling_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_STATE_H*/
