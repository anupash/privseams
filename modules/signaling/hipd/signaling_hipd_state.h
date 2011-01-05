/*
 * signaling_hipd_state.h
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#ifndef HIP_HIPD_SIGNALING_HIPD_STATE_H
#define HIP_HIPD_SIGNALING_HIPD_STATE_H

#include "lib/core/modularization.h"
#include "lib/core/protodefs.h"

#include "modules/signaling/lib/signaling_prot_common.h"

/**
 * Definition of the state the signaling module keeps for the hip daemon.
 */
struct signaling_hipd_state {
    /* Holds the connection context for the connection that is currently being established */
    struct signaling_connection_context ctx;
    /* Flags to save whether we need to send our user certificate after BEX or UPDATE is completed */
    int user_certificate_required;
};

int signaling_hipd_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_HIPD_STATE_H*/
