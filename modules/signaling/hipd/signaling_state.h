/*
 * signaling_state.h
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#ifndef HIP_HIPD_SIGNALING_STATE_H
#define HIP_HIPD_SIGNALING_STATE_H

#include "lib/core/modularization.h"


struct signaling_port_state {
    /** ESP extension protection transform */
    uint16_t                src_port;
    uint16_t                dest_port;
};

int signaling_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_STATE_H*/
