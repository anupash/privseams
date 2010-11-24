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

/* Holds information about the application associated with a connection
 * Strings have to be null terminated. */
struct signaling_state_application {
    uint16_t src_port;
    uint16_t dest_port;
    int pid;
    char *path;
    char *application_dn;
    char *issuer_dn;
    char *requirements;
    char *groups;
};

/*
 * Container
 */
struct signaling_state {
    struct signaling_state_application application;
};

int signaling_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_STATE_H*/
