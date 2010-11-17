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

/* Identifies a specific connection
 * TODO: src and destination hits are most likely redundant here since they can be obtained
 *       from elsewhere in the hadb entry and anyway, all we need are ports.*/
struct signaling_state_connection {
    hip_hit_t src_hit;
    hip_hit_t dest_hit;
    uint16_t src_port;
    uint16_t dest_port;
};

/* Holds information about the application associated with a connection
 * Strings have to be null terminated. */
struct signaling_state_application {
    int pid;
    char *path;
    char *application_dn;
    char *issuer_dn;
    char *requirements;
    char *groups;
};

/*
 * Holds all the information about the binding between a application and the connection.
 * Contents are filled in in different places.
 */
struct signaling_state {
    struct signaling_state_connection connection;
    struct signaling_state_application application;
};

int signaling_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_STATE_H*/
