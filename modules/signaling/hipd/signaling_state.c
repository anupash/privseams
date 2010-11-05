/*
 * signaling_state.c
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/ife.h"
#include "lib/core/debug.h"
#include "signaling_state.h"

/*
 * Initialize an signaling_port_state instance.
 *
 * Allocates the required memory and sets the members to the start values.
 *
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
int signaling_init_state(struct modular_state *state)
{
    int err = 0;
    struct signaling_port_state *port_state = NULL;

    HIP_IFEL(!(port_state = (struct signaling_port_state *) malloc(sizeof(struct signaling_port_state))),
             -1,
             "Error on allocating memory for a port_state instance.\n");

    memset(port_state, 0, sizeof(struct signaling_port_state));

    err = lmod_add_state_item(state, port_state, "signaling_port_state");

out_err:
    return err;
}
