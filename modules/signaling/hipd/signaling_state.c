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
 * Initialize an signaling_state instance.
 *
 * Allocates the required memory and sets the members to the start values.
 *
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
int signaling_init_state(struct modular_state *state)
{
    int err = 0;
    struct signaling_state *sig_state = NULL;

    HIP_IFEL(!(sig_state = (struct signaling_state *) malloc(sizeof(struct signaling_state))),
             -1,
             "Error on allocating memory for a port_state instance.\n");

    memset(sig_state, 0, sizeof(struct signaling_state));

    err = lmod_add_state_item(state, sig_state, "signaling_state");

out_err:
    return err;
}
