/*
 * signaling_hipd_state.c
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/ife.h"
#include "lib/core/debug.h"

#include "signaling_hipd_state.h"

/*
 * Initialize an signaling_hipd_state instance.
 *
 * Allocates the required memory and sets the members to the start values.
 *
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
int signaling_hipd_init_state(struct modular_state *state)
{
    int err = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) malloc(sizeof(struct signaling_hipd_state))),
             -1,
             "Error on allocating memory for a signaling_hipd_state instance.\n");

    // TODO: proper initialization to 0/NULL values
    memset(sig_state, 0, sizeof(struct signaling_hipd_state));
    sig_state->ctx.user_ctx.euid            = -1;
    sig_state->ctx.app_ctx.pid              = -1;

    sig_state->user_cert_ctx.user_certificate_required    = 0;
    sig_state->user_cert_ctx.cert_chain                   = NULL;
    sig_state->user_cert_ctx.group                        = -1;

    sig_state->update_in_progress = 0;

    signaling_init_user_context(&sig_state->user_cert_ctx.user_ctx);

    err = lmod_add_state_item(state, sig_state, "signaling_hipd_state");

out_err:
    return err;
}
