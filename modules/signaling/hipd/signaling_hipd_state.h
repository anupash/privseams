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

/*
 * The application context is for now the only state kept in the hipd.
 * However, we use struct signaling_hipd_state as a container to be able to add further state later.
 */
struct signaling_hipd_state {
    struct signaling_application_context app_ctx;
};

int signaling_hipd_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_HIPD_STATE_H*/
