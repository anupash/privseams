/*
 * signaling_hipd_state.h
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#ifndef HIP_HIPD_SIGNALING_HIPD_STATE_H
#define HIP_HIPD_SIGNALING_HIPD_STATE_H

#include <openssl/x509.h>

#include "lib/core/modularization.h"
#include "lib/core/protodefs.h"

#include "modules/signaling/lib/signaling_prot_common.h"

struct user_certificate_context {
    /* Flag to save whether we need to send our user certificate after BEX or UPDATE is completed */
    int user_certificate_required;
    int group;
    STACK_OF(X509) *cert_chain;
    /* Holds the user context for which the certificates are received */
    struct signaling_user_context user_ctx;
};

/**
 * Definition of the state the signaling module keeps for the hip daemon.
 */
struct signaling_hipd_state {
    /* Holds the connection context for the connection that is currently being established */
    struct signaling_connection_context ctx;
    /* Collects user certificates accross multiple updates */
    struct user_certificate_context user_cert_ctx;
    int update_in_progress;
};

int signaling_hipd_init_state(struct modular_state *state);

#endif /*HIP_HIPD_SIGNALING_HIPD_STATE_H*/
