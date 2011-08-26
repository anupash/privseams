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
#include "lib/core/hashtable.h"

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
    /* Holds the connection contexts for the connections that are currently being established */
    HIP_HASHTABLE *connections;

    /* Points to a connection context with status pending.
     * We need this to determine which context to use in I2 and R2. */
    struct signaling_connection *pending_conn;

    /* Collects user certificates accross multiple updates */
    struct user_certificate_context user_cert_ctx;
};

int signaling_hipd_init_state(struct modular_state *state);
struct signaling_connection *signaling_hipd_state_get_connection(struct signaling_hipd_state *state, uint32_t id);
void signaling_hipd_state_delete_connection(struct signaling_hipd_state *state, struct signaling_connection *conn);
struct signaling_connection * signaling_hipd_state_add_connection(struct signaling_hipd_state *state,
                                                                  const struct signaling_connection *const conn);
void signaling_hipd_state_print(struct signaling_hipd_state *state);

#endif /*HIP_HIPD_SIGNALING_HIPD_STATE_H*/
