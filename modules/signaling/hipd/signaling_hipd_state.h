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
#include "lib/core/linkedlist.h"
#include "modules/signaling/lib/signaling_prot_common.h"

struct user_certificate_context {
    uint32_t network_id;
    int      group;
    int      count;
    int      next_cert_id;
    STACK_OF(X509) * cert_chain;
};

/**
 * Definition of the state the signaling module keeps for the hip daemon.
 */
struct signaling_hipd_state {
    /* Holds the connection contexts for the connections that are currently being established */
    struct hip_ll *connections;

    /* Points to a connection context with status pending.
     * We need this to determine which context to use in I2 and R2. */
    struct signaling_connection        *pending_conn;
    struct signaling_connection_context pending_conn_context;
    uint8_t                             flag_user_sig;
    void                               *service_ack[10];
    /* Collects user certificates accross multiple updates */
    struct user_certificate_context user_cert_ctx;
};

int signaling_hipd_init_state(struct modular_state *state);
int signaling_hipd_state_initialize_service_ack(struct signaling_hipd_state    *state);
struct signaling_connection *signaling_hipd_state_get_connection(struct signaling_hipd_state *state, uint32_t id,
                                                                 uint16_t src_port, uint16_t dst_port);
int signaling_hipd_state_get_connections_by_app_name(struct signaling_hipd_state *state,
                                                     char *app_name, struct hip_ll *ret_list);
void signaling_hipd_state_delete_connection(struct signaling_hipd_state *state, struct signaling_connection *conn);
struct signaling_connection *signaling_hipd_state_add_connection(struct signaling_hipd_state *state,
                                                                 const struct signaling_connection *const conn);
void signaling_hipd_state_print(struct signaling_hipd_state *state);

/* Utility functions*/
void signaling_port_pairs_from_hipd_state_by_app_name(struct signaling_hipd_state *state, char *app_name, struct signaling_port_pair *ports);
#endif /*HIP_HIPD_SIGNALING_HIPD_STATE_H*/
