/*
 * signaling_hipd_user_msg.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <string.h>

#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/debug.h"
#include "lib/core/lmod.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "lib/core/message.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/user.h"

#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "signaling_hipfw_user_msg.h"
#include "signaling_cdb.h"
#include "signaling_policy_engine.h"

/**
 * HIPFW resends a CONNECTION_REQUEST message to the HIPD, when it has been notified about
 * the successful establishment of another connection by the HIPD and HIPFW has waiting connections.
 *
 * @return          0 on sucess, negative on error
 */
static int signaling_hipfw_send_connection_request(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                                                   const struct signaling_connection *const conn) {
    int err                 = 0;
    struct hip_common *msg  = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_REQUEST_CONNECTION, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
             -1, "build connection parameter failed \n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

    HIP_DEBUG("Sent request to HIPD to establish a connection with following connection context: \n");
    signaling_connection_print(conn, "");

out_err:
    free(msg);
    return err;
}


/**
 * HIPFW sends a CONNECTION_REQUEST message to the HIPD, when it has detected a new connection attempt.
 * In this case we are the initiator.
 *
 * @return          0 on sucess, negative on error
 */
int signaling_hipfw_send_connection_request_by_ports(hip_hit_t *src_hit, hip_hit_t *dst_hit,
                                                     uint16_t src_port, uint16_t dst_port) {
    int err = 0;
    struct signaling_connection new_conn;
    struct hip_common *msg                          = NULL;

    /* Build the local connection context */
    HIP_IFEL(signaling_init_connection(&new_conn),
             -1, "Could not init connection context\n");
    new_conn.status            = SIGNALING_CONN_NEW;
    new_conn.id                = signaling_cdb_get_next_connection_id();
    new_conn.src_port = src_port;
    new_conn.dst_port = dst_port;

    if (signaling_get_verified_application_context_by_ports(src_port, dst_port, &new_conn.ctx_out)) {
        HIP_DEBUG("Application lookup/verification failed.\n");
    }

    if (signaling_user_api_get_uname(new_conn.ctx_out.user.uid, &new_conn.ctx_out.user)) {
        HIP_DEBUG("Could not get user name \n");
    }

    /* Check the local context against out local policy,
     * block this connection if context is rejected */
    if (!signaling_policy_check(src_hit, &new_conn.ctx_out)) {
        HIP_DEBUG("Received connection request has been rejected by local policy (outgoing context rejected) \n");
        new_conn.status = SIGNALING_CONN_BLOCKED;
        HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, &new_conn), -1, "Could not insert connection into cdb\n");
        signaling_cdb_print();
        return 0;
    }

    /* set local host and user to authed since we have passed policy check */
    signaling_flag_set(&new_conn.ctx_out.flags, USER_AUTHED);
    signaling_flag_set(&new_conn.ctx_out.flags, HOST_AUTHED);

    /* Since this is a new connection we have to add an entry to the scdb */
    HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, &new_conn),
             -1, "Could not add entry to scdb.\n");
    signaling_cdb_print();

    /* Now request the connection from the HIPD */
    signaling_hipfw_send_connection_request(src_hit, dst_hit, &new_conn);

out_err:
    free(msg);
    return err;
}

/**
 * Send a confirmation about the establishment of a new connection to the HIPD.
 * This is the answer to a previous connection context request from the HIPD.
 * We have to include the local application context in our answer.
 *
 * @param hits      the source hit of the new connection (our local hit)
 * @param hitr      the remote hit of the new connection
 * @param appinfo   the local application context for which the application has been established
 *
 * @return          0 on success, negative on error
 */
static int signaling_hipfw_send_connection_confirmation(const hip_hit_t *hits, const hip_hit_t *hitr,
                                                        const struct signaling_connection *const conn)
{
    int err                 = 0;
    struct hip_common *msg  = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CONFIRM_CONNECTION, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hitr, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hits, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, conn,
                                      HIP_PARAM_SIGNALING_CONNECTION,
                                      sizeof(struct signaling_connection)),
             -1, "build application context failed \n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, 0), -1, "send_recv msg failed\n");

    HIP_DEBUG("Sent connection confirmation to HIPD: \n");
    signaling_connection_print(conn, "");

out_err:
    free(msg);
    return err;
}

/**
 * This function receives and handles a message of type HIP_MSG_SIGNALING_CONNECTION_CONFIRMATION
 * from the HIPD. This message is send as the answer to a previous
 * HIP_MSG_SIGNALING_CONNECTION_REQUEST message from hipfw to hipd.
 * This message contains the local application context for the new connection.
 *
 * @param msg   the confirmation from the HIPD
 *
 * @return      0 on success, negative on error
 */
int signaling_hipfw_handle_connection_confirmation(struct hip_common *msg) {
    int err = 0;
    const struct hip_tlv_common *param          = NULL;
    const hip_hit_t *src_hit                    = NULL;
    const hip_hit_t *dst_hit                    = NULL;
    struct signaling_connection conn;

    HIP_IFEL(hip_get_msg_type(msg) != HIP_MSG_SIGNALING_CONFIRM_CONNECTION,
            -1, "Message has wrong type, expected HIP_MSG_SIGNALING_CONFIRM_CONNECTION.\n");

    HIP_DEBUG("Got confirmation about a previously requested connection from HIPD\n");

    signaling_get_hits_from_msg(msg, &src_hit, &dst_hit);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
            -1, "No HIP_PARAM_SIGNALING_CONNECTION parameter in message.\n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    signaling_copy_connection(&conn, (const struct signaling_connection *) (param + 1));

    signaling_cdb_add(src_hit, dst_hit, &conn);
    signaling_cdb_print();

out_err:
    return err;
}

/**
 * This function receives and handles a message of type HIP_MSG_SIGNALING_REQUEST_CONNECTION
 * from the HIPD. The message contains at least the remote connection context. If it does not
 * contain the local connection context, the connection is new and the firewall must perform
 * the lookup of application and user. Otherwise the firewall checks the supplied contexts
 * against the local policy.
 *
 * We have to
 *   a) check whether we want to allow the remote connection context
 *   b) establish the local connection context
 *   c) check whether to allow the local connection context
     d) send an answer with the local context
 *
 * @param msg the message from the hipd
 *
 * @return 0 on success
 */
int signaling_hipfw_handle_connection_request(struct hip_common *msg) {
    int err                                         = 0;
    const struct hip_tlv_common *param              = NULL;
    const hip_hit_t *hits                           = NULL;
    const hip_hit_t *hitr                           = NULL;
    const struct signaling_connection *recv_conn    = NULL;
    struct signaling_connection *existing_conn      = NULL;
    struct signaling_connection new_conn;

    /* Establish the connection context */
    signaling_get_hits_from_msg(msg, &hitr, &hits);
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Could not get connection parameter from connection request \n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    recv_conn = (const struct signaling_connection *) (param + 1);
    HIP_DEBUG("Received connection request from HIPD\n");
    signaling_connection_print(recv_conn, "\t");
    signaling_copy_connection(&new_conn, recv_conn);

    /* Check the remote context against out local policy,
     * block this connection if context is rejected */
    if (!signaling_policy_check(hits, &new_conn.ctx_in)) {
        HIP_DEBUG("Received connection request has been rejected by local policy (incoming context rejected) \n");
        new_conn.status = SIGNALING_CONN_BLOCKED;
        HIP_IFEL(signaling_cdb_add(hits, hitr, &new_conn), -1, "Could not insert connection into cdb\n");
        signaling_cdb_print();
        signaling_hipfw_send_connection_confirmation(hits, hitr, &new_conn);
        return 0;
    }

    /* Check if this is a first time connection request.
     * In this case we need to build the local connection context.
     * If not we update our incoming connection context. */
    existing_conn = signaling_cdb_entry_get_connection(hits, hitr, recv_conn->id);
    if(!existing_conn) {
        if (signaling_get_verified_application_context_by_ports(recv_conn->src_port, recv_conn->dst_port, &new_conn.ctx_out)) {
            HIP_DEBUG("Application lookup/verification failed.\n");
        }
        if (signaling_user_api_get_uname(new_conn.ctx_out.user.uid, &new_conn.ctx_out.user)) {
            HIP_DEBUG("Could not get user name \n");
        }
        HIP_IFEL(signaling_cdb_add(hits, hitr, &new_conn),
                 -1, "Could not add new connection to cdb \n");
        HIP_IFEL(!(existing_conn = signaling_cdb_entry_get_connection(hits, hitr, new_conn.id)),
                 -1, "Could not retrieve cdb entry \n");
    } else {
        signaling_copy_connection_context(&existing_conn->ctx_in, &recv_conn->ctx_in);
    }

    /* todo: [AUTH] for now, we dont care for user auth at the local side */
    signaling_flag_set(&existing_conn->ctx_in.flags, HOST_AUTHED);
    signaling_flag_set(&existing_conn->ctx_in.flags, USER_AUTHED);

    /* Now, we have handled the differences between an initial connection request and an update request.
     * We now need to check the local context against our local policy,
     * block the connection if the context is rejected */
    if (!signaling_policy_check(hits, &existing_conn->ctx_out)) {
        HIP_DEBUG("Received connection request has been rejected by local policy (outgoing context rejected) \n");
        existing_conn->status = SIGNALING_CONN_BLOCKED;
        signaling_cdb_print();
        signaling_hipfw_send_connection_confirmation(hits, hitr, existing_conn);
        return 0;
    }

    /* Both the incoming and outgoing contexts have passed local policy checks.
     * Now, we need to determine the state transition for the connection. */
    switch (existing_conn->status) {
    case SIGNALING_CONN_NEW:
        existing_conn->status = SIGNALING_CONN_PROCESSING;
        /* todo: [AUTH] just set the flags, since they are not significatn for the outgoing context */
        signaling_flag_set(&existing_conn->ctx_out.flags, HOST_AUTHED);
        signaling_flag_set(&existing_conn->ctx_out.flags, USER_AUTHED);
        break;
    case SIGNALING_CONN_PROCESSING:
        if (signaling_flag_check_auth_complete(existing_conn->ctx_out.flags) &&
            signaling_flag_check_auth_complete(existing_conn->ctx_in.flags)) {
            existing_conn->status = SIGNALING_CONN_ALLOWED;
        }
        break;
    default:
        HIP_ERROR("Connection state is not allowed at this point: %s \n", signaling_connection_status_name(existing_conn->status));
    }

    /* Finally send a positive answer back to HIPD */
    signaling_hipfw_send_connection_confirmation(hits, hitr, existing_conn);

out_err:
    return err;
}
