/*
 * signaling_hipd_user_msg.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

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

/**
 * HIPFW resends a CONNECTION_REQUEST message to the HIPD, when it has been notified about
 * the successful establishment of another connection by the HIPD and HIPFW has waiting connections.
 *
 * @return          0 on sucess, negative on error
 */
int signaling_hipfw_send_connection_request(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
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
    signaling_connection_context_print(&conn->ctx_out, "");

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
        signaling_flag_unset(&new_conn.ctx_out.flags, USER_AUTHED);
    } else {
        signaling_flag_set(&new_conn.ctx_out.flags, USER_AUTHED);
    }

    /* Since this is a new connection we have to add an entry to the scdb */
    HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, &new_conn),
             -1, "Could not add entry to scdb.\n");

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
int signaling_hipfw_send_connection_context(const hip_hit_t *hits, const hip_hit_t *hitr,
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

    HIP_DEBUG("Sent connection context to HIPD for use in R2: \n");
    signaling_connection_context_print(&conn->ctx_out, "");

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
    //HIP_DUMP_MSG(msg);

    signaling_get_hits_from_msg(msg, &src_hit, &dst_hit);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
            -1, "No HIP_PARAM_SIGNALING_CONNECTION parameter in message.\n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    signaling_copy_connection(&conn, (const struct signaling_connection *) (param + 1));

    // todo: handle unauthed case porperly
    if (signaling_flag_check(conn.ctx_in.flags, USER_AUTHED) || !signaling_flag_check(conn.ctx_in.flags, USER_AUTHED)) {
        conn.status = SIGNALING_CONN_ALLOWED;
    }

    signaling_cdb_add(src_hit, dst_hit, &conn);
    signaling_cdb_print();

out_err:
    return err;
}

/**
 * This function receives and handles a message of type HIP_MSG_SIGNALING_REQUEST_CONNECTION
 * from the HIPD. This message means, that the HIPD is the responder to a new
 * connection with the application context included in this message. With this message the
 * HIPD requested the local connection context for the new connection.
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
int signaling_hipfw_handle_connection_context_request(struct hip_common *msg) {
    int err                                         = 0;
    const struct hip_tlv_common *param              = NULL;
    const hip_hit_t *hits                           = NULL;
    const hip_hit_t *hitr                           = NULL;
    const struct signaling_connection *conn         = NULL;
    struct signaling_connection new_conn;

    uint16_t src_port , dst_port;

    /* Get HITs and Ports from the message */
    signaling_get_hits_from_msg(msg, &hitr, &hits);
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Could not get connection parameter from connection request \n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    conn = (const struct signaling_connection *) (param + 1);
    dst_port = conn->src_port;
    src_port = conn->dst_port;

    HIP_DEBUG("Received connection context request for following context: \n");
    signaling_connection_context_print(&conn->ctx_in, "");

    /* a) check with local policy if we want to allow the remote connection context
     *    here we only assume that user authentication is required always
     * TODO: hand context to some policy decision engine */


    /* b) build the local connection context */
    HIP_IFEL(signaling_copy_connection(&new_conn, conn),
             -1, "Could not init connection context\n");
    HIP_IFEL(signaling_get_verified_application_context_by_ports(src_port, dst_port, &new_conn.ctx_out),
             -1, "Application lookup/verification failed.\n");
    HIP_IFEL(signaling_user_api_get_uname(new_conn.ctx_out.user.uid, &new_conn.ctx_out.user),
             -1, "Could not get user name \n");

    /* c) check with local policy if we want to allow the local connection context
     *    if we allow the connection, add it right away, or wait for user auth confirmation.
     *    TODO: hand local context to some policy decision engine
     *    */

    new_conn.status = SIGNALING_CONN_PROCESSING;
    signaling_cdb_add(hits, hitr, &new_conn);
    signaling_cdb_print();

    /* d) send answer to HIPD */
    signaling_hipfw_send_connection_context(hits, hitr, &new_conn);

out_err:
    return err;
}
