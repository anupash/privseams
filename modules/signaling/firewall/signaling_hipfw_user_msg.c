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
#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "signaling_hipfw_user_msg.h"
#include "signaling_cdb.h"

/**
 * HIPFW sends a CONNECTION_REQUEST message to the HIPD, when it has detected a new connection attempt.
 * In this case we are the initiator.
 *
 * @return          0 on sucess, negative on error
 */
int signaling_hipfw_send_connection_request(hip_hit_t *src_hit, hip_hit_t *dst_hit,
                                            uint16_t src_port, uint16_t dst_port) {
    int err = 0;
    struct signaling_connection_context *new_ctx    = NULL;
    struct hip_common *msg                          = NULL;

    /* Build the local connection context */
    HIP_IFEL(!(new_ctx = malloc(sizeof(struct signaling_connection_context))),
             -1, "Could not allocate memory for new connection context\n");
    HIP_IFEL(signaling_init_connection_context(new_ctx),
             -1, "Could not init connection context\n");
    HIP_IFEL(signaling_get_verified_application_context_by_ports(src_port, dst_port, new_ctx),
             -1, "Application lookup/verification failed.\n");
    HIP_IFEL(signaling_user_api_get_uname(new_ctx->user_ctx.euid, &new_ctx->user_ctx),
             -1, "Could not get user name \n");
    new_ctx->connection_status = SIGNALING_CONN_PENDING;

    /* Since this is a new connection we have to add an entry to the scdb */
    HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, new_ctx),
             -1, "Could not add entry to scdb.\n");

    /* Now request the connection from the HIPD */
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_REQUEST_CONNECTION, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, new_ctx, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT, sizeof(struct signaling_connection_context)),
             -1, "build connection context failed \n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

    HIP_DEBUG("Send request to HIPD to establish a new connection with following connection context: \n");
    signaling_connection_context_print(new_ctx);

out_err:
    if (err) {
        free(new_ctx);
    }
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
                                            const struct signaling_connection_context *ctx)
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
    HIP_IFEL(hip_build_param_contents(msg, ctx,
                                      HIP_PARAM_SIGNALING_CONNECTION_CONTEXT,
                                      sizeof(struct signaling_connection_context)),
             -1, "build application context failed \n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, 0), -1, "send_recv msg failed\n");

    HIP_DEBUG("Sent connection context to HIPD for use in R2: \n");
    signaling_connection_context_print(ctx);

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

    HIP_IFEL(signaling_cdb_handle_add_request(msg),
             -1, "Could not add connection to cdb \n");

    HIP_DEBUG("Got confirmation about connection from HIPD and added it to scdb: \n");
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
 *   a) check whether we want to allow this connection
     b) send an answer with the local context
 *
 * @param msg the message from the hipd
 *
 * @return 0 on success
 */
int signaling_hipfw_handle_connection_context_request(struct hip_common *msg) {
    int err                                         = 0;
    struct signaling_connection_context *new_ctx    = NULL;
    const struct hip_tlv_common *param              = NULL;
    const hip_hit_t *hits                           = NULL;
    const hip_hit_t *hitr                           = NULL;
    uint16_t src_port , dst_port;

    /* Get HITs and Ports from the message */
    signaling_get_hits_from_msg(msg, &hits, &hitr);
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_CONTEXT)),
             -1, "Could not get application context parameter from connection request \n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    dst_port = ((const struct signaling_connection_context *) (param + 1))->src_port;
    src_port = ((const struct signaling_connection_context *) (param + 1))->dest_port;

    HIP_DEBUG("Received connection context request for following context: \n");
    signaling_connection_context_print((const struct signaling_connection_context *) (param + 1));

    /* a) check if we want to allow the connection */
        // TODO: DO this here

    /* b) build the local connection context and send it */
    HIP_IFEL(!(new_ctx = malloc(sizeof(struct signaling_connection_context))),
             -1, "Could not allocate memory for new connection context\n");
    HIP_IFEL(signaling_init_connection_context(new_ctx),
             -1, "Could not init connection context\n");
    HIP_IFEL(signaling_get_verified_application_context_by_ports(src_port, dst_port, new_ctx),
             -1, "Application lookup/verification failed.\n");
    HIP_IFEL(signaling_user_api_get_uname(new_ctx->user_ctx.euid, &new_ctx->user_ctx),
             -1, "Could not get user name \n");
    new_ctx->connection_status = SIGNALING_CONN_ALLOWED;
    signaling_cdb_add(hits, hitr, new_ctx);
    signaling_cdb_print();
    signaling_hipfw_send_connection_context(hits, hitr, new_ctx);

out_err:
    return err;
}
