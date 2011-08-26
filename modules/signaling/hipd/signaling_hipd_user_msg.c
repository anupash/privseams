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
#include "lib/core/modularization.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "lib/core/message.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/netdev.h"
#include "hipd/user.h"

#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_user_management.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

/** Generic send function used to send to the firewall.
 *
 * @param msg       the message to be sent
 * @param block     set to 0 if no answer is expected,
 *                  set to 1 if function should block and wait for an answer
 * @return          0 on success, negative on error
 */
static int signaling_hipd_send_to_fw(struct hip_common *msg, const int block)
{
    struct sockaddr_in6 hip_fw_addr;
    struct sockaddr_in6 resp_addr;
    struct in6_addr loopback = in6addr_loopback;
    int err                  = 0;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_fw_addr.sin6_addr, &loopback);

    err = hip_sendto_user(msg, (struct sockaddr *) &hip_fw_addr);
    if (err < 0) {
        HIP_ERROR("Sending message to firewall failed\n");

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("Sending message to firewall successful\n");

        // this is needed if we want to use HIP_IFEL
        err = 0;
    }

    if (block) {
        HIP_DEBUG("Waiting for response on msg type %d\n", hip_get_msg_type(msg));
        HIP_IFEL(hip_read_user_control_msg(hip_user_sock, msg, &resp_addr),
                 -1, "Could not receive response on connection request\n");

    }

out_err:
    return err;
}

/**
 * Send a confirmation about the establishment of a new connection to the hipfw/oslayer.
 * This is the answer to a previous connection request from the hipfw/oslayer.
 *
 * @param hits      the source hit of the new connection (our local hit)
 * @param hitr      the remote hit of the new connection
 * @param appinfo   the application context for which the connection has been established
 *
 * @return          0 on success, negative on error
 */
static int signaling_send_connection_confirmation(const hip_hit_t *hits,
                                           const hip_hit_t *hitr,
                                           const struct signaling_connection *conn)
{
    struct hip_common *msg = NULL;
    int err                = 0;

    /* Build and send a HIP_MSG_SIGNALING_CONFIRM_CONNECTION message.
     * The message must identify the connection that has been established,
     * i.e. include HITs and application context. */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)),
            -1, "alloc memory for adding scdb entry\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CONFIRMATION, 0), -1,
              "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hits,
                                      HIP_PARAM_HIT,
                                      sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hitr,
                                      HIP_PARAM_HIT,
                                      sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
             -1, "build connection context failed \n");

    HIP_IFEL(signaling_hipd_send_to_fw(msg, 0), -1, "failed to send add scdb-msg to fw\n");

    HIP_DEBUG("Sent connection confirmation to firewall/oslayer: \n");
    signaling_connection_print(conn, "\t");

out_err:
    free(msg);
    return err;
}

/**
 * This functions receives and handles a message of type HIP_MSG_SIGNALING_CONNECTION_CONFIRMATION
 * from the firewall. This message is sent as the answer to a previous
 * HIP_MSG_SIGNALING_CONNECTION_REQUEST message from hipd to hipfw.
 * This message contains the local application context for the new connection.
 * We have to save the application context to our local state, so that it can
 * be included in an R2 or UPDATE later.
 *
 * @param msg   the answer from the firewall
 *
 * @return 0 on success, negative on error
 */
static int signaling_handle_connection_confirmation(struct hip_common *msg,
                                                    UNUSED struct sockaddr_in6 *src) {
    int err                                 = 0;
    const hip_hit_t *our_hit                = NULL;
    const hip_hit_t *peer_hit               = NULL;
    struct signaling_hipd_state *sig_state  = NULL;
    const struct hip_tlv_common *param      = NULL;
    hip_ha_t *entry                         = NULL;
    const struct signaling_connection *recv_conn  = NULL;
    struct signaling_connection *existing_conn = NULL;
    struct userdb_user_entry *db_entry = NULL;

    signaling_get_hits_from_msg(msg, &our_hit, &peer_hit);
    HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
             -1, "hadb entry has not been set up\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Missing connection parameter\n");
    // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
    recv_conn = (const struct signaling_connection *) (param + 1);

    existing_conn = signaling_hipd_state_get_connection(sig_state, recv_conn->id);
    if (!existing_conn) {
        HIP_IFEL(!(existing_conn = signaling_hipd_state_add_connection(sig_state, recv_conn)),
                 -1, "Could not save connection in local state\n");
    } else {
        HIP_IFEL(signaling_copy_connection(existing_conn, recv_conn),
                 -1, "Could not copy connection context to state \n");
    }

    /* add/update user in user db */
    if ((db_entry = userdb_add_user_from_msg(msg, 0))) {
        HIP_ERROR("Added new user from message\n");
        existing_conn->ctx_out.userdb_entry = db_entry;
    }

    HIP_DEBUG("Saved/updated state for connection received from hipfw:\n");
    signaling_connection_print(existing_conn, "");

out_err:
    return err;
}

/**
 * HIPD sends a HIP_MSG_SIGNALING_REQUEST_CONNECTION message to the firewall,
 * when it receives the remote connection context or updates of it.
 * With this message, HIPD tells HIPFW about the incoming connection
 * and gives HIPFW the chance to check this connection against the policy.
 *
 * @note This function blocks until the firewall has sent its response.
 *       The response must include the same connection but may have flags changed
 *       or content filled in.
 *
 * @param src_hit       src hit of the new incoming connection
 * @param dst_hit       dst hit of the new incoming connection
 * @param conn          the connection witht the incoming and outgoing connection context
 *                      if the outgoing is empty (standard values) the firewall needs
 *                      to look the context up and fill it in
 *
 * @return              0 on sucess, negative on error
  */
static int signaling_send_any_connection_request(const hip_hit_t *src_hit,
                                                 const hip_hit_t *dst_hit,
                                                 const int type,
                                                 const struct signaling_connection *conn) {
    int err = 0;
    struct hip_common *msg = NULL;

    /* sanity checks */
    HIP_IFEL(!conn,                -1, "Need connection state to build connection/update request\n");
    HIP_IFEL(!src_hit || !dst_hit, -1, "Need both source and destination hit \n");

    /* Allocate, build and send a message of type
     * HIP_MSG_SIGNALING_REQUEST_CONNECTION to the hipfw,
     * containing the receive application context */
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, type, 0), -1, "build hdr failed\n");

    /* Include hits and connection state */
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
            -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
             -1, "build connection context failed \n");

    /* Print and send */
    HIP_DEBUG("Sending connection request for following context to HIPFW:\n");
    signaling_connection_print(conn, "");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_HIPD_R2_FINISH, PERF_HIPD_I3_FINISH\n");
    hip_perf_stop_benchmark(perf_set, PERF_HIPD_R2_FINISH);
    hip_perf_stop_benchmark(perf_set, PERF_HIPD_I3_FINISH);
    HIP_DEBUG("Start PERF_USER_COMM\n");
    hip_perf_start_benchmark(perf_set, PERF_USER_COMM);
#endif
    HIP_IFEL(signaling_hipd_send_to_fw(msg, 1), -1, "failed to send/recv connection request to fw\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_USER_COMM\n");
    hip_perf_stop_benchmark(perf_set, PERF_USER_COMM);
#endif

    /* We expect the corresponding local application context in the response. */
    HIP_IFEL(signaling_handle_connection_confirmation(msg, NULL),
             -1, "Failed to process connection confirmation from hipfw/oslayer \n");

out_err:
    free(msg);
    return err;
}

int signaling_send_first_connection_request(const hip_hit_t *src_hit,
                                            const hip_hit_t *dst_hit,
                                            const struct signaling_connection *conn) {
    return signaling_send_any_connection_request(src_hit, dst_hit, HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST, conn);
}

int signaling_send_second_connection_request(const hip_hit_t *src_hit,
                                             const hip_hit_t *dst_hit,
                                             const struct signaling_connection *conn) {
    return signaling_send_any_connection_request(src_hit, dst_hit, HIP_MSG_SIGNALING_SECOND_CONNECTION_REQUEST, conn);
}

int signaling_send_connection_update_request(const hip_hit_t *src_hit,
                                             const hip_hit_t *dst_hit,
                                             const struct signaling_connection *conn) {
    return signaling_send_any_connection_request(src_hit, dst_hit, HIP_MSG_SIGNALING_CONNECTION_UPDATE_REQUEST, conn);
}

/**
 * This function receives and handles a messages of type HIP_MSG_SIGNALING_REQUEST_CONNECTION,
 * from the firewall. This message means, that the firewall wants the HIPD
 * to establish a new connection for the context contained in the message.
 *
 * We have to check whether to trigger a BEX or an UPDATE and do it.
 *   a) BEX:    We save the connection context to include it in the I2 later.
 *   b) UPDATE: We save the connection context and send the UPDATE right away.
 *
 * @param msg the message from the firewall
 *
 * @return 0 on success
 */
int signaling_handle_connection_request(struct hip_common *msg,
                                        struct sockaddr_in6 *src) {
    const hip_hit_t *our_hit    = NULL;
    const hip_hit_t *peer_hit   = NULL;
    const struct hip_tlv_common *param;
    hip_ha_t *entry = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct signaling_connection *conn = NULL;
    struct signaling_connection new_conn;
    int err = 0;
    struct userdb_user_entry *db_entry = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_TRIGGER_CONN\n");
        hip_perf_start_benchmark(perf_set, PERF_TRIGGER_CONN);
#endif

    /* Determine if we already have an association */
    signaling_get_hits_from_msg(msg, &our_hit, &peer_hit);
    entry = hip_hadb_find_byhits(our_hit, peer_hit);

    /* Now check whether we need to trigger a BEX or an UPDATE */
    if(entry) {   // UPDATE
        /* check if there is a connection context, if not exit */
        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
                 -1, "Missing application_context parameter\n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");

        /* get a local copy of the connection context */
        HIP_IFEL(signaling_copy_connection(&new_conn, (const struct signaling_connection *) (param + 1)),
                 -1, "Could not copy connection context\n");

        /* check if previous BEX has been completed */
        if ((entry->state != HIP_STATE_ESTABLISHED && entry->state != HIP_STATE_R2_SENT)) {
            new_conn.status         = SIGNALING_CONN_WAITING;
        } else {
            new_conn.status         = SIGNALING_CONN_PROCESSING;
        }

        /* save application context to our local state */
        HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                 -1, "Could save connection in local state\n");

        /* add/update user in user db */
        if (!(db_entry = userdb_add_user_from_msg(msg, 0))) {
            HIP_ERROR("Could not add user from message\n");
        }
        conn->ctx_out.userdb_entry = db_entry;

        /* now trigger the UPDATE */
        if (conn->status == SIGNALING_CONN_PROCESSING) {
            HIP_IFEL(signaling_send_first_update(our_hit, peer_hit, conn),
                     -1, "Failed triggering first bex update.\n");
            HIP_DEBUG("Triggered UPDATE for following connection context:\n");
            signaling_connection_print(conn, "");
        } else {
            HIP_DEBUG("We have a BEX running, postponing establishment of new connection for: \n");
            signaling_connection_print(conn, "");
        }

    } else {       // BEX
        HIP_DEBUG("Triggering BEX \n");
        // trigger bex since we intercepted the packet before it could be handled by the hipfw
        HIP_IFEL(hip_netdev_trigger_bex_msg(msg, src),
                 -1, "Netdev could not trigger the BEX\n");
        // have to do this again after triggering BEX since there is no state before
        HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "hadb entry has not been set up\n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");
        HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
                 -1, "Missing application_context parameter\n");
        // "param + 1" because we need to skip the hip_tlv_common_t header to get to the connection context struct
        HIP_IFEL(signaling_copy_connection(&new_conn, (const struct signaling_connection *) (param + 1)),
                 -1, "Could not copy connection\n");
        new_conn.status         = SIGNALING_CONN_PROCESSING;

        /* save application context to our local state */
        HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                 -1, "Could not save connection in local state\n");

        /* add/update user in user db */
        if (!(db_entry = userdb_add_user_from_msg(msg, 0))) {
            HIP_ERROR("Could not add user from message\n");
        }
        conn->ctx_out.userdb_entry = db_entry;

        HIP_DEBUG("Started new BEX for following connection context:\n");
        signaling_connection_print(conn, "");
    }


    /* send status for new connection to os layer */
    signaling_send_connection_confirmation(our_hit, peer_hit, conn);

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_TRIGGER_CONN\n");
        hip_perf_stop_benchmark(perf_set, PERF_TRIGGER_CONN);
        hip_perf_write_benchmark(perf_set, PERF_TRIGGER_CONN);
#endif
out_err:
    return err;
}
