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
#include "modules/signaling/lib/signaling_user_api.h"
#include "modules/signaling/lib/signaling_oslayer.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

/**
 * HIPD sends a HIP_MSG_SIGNALING_HIPD_CONNECTION_CONFIRMATION message to hipfw,
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
int signaling_send_connection_confirmation(const hip_hit_t *src_hit,
                                           const hip_hit_t *dst_hit,
                                           const struct signaling_connection *conn)
{
    int                err = 0;
    struct hip_common *msg = NULL;

    /* sanity checks */
    HIP_IFEL(!conn,                -1, "Need connection state to build connection/update request\n");
    HIP_IFEL(!src_hit || !dst_hit, -1, "Need both source and destination hit \n");

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg,
                                HIP_MSG_SIGNALING_HIPD_CONNECTION_CONFIRMATION,
                                0),
             -1, "build hdr failed\n");

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
    HIP_DEBUG("Stop PERF_HIPD_R2_FINISH, PERF_CERTIFICATE_EXCHANGE\n");
    hip_perf_stop_benchmark(perf_set, PERF_HIPD_R2_FINISH);
    hip_perf_stop_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    HIP_DEBUG("Start PERF_USER_COMM\n");
    hip_perf_start_benchmark(perf_set, PERF_USER_COMM);
    hip_perf_start_benchmark(perf_set, PERF_USER_COMM_UPDATE);
#endif
    HIP_IFEL(hip_send_to_hipfw(msg), -1, "failed to send/recv connection request to fw\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_USER_COMM\n");
    hip_perf_stop_benchmark(perf_set, PERF_USER_COMM);
    hip_perf_stop_benchmark(perf_set, PERF_USER_COMM_UPDATE);
#endif

out_err:
    free(msg);
    return err;
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
                                        struct sockaddr_in6 *src)
{
    const hip_hit_t                    *our_hit   = NULL;
    const hip_hit_t                    *peer_hit  = NULL;
    const uint16_t                     *our_port  = 0;
    const uint16_t                     *peer_port = 0;
    const struct hip_tlv_common        *param;
    struct hip_hadb_state              *entry     = NULL;
    struct signaling_hipd_state        *sig_state = NULL;
    struct signaling_connection        *conn      = NULL;
    struct signaling_connection         new_conn;
    struct signaling_connection_context ctx_out;
    int                                 err = 0;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_TRIGGER_CONN\n");
    hip_perf_start_benchmark(perf_set, PERF_TRIGGER_CONN);
#endif
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIT)),
             -1, "Missing (src HIT) parameter\n");
    peer_hit = hip_get_param_contents_direct(param);
    HIP_IFEL(!(param = hip_get_next_param(msg, param)),
             -1, "Missing (dst HIT) parameter\n");
    our_hit = hip_get_param_contents_direct(param);
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_PORT)),
             -1, "Missing (dst port) parameter\n");
    peer_port = hip_get_param_contents_direct(param);
    HIP_IFEL(!(param = hip_get_next_param(msg, param)),
             -1, "Missing (src port) parameter\n");
    our_port = hip_get_param_contents_direct(param);

    /* TODO this parts seems broken. Contexts are looked up in
     * signaling_init_connection_context() and
     * signaling_netstat_get_application_system_info_by_ports().
     * Furthermore, the connection context should be looked up only after
     * sending the I1 message. */
    HIP_IFEL(signaling_init_connection(&new_conn),
             -1, "Could not init connection context\n");
    HIP_IFEL(signaling_init_connection_context(&ctx_out, OUT),
             -1, "Could not init connection context\n");

    /* Determine if we already have an association */
    entry = hip_hadb_find_byhits(our_hit, peer_hit);
    //entry = hip_hadb_find_byhits(peer_hit, our_hit);
    HIP_DEBUG("our_port = %u, peer_port= %u \n", ntohs(*our_port), ntohs(*peer_port));

    /* Now check whether we need to trigger a BEX or an UPDATE */
    if (entry) {   // UPDATE
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");

        new_conn.id = 0; //some random initiatialization .. will remove it later
                         //conn->id;
        new_conn.src_port = ntohs(*our_port);
        new_conn.dst_port = ntohs(*peer_port);

        memcpy(&sig_state->pending_conn_context.host, &signaling_persistent_host, sizeof(struct signaling_host_context));
        HIP_IFEL(signaling_get_verified_application_context_by_ports(&new_conn, &sig_state->pending_conn_context), -1, "Getting application context failed.\n");
        HIP_IFEL(signaling_get_verified_user_context(&sig_state->pending_conn_context), -1, "Getting user context failed.\n");



        /* save application context to our local state */
        HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                 -1, "Could save connection in local state\n");

        /* now trigger the UPDATE */
        //TODO talk to Rene about this
//        if (conn->status == SIGNALING_CONN_PROCESSING) {
        HIP_IFEL(signaling_send_first_update(our_hit, peer_hit, conn),
                 -1, "Failed triggering first bex update.\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_TRIGGER_CONN\n");
        hip_perf_stop_benchmark(perf_set, PERF_TRIGGER_CONN);
#endif
        HIP_DEBUG("Triggered UPDATE for following connection context:\n");
        signaling_connection_print(conn, "");
//        } else {
        HIP_DEBUG("We have a BEX running, postponing establishment of new connection for: \n");
        signaling_connection_print(conn, "");
//        }
    } else {       // BEX
        HIP_DEBUG("Triggering BEX \n");
        // trigger bex since we intercepted the packet before it could be handled by the hipfw
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_COMPLETE_BEX\n");
        hip_perf_start_benchmark(perf_set, PERF_COMPLETE_BEX);
#endif
        HIP_IFEL(hip_netdev_trigger_bex_msg(msg, src),
                 -1, "Netdev could not trigger the BEX\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_TRIGGER_CONN\n");
        hip_perf_stop_benchmark(perf_set, PERF_TRIGGER_CONN);
#endif
        // have to do this again after triggering BEX since there is no state before
        HIP_IFEL(!(entry = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "hadb entry has not been set up\n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");

        new_conn.id = 0; //some random initiatialization .. will remove it later
                         //conn->id;
        new_conn.src_port = ntohs(*our_port);
        new_conn.dst_port = ntohs(*peer_port);

        memcpy(&sig_state->pending_conn_context.host, &signaling_persistent_host, sizeof(struct signaling_host_context));
        HIP_IFEL(signaling_get_verified_application_context_by_ports(&new_conn, &sig_state->pending_conn_context), -1, "Getting application context failed.\n");
        HIP_IFEL(signaling_get_verified_user_context(&sig_state->pending_conn_context), -1, "Getting user context failed.\n");


        /* save application context to our local state */
        HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                 -1, "Could not save connection in local state\n");

        HIP_DEBUG("Started new BEX for following connection context:\n");
        signaling_connection_print(conn, "");
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_TRIGGER_CONN, PERF_CONN_U1_HOST_SIGN, PERF_CONN_U1_USER_SIGN, PERF_I_HOST_CTX_LOOKUP,"
              "PERF_I_NETSTAT_LOOKUP, PERF_I_USER_CTX_LOOKUP, PERF_I_APP_CTX_LOOKUP, PERF_I_X509AC_VERIFY_CERT_CHAIN,"
              "PERF_I_VERIFY_APPLICATION, PERF_I_LOAD_USER_CERT, PERF_I_LOAD_USER_NAME\n");
    hip_perf_write_benchmark(perf_set, PERF_TRIGGER_CONN);
    hip_perf_write_benchmark(perf_set, PERF_CONN_U1_HOST_SIGN);
    hip_perf_write_benchmark(perf_set, PERF_CONN_U1_USER_SIGN);

    hip_perf_write_benchmark(perf_set, PERF_I_HOST_CTX_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_I_APP_CTX_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_I_NETSTAT_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_I_X509AC_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_I_VERIFY_APPLICATION);
    hip_perf_write_benchmark(perf_set, PERF_I_USER_CTX_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_I_LOAD_USER_CERT);
    hip_perf_write_benchmark(perf_set, PERF_I_LOAD_USER_NAME);

#endif

out_err:
    return err;
}
