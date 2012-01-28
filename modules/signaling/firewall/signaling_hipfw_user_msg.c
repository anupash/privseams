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
#include "lib/core/modularization.h"
#include "lib/core/builder.h"
#include "lib/core/prefix.h"
#include "lib/core/message.h"
#include "hipd/hadb.h"
#include "hipd/hipd.h"
#include "hipd/user.h"
#include "firewall/helpers.h"

#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "signaling_hipfw_user_msg.h"
#include "signaling_cdb.h"
#include "signaling_policy_engine.h"

static void insert_iptables_rule(const struct in6_addr *const s,
                                 const struct in6_addr *const d,
                                 const struct signaling_port_pair *const ports)
{
    int  i = 0;
    char buf[400];
    char src_hit[41];
    char dst_hit[41];

    if (!inet_ntop(AF_INET6, s, src_hit, sizeof(src_hit))) {
        return;
    }
    if (!inet_ntop(AF_INET6, d, dst_hit, sizeof(dst_hit))) {
        return;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_IP6TABLES\n");
    hip_perf_start_benchmark(perf_set, PERF_IP6TABLES);
#endif
    while (i < SIGNALING_MAX_SOCKETS && ports[i].src_port != 0 && ports[i].src_port != 0) {
        sprintf(buf, "ip6tables -I HIPFW-OUTPUT -p tcp -s %s -d %s --sport %d --dport %d -j ACCEPT &&"
                     "ip6tables -I HIPFW-INPUT -p tcp -d %s -s %s --dport %d --sport %d -j ACCEPT",
                src_hit, dst_hit, ports[i].src_port, ports[i].dst_port, src_hit, dst_hit, ports[i].src_port, ports[i].dst_port);
        //system_print(buf);
        //sprintf(buf, "ip6tables -I HIPFW-INPUT -p tcp -d %s -s %s --dport %d --sport %d -j ACCEPT",
        //        src_hit, dst_hit, ports[i].src_port, ports[i].dst_port);
        system_print(buf);
        i++;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_IP6TABLES\n");
    hip_perf_stop_benchmark(perf_set, PERF_IP6TABLES);
    hip_perf_write_benchmark(perf_set, PERF_IP6TABLES);
#endif
}

/**
 * HIPFW resends a CONNECTION_REQUEST message to the HIPD, when it has been notified about
 * the successful establishment of another connection by the HIPD and HIPFW has waiting connections.
 *
 * @return          0 on sucess, negative on error
 */
//TODO remove the signaling_connection parameter from the function.
int signaling_hipfw_send_connection_request(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                                            const struct signaling_connection *const conn)
{
    int                err = 0;
    struct hip_common *msg = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
             -1, "build connection parameter failed \n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_SEND_CONN_REQUEST\n");
    hip_perf_start_benchmark(perf_set, PERF_SEND_CONN_REQUEST);
#endif
    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, 0), -1, "send_recv msg failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_SEND_CONN_REQUEST\n");
    hip_perf_stop_benchmark(perf_set, PERF_SEND_CONN_REQUEST);
    hip_perf_write_benchmark(perf_set, PERF_SEND_CONN_REQUEST);
#endif

    HIP_DEBUG("Sent request to HIPD to establish a connection with following connection context: \n");
    signaling_connection_print(conn, "");

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
    int                err = 0;
    struct hip_common *msg = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CONFIRMATION, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hitr, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, hits, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");

    HIP_IFEL(hip_build_param_contents(msg, conn,
                                      HIP_PARAM_SIGNALING_CONNECTION,
                                      sizeof(struct signaling_connection)),
             -1, "build shorter application context failed \n");

    HIP_IFEL(hip_send_recv_daemon_info(msg, 1, 0), -1, "send_recv msg failed\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_HIPFW_REQ1, PERF_HIPFW_REQ2, PERF_HIPFW_REQ3\n");
    hip_perf_stop_benchmark(perf_set, PERF_HIPFW_REQ1);
    hip_perf_stop_benchmark(perf_set, PERF_HIPFW_REQ2);
    hip_perf_stop_benchmark(perf_set, PERF_HIPFW_REQ3);

    HIP_DEBUG("Write PERF_NEW_CONN, PERF_NEW_UPDATE_CONN, PERF_HIPFW_R2_FINISH, PERF_HIPFW_I3_FINISH, PERF_HIPFW_REQ1, PERF_HIPFW_REQ2, PERF_HIPFW_REQ3, PERF_NETSTAT_LOOKUP, PERF_VERIFY_APPLICATION, PERF_CTX_LOOKUP, PERF_X509AC_VERIFY_CERT_CHAIN, PERF_HASH\n");
    hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
    hip_perf_write_benchmark(perf_set, PERF_NEW_UPDATE_CONN);
    hip_perf_write_benchmark(perf_set, PERF_HIPFW_REQ1);
    hip_perf_write_benchmark(perf_set, PERF_HIPFW_REQ2);
    hip_perf_write_benchmark(perf_set, PERF_HIPFW_REQ3);
    hip_perf_write_benchmark(perf_set, PERF_NETSTAT_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_VERIFY_APPLICATION);
    hip_perf_write_benchmark(perf_set, PERF_HASH);
    hip_perf_write_benchmark(perf_set, PERF_CTX_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_X509AC_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_HIPFW_R2_FINISH);
    hip_perf_write_benchmark(perf_set, PERF_HIPFW_I3_FINISH);
#endif

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
int signaling_hipfw_handle_connection_confirmation(struct hip_common *msg)
{
    int                          err     = 0;
    const struct hip_tlv_common *param   = NULL;
    const hip_hit_t             *src_hit = NULL;
    const hip_hit_t             *dst_hit = NULL;
    struct signaling_cdb_entry  *entry = NULL;
    struct signaling_connection  conn;

    HIP_IFEL(hip_get_msg_type(msg) != HIP_MSG_SIGNALING_CONFIRMATION,
             -1, "Message has wrong type, expected HIP_MSG_SIGNALING_CONFIRM_CONNECTION.\n");

    HIP_DEBUG("Got confirmation about a previously requested connection from HIPD\n");

    signaling_get_hits_from_msg(msg, &src_hit, &dst_hit);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "No HIP_PARAM_SIGNALING_CONNECTION_SHORT parameter in message.\n");
    /* "param + 1" because we need to skip the hip_tlv_common header to get to
     * the connection context struct */
    signaling_copy_connection(&conn,
                              (const struct signaling_connection *) (param + 1));

    if ((entry = signaling_cdb_get_connection(src_hit, dst_hit,
                                              conn.src_port, conn.dst_port)) != NULL) {
        entry->status = SIGNALING_CONN_PROCESSING;
    } else {
        signaling_cdb_add_connection(src_hit, dst_hit,
                                     conn.src_port, conn.dst_port,
                                     SIGNALING_CONN_PROCESSING);
    }

    signaling_cdb_print();

out_err:
    return err;
}

/**
 * This function receives and handles a message of type HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST
 * from the HIPD. This message must only be sent by the HIPD after receiving an I2 or
 * the first BEX UPDATE. The message must contain the remote connection context from the Inititator.
 *
 * The firewall needs to
 *   a) check whether we want to allow the remote connection context
 *   b) establish the local connection context
 *   c) check whether to allow the local connection context
 *   d) send an answer with the local context
 *
 * @param msg the message from the hipd
 *
 * @return 0 on success
 */
int signaling_hipfw_handle_first_connection_request(struct hip_common *msg)
{
    int                          err       = 0;
    const struct hip_tlv_common *param     = NULL;
    const hip_hit_t             *src_hit   = NULL;
    const hip_hit_t             *dst_hit   = NULL;
    struct signaling_connection *conn = NULL;
    int                          status = SIGNALING_CONN_ALLOWED;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HIPFW_REQ1\n");
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_REQ1);
#endif

    /* sanity checks */
    HIP_IFEL(!msg, -1, "Msg is NULL \n");

    /* Establish a new connection state from the incoming connection context */
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Could not get connection short parameter from connection request \n");
    signaling_copy_connection(conn, (const struct signaling_connection *) (param + 1));

    signaling_get_hits_from_msg(msg, &src_hit, &dst_hit);

    if ((entry = signaling_cdb_get_connection(src_hit, dst_hit,
                                              conn.src_port, conn.dst_port)) != NULL) {
        entry->status = SIGNALING_CONN_ALLOWED;
    } else {
        signaling_cdb_add_connection(src_hit, dst_hit,
                                     conn.src_port, conn.dst_port,
                                     SIGNALING_CONN_ALLOWED);
    }

    signaling_hipfw_send_connection_confirmation(hits, hitr, &conn);

out_err:
    return err;
}

/**
 * This function receives and handles a message of type HIP_MSG_SIGNALING_SECOND_CONNECTION_REQUEST
 * from the HIPD. This message must only be sent by the HIPD after receiving an R2 or
 * the second BEX UPDATE. The message must contain the remote connection context from the Responder.
 *
 * The firewall needs to
 *   a) Check whether we want to allow the remote connection context.
 *   b) Send a confirmation.
 *
 * @param msg the message from the hipd
 *
 * @return 0 on success
 */
int signaling_hipfw_handle_second_connection_request(struct hip_common *msg)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;
    const hip_hit_t             *hits  = NULL;
    const hip_hit_t             *hitr  = NULL;
    //const struct signaling_connection       *recv_conn     = NULL;
    struct signaling_connection       *existing_conn = NULL;
    const struct signaling_connection *recv_conn;
    int                                status = SIGNALING_CONN_ALLOWED;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HIPFW_REQ2, PERF_HIPFW_R2_FINISH\n");
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_REQ2);
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_R2_FINISH);
#endif

    /* sanity checks */
    HIP_IFEL(!msg, -1, "Msg is NULL \n");

    /* Get and update the local connection state */
    signaling_get_hits_from_msg(msg, &hitr, &hits);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Could not get connection parameter from connection request \n");
    recv_conn = (const struct signaling_connection *) (param + 1);

    /*HIP_IFEL(!(existing_conn->id = signaling_cdb_entry_get_connection(hits, hitr, &recv_conn->src_port, &recv_conn->dst_port)),
             -1, "Received second connection request for non-existant connection id %d \n", recv_conn->id);*/

    /* Answer to HIPD */
    signaling_hipfw_send_connection_confirmation(hits, hitr, existing_conn);

out_err:
    return err;
}

/**
 *
 */
int signaling_hipfw_handle_connection_update_request(struct hip_common *msg)
{
    int                                err                  = 0;
    const struct hip_tlv_common       *param                = NULL;
    const hip_hit_t                   *hits                 = NULL;
    const hip_hit_t                   *hitr                 = NULL;
    const struct signaling_connection *recv_conn            = NULL;
    struct signaling_connection       *existing_conn        = NULL;
    uint32_t                          *existing_conn_id     = NULL;
    const struct signaling_cdb_entry  *entry                = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HIPFW_REQ3, PERF_HIPFW_I3_FINISH\n");
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_REQ3);
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_I3_FINISH);
#endif
    /* Get the connection state */
    signaling_get_hits_from_msg(msg, &hitr, &hits);

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION)),
             -1, "Could not get connection parameter from connection request \n");
    recv_conn = (const struct signaling_connection *) (param + 1);

    HIP_IFEL(!(entry = signaling_cdb_get_connection(*hits, *hitr, recv_conn->src_port, recv_conn->dst_port)),
             -1, "Received connection update request for non-existent connection id %d \n", recv_conn->id);

    HIP_DEBUG("Received connection update request from HIPD\n");

    /* Just copy whole connection state */
    signaling_copy_connection(existing_conn, recv_conn);

    /* Check if we want to allow the connection */
    // TODO update flags in the existing_conn
    if (entry->status == SIGNALING_CONN_BLOCKED) {
        HIP_DEBUG("Connection is blocked by peer host (or network).\n");
    } else {
        HIP_DEBUG("Can not yet allow this connection, because authentication is not complete:\n");
    }

    /* Answer to HIPD */
    signaling_hipfw_send_connection_confirmation(hits, hitr, existing_conn);

    return 0;

out_err:
    return err;
}
