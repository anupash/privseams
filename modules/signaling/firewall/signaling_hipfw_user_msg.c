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
                                 const uint16_t src_port,
                                 const uint16_t dst_port)
{
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
    sprintf(buf, "ip6tables -I HIPFW-OUTPUT -p tcp -s %s -d %s --sport %d --dport %d -j ACCEPT && "
                 "ip6tables -I HIPFW-INPUT -p tcp -d %s -s %s --dport %d --sport %d -j ACCEPT",
            src_hit, dst_hit, src_port, dst_port, src_hit, dst_hit, src_port, dst_port);
    //system_print(buf);
    //sprintf(buf, "ip6tables -I HIPFW-INPUT -p tcp -d %s -s %s --dport %d --sport %d -j ACCEPT",
    //        src_hit, dst_hit, ports[i].src_port, ports[i].dst_port);
    system_print(buf);
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
int signaling_hipfw_send_connection_request(const hip_hit_t src_hit,
                                            const hip_hit_t dst_hit,
                                            const uint16_t src_port,
                                            const uint16_t dst_port)
{
    int                err = 0;
    struct hip_common *msg = NULL;

    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_HIPFW_CONNECTION_REQUEST, 0),
             -1, "build hdr failed\n");
    HIP_IFEL(hip_build_param_contents(msg, &dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, &src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, &dst_port, HIP_PARAM_PORT, sizeof(uint16_t)),
             -1, "build param contents (dst port) failed\n");
    HIP_IFEL(hip_build_param_contents(msg, &src_port, HIP_PARAM_PORT, sizeof(uint16_t)),
             -1, "build param contents (src port) failed\n");

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
    HIP_DEBUG_HIT("Src HIT:\t\t", &src_hit);
    HIP_DEBUG_HIT("Dst HIT:\t\t", &dst_hit);
    HIP_DEBUG("Src Port:\t\t%u\n", src_port);
    HIP_DEBUG("Dst Port:\t\t%u\n", dst_port);

out_err:
    free(msg);
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
int signaling_handle_hipd_connection_confirmation(struct hip_common *msg)
{
    const struct hip_tlv_common *param = NULL;
    const hip_hit_t             *hits  = NULL;
    const hip_hit_t             *hitr  = NULL;
    struct signaling_connection  recv_conn;
    struct signaling_cdb_entry  *entry = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HIPFW_REQ2, PERF_HIPFW_R2_FINISH\n");
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_REQ2);
    hip_perf_start_benchmark(perf_set, PERF_HIPFW_R2_FINISH);
#endif

    HIP_ASSERT(msg != NULL);

    /* Get and update the local connection state */
    signaling_get_hits_from_msg(msg, &hits, &hitr);

    if (!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION))) {
        HIP_ERROR("Could not get connection parameter from connection request\n");
        return -1;
    }
    signaling_copy_connection(&recv_conn, (const struct signaling_connection *) (param + 1));

    HIP_DEBUG_HIT("Src Hit: \t ", hits);
    HIP_DEBUG_HIT("Dst Hit: \t ", hitr);
    HIP_DEBUG("Src Port = %u, dst_port = %u.\n", recv_conn.src_port, recv_conn.src_port);

    if ((entry = signaling_cdb_get_connection(*hits, *hitr,
                                              recv_conn.src_port, recv_conn.dst_port)) != NULL) {
        entry->status = SIGNALING_CONN_ALLOWED;
        insert_iptables_rule(hits, hitr, recv_conn.src_port, recv_conn.dst_port);
    } else {
        HIP_ERROR("No state found for connection confirmed by hipd.\n");
        return -1;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_NEW_CONN\n");
    hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
    HIP_DEBUG("Stop PERF_NEW_UPDATE_CONN\n");
    hip_perf_stop_benchmark(perf_set, PERF_NEW_UPDATE_CONN);
#endif

    signaling_cdb_print();

    return 0;
}
