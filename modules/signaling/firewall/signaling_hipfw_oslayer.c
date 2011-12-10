/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/core/builder.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "firewall/firewall.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "modules/signaling/lib/signaling_oslayer.h"

#include "signaling_hipfw_oslayer.h"
#include "signaling_hipfw_user_msg.h"
#include "signaling_cdb.h"
#include "signaling_policy_engine.h"

#define HIPFW_SIGNALING_CONF_FILE HIPL_SYSCONFDIR "/signaling_firewall_policy.cfg"

/* Init connection tracking data base */
int signaling_hipfw_oslayer_init(void)
{
    if (signaling_cdb_init()) {
        HIP_ERROR("Could not init connection tracking database \n");
        return -1;
    }

    if (signaling_policy_engine_init_from_file(HIPFW_SIGNALING_CONF_FILE)) {
        HIP_ERROR("Could not init connection tracking database \n");
        return -1;
    }

    return 0;
}

int signaling_hipfw_oslayer_uninit(void)
{
    return 0;
}

static int handle_new_connection(struct in6_addr *src_hit, struct in6_addr *dst_hit,
                                 uint16_t src_port, uint16_t dst_port)
{
    int                          err  = 0;
    struct signaling_connection *conn = NULL;
    struct signaling_connection  new_conn;
    int                          pos = 0;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_NEW_CONN, PERF_NEW_UPDATE_CONN, PERF_CONN_REQUEST\n");
    hip_perf_start_benchmark(perf_set, PERF_NEW_CONN);
    hip_perf_start_benchmark(perf_set, PERF_NEW_UPDATE_CONN);
    hip_perf_start_benchmark(perf_set, PERF_CONN_REQUEST);
#endif

    /* We have no waiting contexts. So build the local connection context and queue it. */
    HIP_IFEL(signaling_init_connection(&new_conn),
             -1, "Could not init connection context\n");
    new_conn.status              = SIGNALING_CONN_PROCESSING;;
    new_conn.id                  = signaling_cdb_get_next_connection_id();
    new_conn.side                = INITIATOR;
    new_conn.sockets[0].src_port = src_port;
    new_conn.sockets[0].dst_port = dst_port;

    /* Look up the host context */
    //TODO write the handler for verification of host identifier
    if (signaling_get_verified_application_context_by_ports(src_port, dst_port, &new_conn.ctx_out)) {
        HIP_DEBUG("Host lookup/verification failed, assuming ANY HOST.\n");
        signaling_init_host_context(&new_conn.ctx_out.host);
    }
    if (signaling_get_verified_application_context_by_ports(src_port, dst_port, &new_conn.ctx_out)) {
        HIP_DEBUG("Application lookup/verification failed, assuming ANY APP.\n");
        signaling_init_application_context(&new_conn.ctx_out.app);
    }
    if (signaling_user_api_get_uname(new_conn.ctx_out.user.uid, &new_conn.ctx_out.user)) {
        HIP_DEBUG("Could not get user name, assuming ANY USER. \n");
        signaling_init_user_context(&new_conn.ctx_out.user);
    }

    /* Set host and user authentication flags.
     * These are trivially true. */
    signaling_flag_set(&new_conn.ctx_out.flags, HOST_AUTHED);
    signaling_flag_set(&new_conn.ctx_out.flags, USER_AUTHED);

    /* Check the local context against our local policy,
     * block this connection if context is rejected */
    if (signaling_policy_engine_check_and_flag(dst_hit, &new_conn.ctx_out)) {
        new_conn.status = SIGNALING_CONN_BLOCKED;
        HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, &new_conn), -1, "Could not insert connection into cdb\n");
        signaling_cdb_print();
        return 0;
    }

    /* set local host and user to authed since we have passed policy check */
    signaling_flag_set(&new_conn.ctx_out.flags, USER_AUTHED);
    signaling_flag_set(&new_conn.ctx_out.flags, HOST_AUTHED);

    /* Since this is a new connection we have to add an entry to the scdb */
    gettimeofday(&new_conn.timestamp, NULL);
    HIP_IFEL(signaling_cdb_add(src_hit, dst_hit, &new_conn),
             -1, "Could not add entry to scdb.\n");
    signaling_cdb_print();

    HIP_DEBUG("Sending connection request to hipd.\n");
    signaling_hipfw_send_connection_request(&entry->local_hit, &entry->remote_hit, conn);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_CONN_REQUEST\n");
    hip_perf_stop_benchmark(perf_set, PERF_CONN_REQUEST);
    HIP_DEBUG("Write PERF_CONN_REQUEST, PERF_CONN_REQUEST, PERF_NETSTAT_LOOKUP, PERF_VERIFY_APPLICATION, PERF_HASH, PERF_CTX_LOOKUP, PERF_X509AC_VERIFY_CERT_CHAIN\n");
    hip_perf_write_benchmark(perf_set, PERF_CONN_REQUEST);
    hip_perf_write_benchmark(perf_set, PERF_NETSTAT_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_VERIFY_APPLICATION);
    hip_perf_write_benchmark(perf_set, PERF_CTX_LOOKUP);
    hip_perf_write_benchmark(perf_set, PERF_X509AC_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_HASH);
#endif

out_err:
    return err;
}

/**
 * Check if the packet is conntracked or not. Take the corresponding actions.
 *
 * @return verdict 1 for pass, 0 for drop.
 */
int signaling_hipfw_handle_packet(struct hip_fw_context *ctx)
{
    int                          err     = 0;
    int                          verdict = VERDICT_DEFAULT;
    int                          found   = 0;
    int                          src_port, dest_port;
    signaling_cdb_entry_t       *entry = NULL;
    struct signaling_connection *conn  = NULL;

    /* Get ports from tcp header */
    // TODO this code should not depend on payload to be TCP
    src_port  = ntohs(ctx->transport_hdr.tcp->source);
    dest_port = ntohs(ctx->transport_hdr.tcp->dest);

    HIP_DEBUG("Determining if there is a connection between \n");
    HIP_DEBUG_HIT("\tsrc", &ctx->src);
    HIP_DEBUG_HIT("\tdst", &ctx->dst);
    HIP_DEBUG("\t on ports %d/%d or if corresponding application is generally allowed.\n", src_port, dest_port);

    /* Is there a HA between the two hosts? */
    entry = signaling_cdb_entry_find(&ctx->src, &ctx->dst);
    if (entry == NULL) {
        HIP_DEBUG("No association between the two hosts, need to trigger complete BEX.\n");
        HIP_IFEL(handle_new_connection(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to handle new connection\n");
        verdict = VERDICT_DROP;
        goto out_err;
    }

    /* If there is an association, is the connection known? */
    found = signaling_cdb_entry_find_connection(src_port, dest_port, entry, &conn);
    if (found < 0) {
        HIP_DEBUG("An error occured searching the connection tracking database.\n");
        verdict = VERDICT_DEFAULT;
    } else if (found > 0) {
        switch (conn->status) {
        case SIGNALING_CONN_ALLOWED:
            HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
            verdict = VERDICT_ACCEPT;
            break;
        case SIGNALING_CONN_BLOCKED:
            HIP_DEBUG("Connection is blocked explicitly. Drop packet.\n");
            verdict = VERDICT_DROP;
            break;
        case SIGNALING_CONN_PROCESSING:
            HIP_DEBUG("Received packet for pending connection. Drop packet. (Should do some timeout stuff here.)\n");
            verdict = VERDICT_DROP;
            break;
        case SIGNALING_CONN_NEW:
        default:
            HIP_DEBUG("Invalid connection state %d. Drop packet.\n", conn->status);
            verdict = VERDICT_DROP;
            break;
        }
    } else {
        HIP_DEBUG("HA exists, but connection is new. We need to trigger a BEX UPDATE now and drop this packet.\n");
        HIP_IFEL(handle_new_connection(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to handle new connection\n");
        verdict = VERDICT_DROP;
    }

out_err:
    if (err) {
        return VERDICT_DROP;
    }
    return verdict;
}
