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

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "modules/signaling/lib/signaling_oslayer.h"

#include "signaling_hipfw_oslayer.h"
#include "signaling_hipfw_user_msg.h"
#include "signaling_cdb.h"
#include "signaling_policy_engine.h"

static int waiting_connections = 0;
static struct timeval new_connection_wait_timeout;

/* Init connection tracking data base */
int signaling_hipfw_oslayer_init(void) {
    if (signaling_cdb_init()) {
        HIP_ERROR("Could not init connection tracking database \n");
        return -1;
    }

    new_connection_wait_timeout.tv_sec = 0;
    new_connection_wait_timeout.tv_usec = 0;

    if (signaling_policy_engine_init_from_file("/usr/local/etc/hip/signaling_local_firewall_policy.cfg")) {
            HIP_ERROR("Could not init connection tracking database \n");
            return -1;
        }

    return 0;
}

int signaling_hipfw_oslayer_uninit(void) {
    return 0;
}

/*
 * return 1 if expired, else 0
 */
static int expired(struct timeval *start, struct timeval *timeout) {
    struct timeval now;
    uint64_t timediff;
    gettimeofday(&now, NULL);

    timediff = calc_timeval_diff(start, &now);
    HIP_DEBUG("Time passed since start %.3f ms, timeout is %.3f ms\n", timediff / 1000.0, timeout->tv_sec*1000.0);

    /* no timeout */
    if (timeout->tv_sec == 0 && timeout->tv_usec == 0) {
        return 1;
    }
    /* timeout given in seconds */
    if (timeout->tv_sec > 0 && (now.tv_sec - start->tv_sec >= timeout->tv_sec)) {
        return 1;
    }
    /* timeout given in microseconds */
    if (timeout->tv_usec > 0 && (now.tv_usec - start->tv_usec >= timeout->tv_usec)) {
        return 1;
    }
    return 0;
}

static int send_on_timeout(signaling_cdb_entry_t *entry) {
    struct slist *listentry = NULL;
    struct signaling_connection *conn = NULL;

    listentry = entry->connections;
    while(listentry) {
        if ((conn = listentry->data) && (conn->status == SIGNALING_CONN_WAITING)) {
            if (!expired(&conn->timestamp, &new_connection_wait_timeout)) {
                HIP_DEBUG("Continue to wait on connection %d until expired.\n", conn->id);
            } else {
                /* timeout has expired, send it */
                conn->status = SIGNALING_CONN_PROCESSING;
                HIP_DEBUG("Sending connection request after timeout of %d s.\n", new_connection_wait_timeout.tv_sec);
                signaling_hipfw_send_connection_request(&entry->local_hit, &entry->remote_hit, conn);
            }
        }
        listentry = listentry->next;
    }
    return 0;
}

/**
 * This function checks whether there are connections in our outgoing queue,
 * which we should send out because the timeout is reached.
 *
 * @return      0 on success, -1 on internal errors
 */
static void check_timeout_wait_for_new_connections(void) {
    signaling_cdb_apply_func(&send_on_timeout);
}

static int handle_new_connection(struct in6_addr *src_hit, struct in6_addr *dst_hit,
                                 uint16_t src_port, uint16_t dst_port) {
    int err = 0;
    struct signaling_connection *conn = NULL;
    struct signaling_connection new_conn;
    int pos = 0;

    /* Find if there is a waiting connection for this source and destination application. */
    if ((conn = signaling_cdb_entry_find_connection_by_dst_port(src_hit, dst_hit, dst_port))) {
        if (conn->status == SIGNALING_CONN_WAITING) {
            pos = signaling_connection_add_port_pair(src_port, dst_port, conn);
            if (pos < 0 || pos == SIGNALING_MAX_SOCKETS - 1) {
                if(!signaling_hipfw_send_connection_request(src_hit, dst_hit, conn)) {
                    waiting_connections--;
                    return 0;
                } else {
                    HIP_ERROR("Failed to send connection request to HIPD for connection:\n");
                    signaling_connection_print(conn, "\t");
                    return -1;
                }
            } else {
                HIP_DEBUG("Queued new connection (this is the %d. connection for the same application), "
                          "waiting for more until timeout.\n", pos);
                check_timeout_wait_for_new_connections();
                return 0;
            }
        }
    }

    /* We have no waiting contexts. So build the local connection context and queue it. */
    HIP_IFEL(signaling_init_connection(&new_conn),
             -1, "Could not init connection context\n");
    new_conn.status               = SIGNALING_CONN_WAITING;
    new_conn.id                   = signaling_cdb_get_next_connection_id();
    new_conn.side                 = INITIATOR;
    new_conn.sockets[0].src_port  = src_port;
    new_conn.sockets[0].dst_port  = dst_port;

    /* Look up the local connection context */
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
    waiting_connections++;

out_err:
    return err;
}

/*
 * Returns a verdict 1 for pass, 0 for drop.
 */
int signaling_hipfw_conntrack(hip_fw_context_t *ctx) {
    int err = 0;
    int verdict = VERDICT_DEFAULT;
    int found = 0;
    int src_port, dest_port;
    signaling_cdb_entry_t *entry = NULL;
    struct signaling_connection *conn = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_NEW_CONN\n");
    hip_perf_start_benchmark(perf_set, PERF_NEW_CONN);
#endif

    /* Get ports from tcp header */
    src_port    = ntohs(ctx->transport_hdr.tcp->source);
    dest_port   = ntohs(ctx->transport_hdr.tcp->dest);

    HIP_DEBUG("Determining if there is a connection between \n");
    HIP_DEBUG_HIT("\tsrc", &ctx->src);
    HIP_DEBUG_HIT("\tdst", &ctx->dst);
    HIP_DEBUG("\t on ports %d/%d or if corresponding application is generally allowed.\n", src_port, dest_port);

    /* Is there a HA between the two hosts? */
    entry = signaling_cdb_entry_find(&ctx->src, &ctx->dst);
    if(entry == NULL) {
        HIP_DEBUG("No association between the two hosts, need to trigger complete BEX.\n");
        HIP_IFEL(handle_new_connection(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to handle new connection\n");
        verdict = VERDICT_DROP;
        goto out_err;
    }

    /* If there is an association, is the connection known? */
    found = signaling_cdb_entry_find_connection(src_port, dest_port, entry, &conn);
    if(found < 0) {
        HIP_DEBUG("An error occured searching the connection tracking database.\n");
        verdict = VERDICT_DEFAULT;
    } else if(found > 0) {
        switch (conn->status) {
        case SIGNALING_CONN_ALLOWED:
            HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
            verdict = VERDICT_ACCEPT;
            break;
        case SIGNALING_CONN_BLOCKED:
            HIP_DEBUG("Connection is blocked explicitly. Drop packet.\n");
            verdict = VERDICT_DROP;
            break;
        case SIGNALING_CONN_WAITING:
            HIP_DEBUG("Connection is on wait, but will be established later. Drop packet.\n");
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

/*
 * This function will be called after each firewall cycle,
 * i.e. either after the select timeout is reached
 * or after at most one message from each socket handle has been processed.
 * Register all functions that should be called periodically here.
 */
int signaling_firewall_maintenance(void) {

    /* Check if we need to send out queued connection requests. */
    check_timeout_wait_for_new_connections();

    return 0;
}

