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
#include "signaling_cdb.h"

/* Init connection tracking data base */
int signaling_hipfw_oslayer_init(void) {
    int err = 0;
    err = signaling_cdb_init();

    return err;
}

/**
 * Tell the HIPD that there is a new connection attempt.
 * The HIPD then has to decide whether to effect a BEX or UPDATE.
 *
 * @param ctx the connection context
 *
 * @return 0 on success, negative otherwise
 * */
static int signaling_hipfw_send_trigger_new_connection(hip_hit_t *src_hit,
                                                       hip_hit_t *dst_hit,
                                                       struct signaling_connection_context *ctx) {
    int err = 0;

    /* Allocate the message */
    struct hip_common *msg = NULL;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* Build the message header and parameter */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_REQUEST_CONNECTION, 0),
             -1, "build hdr failed\n");

    HIP_IFEL(hip_build_param_contents(msg, dst_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");

    HIP_IFEL(hip_build_param_contents(msg, src_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (src hit) failed\n");

    HIP_IFEL(signaling_build_param_application_context(msg, ctx),
             -1, "build param application context failed\n");

    /* Print and send message */
    HIP_DUMP_MSG(msg);
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

out_err:
    return err;
}

/**
 * Gather all information about a new connection.
 */
static int signaling_hipfw_trigger_new_connection(hip_hit_t *src_hit, hip_hit_t *dst_hit,
                                                  uint16_t src_port, uint16_t dst_port) {
    int err = 0;
    struct signaling_connection_context *new_ctx = NULL;

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
    signaling_cdb_print();

    /* Notify the HIPD */
    HIP_IFEL(signaling_hipfw_send_trigger_new_connection(src_hit, dst_hit, new_ctx),
             -1, "Could not notify HIPD of new connection \n");

out_err:
    if (err) {
        free(new_ctx);
    }
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
    signaling_cdb_entry_t *entry;
    struct signaling_connection_context *app_ctx;


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
        HIP_IFEL(signaling_hipfw_trigger_new_connection(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to trigger new connection\n");
        verdict = VERDICT_DROP;
        goto out_err;
    }

    /* If there is an association, is the connection known? */
    found = signaling_cdb_entry_find_connection(src_port, dest_port, entry, &app_ctx);
    if(found < 0) {
        HIP_DEBUG("An error occured searching the connection tracking database.\n");
        verdict = VERDICT_DEFAULT;
    } else if(found > 0) {
        switch (app_ctx->connection_status) {
        case SIGNALING_CONN_ALLOWED:
            HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
            verdict = VERDICT_ACCEPT;
            break;
        case SIGNALING_CONN_BLOCKED:
            HIP_DEBUG("Connection is blocked explicitly. Drop packet.\n");
            verdict = VERDICT_DROP;
            break;
        case SIGNALING_CONN_PENDING:
            HIP_DEBUG("Received packet for pending connection. Drop packet. (Should do some timeout stuff here.)\n");
            verdict = VERDICT_DROP;
            break;
        case SIGNALING_CONN_NEW:
        default:
            HIP_DEBUG("Invalid connection state %d. Drop packet.\n", app_ctx->connection_status);
            verdict = VERDICT_DROP;
        }
    } else {
        HIP_DEBUG("HA exists, but connection is new. We need to trigger a BEX UPDATE now and drop this packet.\n");
        HIP_IFEL(signaling_hipfw_trigger_new_connection(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to trigger new connection\n");
        verdict = VERDICT_DROP;
    }

out_err:
    if (err) {
        return VERDICT_DEFAULT;
    }
    return verdict;
}

