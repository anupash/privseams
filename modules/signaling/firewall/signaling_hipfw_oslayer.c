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

/* Init connection tracking data base */
int signaling_hipfw_oslayer_init(void) {
    int err = 0;
    err = signaling_cdb_init();

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

        HIP_IFEL(signaling_hipfw_send_connection_request_by_ports(&ctx->src, &ctx->dst, src_port, dest_port),
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
            HIP_DEBUG("Invalid connection state %d. Drop packet.\n", app_ctx->connection_status);
            verdict = VERDICT_DROP;
        }
    } else {
        HIP_DEBUG("HA exists, but connection is new. We need to trigger a BEX UPDATE now and drop this packet.\n");
        HIP_IFEL(signaling_hipfw_send_connection_request_by_ports(&ctx->src, &ctx->dst, src_port, dest_port),
                 -1, "Failed to trigger new connection\n");
        verdict = VERDICT_DROP;
    }

out_err:
    if (err) {
        return VERDICT_DROP;
    }
    return verdict;
}

