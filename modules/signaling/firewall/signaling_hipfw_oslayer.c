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

#include "signaling_hipfw_oslayer.h"
#include "signaling_cdb.h"

/* Init connection tracking data base */
int signaling_hipfw_oslayer_init(void) {
    int err = 0;
    err = signaling_cdb_init();

    return err;
}

/* Tell the HIPD to do a BEX update on this new connection. */
int signaling_hipfw_trigger_bex_update(hip_fw_context_t *ctx) {
    int err = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    /* Allocate the message */
    struct hip_common *msg = NULL;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_TRIGGER_NEW_CONNECTION, 0),
             -1, "build hdr failed\n");

    /* Include Hits */
    HIP_IFEL(hip_build_param_contents(msg, &ctx->src,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");

    HIP_IFEL(hip_build_param_contents(msg, &ctx->dst,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (dst hit) failed\n");

    /* Include port numbers. */
    src_port=ntohs(ctx->transport_hdr.tcp->source);
    dst_port=ntohs(ctx->transport_hdr.tcp->dest);
    signaling_build_param_portinfo(msg, src_port, dst_port);

    /* Print and send message */
    HIP_DUMP_MSG(msg);
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

out_err:
    return err;
}

/*
 * Returns a verdict 1 for pass, 0 for drop.
 */
int signaling_hipfw_conntrack(hip_fw_context_t *ctx) {

    int verdict = VERDICT_DEFAULT;
    int found = 0;
    int src_port, dest_port;
    signaling_cdb_entry_t *entry;


    /* Get ports from tcp header */
    src_port = ntohs(ctx->transport_hdr.tcp->source);
    dest_port = ntohs(ctx->transport_hdr.tcp->dest);

    HIP_DEBUG("Determining if there is a connection between \n");
    HIP_DEBUG_HIT("\tsrc", &ctx->src);
    HIP_DEBUG_HIT("\tdst", &ctx->dst);
    HIP_DEBUG("\t on ports %d/%d or if corresponding application is generally allowed.\n", src_port, dest_port);

    entry = signaling_cdb_entry_find(&ctx->src, &ctx->dst);
    if(entry == NULL) {
        HIP_DEBUG("No association between the two hosts, need to trigger complete BEX.\n");
        verdict = VERDICT_ACCEPT;
        /* Let packet proceed because BEX will be triggered by userspace ipsec */
        goto out_err;
    }

    /* If there is an association search the connection. */
    found = signaling_cdb_entry_find_ports(src_port, dest_port, entry);
    if(found < 0) {
        HIP_DEBUG("An error occured searching the connection tracking database.\n");
        verdict = VERDICT_DEFAULT;
    } else if(found > 0) {
        HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
        verdict = VERDICT_ACCEPT;
    } else {
        HIP_DEBUG("HA exists, but connection is new. We need to trigger a BEX UPDATE now and drop this packet.\n");
        signaling_hipfw_trigger_bex_update(ctx);
        verdict = VERDICT_DROP;
    }

out_err:
    return verdict;
}

