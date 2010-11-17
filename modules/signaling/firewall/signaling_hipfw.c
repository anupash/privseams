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

#include "signaling_hipfw.h"
#include "signaling_cdb.h"

/* Init connection tracking data base */
int signaling_hipfw_init(void) {
    int err = 0;
    err = signaling_cdb_init();

    return err;
}
/*
 * Print all application information included in the packet.
 */
int signaling_hipfw_handle_appinfo(const struct hip_common *common, UNUSED struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
	int err = 1;
	UNUSED const struct signaling_param_appinfo *appinfo = NULL;

	/* Get the parameter */
	HIP_IFEL(!(appinfo = (const struct signaling_param_appinfo *) hip_get_param(common, HIP_PARAM_SIGNALING_APPINFO)),
	        -1, "No application info parameter found in the message.\n");

	/* Print out contents */
	signaling_param_appinfo_print(appinfo);

out_err:
	return err;
}

/* Tell the HIPD to do a BEX update on this new connection. */
int signaling_hipfw_trigger_bex_update(hip_fw_context_t *ctx) {
    int err = 0;
    uint16_t src_port, dst_port;

    struct hip_common *msg = NULL;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_TRIGGER_BEX_UPDATE, 0),
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

    /* Include port numbers in bex trigger. port numbers are used by signaling module */
    src_port=ntohs(ctx->transport_hdr.tcp->source);
    dst_port=ntohs(ctx->transport_hdr.tcp->dest);

    signaling_build_param_portinfo(msg, src_port, dst_port);

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

out_err:
    return err;
}

/*
 * Returns a verdict 1 for pass, 0 for drop.
 */
int signaling_hipfw_conntrack(hip_fw_context_t *ctx) {

    int err = 1, found = 0;
    int src_port, dest_port;
    signaling_cdb_entry_t *entry;


    /* Get ports from tcp header */
    src_port = ntohs(ctx->transport_hdr.tcp->source);
    dest_port = ntohs(ctx->transport_hdr.tcp->dest);

    HIP_DEBUG("Determining if there is a connection between \n");
    HIP_DEBUG_HIT("\tsrc", &ctx->src);
    HIP_DEBUG_HIT("\tdst", &ctx->dst);
    HIP_DEBUG("\t on ports %d/%d or if corresponding application is allowed.\n", src_port, dest_port);

    entry = signaling_cdb_entry_find(&ctx->src, &ctx->dst);
    if(entry == NULL) {
        HIP_DEBUG("No association between the two hosts, need to trigger complete BEX.\n");
        /* Let packet proceed because BEX will be triggered by userspace ipsec */
        err = 1;
        goto out_err;
    }

    found = signaling_cdb_ports_find(src_port, dest_port, entry);
    if(found) {
        HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
        err = 1;
    } else {
        HIP_DEBUG("HA exists, but connection is new. We need to trigger a BEX UPDATE now and drop this packet.\n");
        signaling_hipfw_trigger_bex_update(ctx);
        err = 0;
    }

out_err:
    return err;
}

