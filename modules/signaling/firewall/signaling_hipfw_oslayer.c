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
 * @author Anupam Ashish <anupam.ashish@rwth-aachen.de>
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
#include "lib/core/prefix.h"
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
    signaling_cdb_init();

    // TODO can this be removed?
    if (signaling_policy_engine_init_from_file(HIPFW_SIGNALING_CONF_FILE)) {
        HIP_ERROR("Could not init connection tracking database \n");
        return -1;
    }

    return 0;
}

void signaling_hipfw_oslayer_uninit(void)
{
    signaling_cdb_uninit();
}

static int handle_new_connection(const struct hip_fw_context *const ctx,
                                 const uint16_t src_port,
                                 const uint16_t dst_port)
{
    HIP_ASSERT(ipv6_addr_is_hit(&ctx->src));
    HIP_ASSERT(ipv6_addr_is_hit(&ctx->dst));

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_NEW_CONN, PERF_NEW_UPDATE_CONN, PERF_CONN_REQUEST\n");
    hip_perf_start_benchmark(perf_set, PERF_NEW_CONN);
    hip_perf_start_benchmark(perf_set, PERF_NEW_UPDATE_CONN);
    hip_perf_start_benchmark(perf_set, PERF_CONN_REQUEST);
#endif

    /* Since this is a new connection we have to add an entry to the scdb */
    if (signaling_cdb_add_connection(ctx->src, ctx->dst,
                                     src_port, dst_port,
                                     SIGNALING_CONN_PROCESSING)) {
        HIP_ERROR("Could not add entry to scdb.\n");
        return -1;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    hip_perf_start_benchmark(perf_set, PERF_CONN_REQUEST);
#endif

    HIP_DEBUG("Sending connection request to hipd.\n");
    signaling_hipfw_send_connection_request(ctx->src, ctx->dst,
                                            htons(src_port), htons(dst_port));


#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_CONN_REQUEST\n");
    hip_perf_stop_benchmark(perf_set, PERF_CONN_REQUEST);
    HIP_DEBUG("Write PERF_CONN_REQUEST\n");
    hip_perf_write_benchmark(perf_set, PERF_CONN_REQUEST);
#endif

    return 0;
}

/**
 * Check if the packet is conntracked or not. Take the corresponding actions.
 *
 * @return verdict 1 for pass, 0 for drop.
 */
int signaling_hipfw_handle_packet(struct hip_fw_context *ctx)
{
    uint16_t                          src_port, dest_port;
    const struct signaling_cdb_entry *entry = NULL;

    /* Get ports from tcp header */
    // TODO this code should not depend on payload to be TCP
    src_port  = ntohs(ctx->transport_hdr.tcp->source);
    dest_port = ntohs(ctx->transport_hdr.tcp->dest);

    HIP_DEBUG("Determining if there is a connection between \n");
    HIP_DEBUG_HIT("\tsrc", &ctx->src);
    HIP_DEBUG_HIT("\tdst", &ctx->dst);
    HIP_DEBUG("\t on ports %d/%d or if corresponding application is generally allowed.\n", src_port, dest_port);

    /* Do we know this connection already? */
    entry = signaling_cdb_get_connection(ctx->src, ctx->dst, src_port, dest_port);
    if (entry == NULL) {
        HIP_DEBUG("Unknown connection, need to tell hipd.\n");
        if (handle_new_connection(ctx, src_port, dest_port)) {
            HIP_ERROR("Failed to handle new connection\n");
        }
        return VERDICT_DROP;
    }

    /* If we reach this point, we know the connection. So what is the status? */
    switch (entry->status) {
    case SIGNALING_CONN_ALLOWED:
        HIP_DEBUG("Packet is allowed, if kernelspace ipsec was running, setup exception rule in iptables now.\n");
        return VERDICT_ACCEPT;
        break;
    case SIGNALING_CONN_BLOCKED:
        HIP_DEBUG("Connection is blocked explicitly. Drop packet.\n");
        return VERDICT_DROP;
        break;
    case SIGNALING_CONN_PROCESSING:
        HIP_DEBUG("Received packet for pending connection. Drop packet. (Should do some timeout stuff here.)\n");
        return VERDICT_DROP;
        break;
    default:
        HIP_DEBUG("Invalid connection state %d. Drop packet.\n",
                  entry->status);
        return VERDICT_DROP;
        break;
    }
}
