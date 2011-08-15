/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

/**
 * @file
 * This file implements handling of the opportunistic mode for the Host
 * Identity Protocol (HIP). Part of this functionality has been moved
 * here from the removed oppdb.c.
 *
 * @brief Implementation of the HIP opportunistic mode
 */

#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "hadb.h"
#include "hidb.h"
#include "opp_mode.h"
#include "registration.h"


/**
 * fetch an hadb entry corresponding to a pseudo HIT
 *
 * @param init_hit the local HIT of the Initiator
 * @param resp_addr the remote IP address of the Responder from
 *                  which to calculate the pseudo HIT
 * @return a host association or NULL if not found
 */
static struct hip_hadb_state *hip_opp_get_hadb_entry(const hip_hit_t *const init_hit,
                                                     const struct in6_addr *const resp_addr)
{
    hip_hit_t phit;

    HIP_DEBUG_HIT("resp_addr=", resp_addr);
    if (hip_opportunistic_ipv6_to_hit(resp_addr, &phit, HIP_HIT_TYPE_HASH100)) {
        HIP_ERROR("hip_opportunistic_ipv6_to_hit failed\n");
        return NULL;
    }
    HIP_ASSERT(hit_is_opportunistic_hit(&phit));

    return hip_hadb_find_byhits(init_hit, &phit);
}

/**
 * find a host association based on I1 or R1 message
 *
 * @param msg the I1 or R2 message
 * @param src_addr the source address of the message
 * @return the host association or NULL if not found
 */
struct hip_hadb_state *hip_opp_get_hadb_entry_i1_r1(struct hip_common *msg,
                                                    const struct in6_addr *const src_addr)
{
    hip_hdr                type  = hip_get_msg_type(msg);
    struct hip_hadb_state *entry = NULL;

    if (type == HIP_I1) {
        if (!ipv6_addr_is_null(&msg->hitr)) {
            return NULL;
        }
        hip_get_default_hit(&msg->hitr);
    } else if (type == HIP_R1) {
        entry = hip_opp_get_hadb_entry(&msg->hitr, src_addr);
    } else {
        HIP_ASSERT(0);
    }

    return entry;
}

/**
 * Process an incoming R1 packet for an opportunistic connection
 *
 * @param ctx the packet context
 * @return zero on success or negative on failure
 */
int hip_handle_opp_r1(struct hip_packet_context *ctx)
{
    struct hip_hadb_state *opp_entry = NULL;
    hip_hit_t              phit;
    int                    err = 0;

    opp_entry = ctx->hadb_entry;

    HIP_DEBUG_HIT("peer hit", &ctx->input_msg->hits);
    HIP_DEBUG_HIT("local hit", &ctx->input_msg->hitr);

    HIP_IFEL(hip_hadb_add_peer_info_complete(&ctx->input_msg->hitr,
                                             &ctx->input_msg->hits,
                                             NULL,
                                             &ctx->dst_addr,
                                             &ctx->src_addr,
                                             NULL),
             -1, "Failed to insert peer map\n");

    HIP_IFEL(!(ctx->hadb_entry = hip_hadb_find_byhits(&ctx->input_msg->hits,
                                                      &ctx->input_msg->hitr)),
             -1, "Did not find opp entry\n");

    HIP_IFEL(hip_init_us(ctx->hadb_entry, &ctx->input_msg->hitr),
             -1, "hip_init_us failed\n");
    /* old HA has state 2, new HA has state 1, so copy it */
    ctx->hadb_entry->state = opp_entry->state;
    /* For service registration routines */
    ctx->hadb_entry->local_controls = opp_entry->local_controls;
    ctx->hadb_entry->peer_controls  = opp_entry->peer_controls;

    if (hip_replace_pending_requests(opp_entry, ctx->hadb_entry) == -1) {
        HIP_DEBUG("RVS: Error moving the pending requests to a new HA");
    }

    HIP_DEBUG_HIT("peer hit", &ctx->input_msg->hits);
    HIP_DEBUG_HIT("local hit", &ctx->input_msg->hitr);

    HIP_IFEL(hip_opportunistic_ipv6_to_hit(&ctx->src_addr, &phit,
                                           HIP_HIT_TYPE_HASH100),
             -1, "pseudo hit conversion failed\n");

    hip_del_peer_info_entry(opp_entry);

out_err:
    return err;
}
