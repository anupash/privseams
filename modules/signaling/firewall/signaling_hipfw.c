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

#include "firewall/hslist.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"

#include "signaling_policy_engine.h"
#include "signaling_hipfw.h"

/* Set from libconfig.
 * If set to zero, the firewall does only static filtering on basis of the predefined policy.
 * If set to one, the firewall saves the connection contexts it sees to the conntracking table,
 * for later use. */
int do_conntrack = 0;

/*
 * Add all information about application and user to the connection tracking table.
 *
 * @note This function does not return a verdict. The caller has the responsibility to decide
 *       what to do, when this function fails.
 *
 * @return 0 on success, negative on error
 */
static int signaling_hipfw_conntrack(struct tuple * const tuple,
                                     struct signaling_connection_context * const conn_ctx)
{
    int err = 0;

    HIP_IFEL(!tuple,
             -1, "Connection tracking tuple is NULL \n");

    if(!do_conntrack) {
        return 0;
    }

    tuple->connection_contexts = append_to_slist(tuple->connection_contexts, conn_ctx);

out_err:
    return err;
}

/*
 * Handles an I2 packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_i2(const struct hip_common *common, struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
    struct signaling_connection_context *conn_ctx;
    int verdict = 1; // ALLOW
    int err;

    HIP_IFEL(!(conn_ctx = malloc(sizeof(struct signaling_connection_context))),
             -1, "Could not allocate new connection context\n");
    HIP_IFEL(signaling_init_connection_context_from_msg(conn_ctx, common),
             -1, "Could not init new connection context from message\n");

    HIP_DEBUG("Deciding on following connection context: \n");
    signaling_connection_context_print(conn_ctx, "");

    /* Get a verdict on given hosts, user and application from the policy engine */
    verdict = signaling_policy_check(tuple, conn_ctx);

    /* If we allow the connection, save it in conntracking table */
    if (verdict) {
        if (signaling_hipfw_conntrack(tuple, conn_ctx)) {
            // for now we let pass, if we were very restrictive,
            // we would spead verdict = DROP here
            HIP_DEBUG("Couldn't conntrack connection context\n");
        }
    }

out_err:
    if (err) {
        free(conn_ctx);
        verdict = 0;
    }
    return verdict;
}

/*
 * Handles an R2 packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_r2(const struct hip_common *common, struct tuple *tuple, const hip_fw_context_t *ctx)
{
    return signaling_hipfw_handle_i2(common, tuple, ctx);
}

/*
 * Handles an UPDATE packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_update(UNUSED const struct hip_common *common, UNUSED struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
    HIP_DEBUG("WARNING: unimplemented function \n");
    return 1;
}

