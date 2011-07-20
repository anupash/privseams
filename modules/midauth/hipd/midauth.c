/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * This file contains the implementation for the middlebox authentication
 * extension.
 *
 * @author Rene Hummen
 */

#include <errno.h>
#include <string.h>

#include "hipd/hidb.h"
#include "hipd/pkt_handling.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/modularization.h"
#include "lib/core/protodefs.h"
#include "lib/core/solve.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "modules/update/hipd/update.h"
#include "midauth.h"


/**
 * Handle the CHALLENGE_REQUEST parameter.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *             the packet handling (received message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database).
 *
 * @return zero challenge was processed correctly or no challenge was attached
 *         to the packet, negative value otherwise
 */
static int handle_challenge_request_param(UNUSED const uint8_t packet_type,
                                          UNUSED const uint32_t ha_state,
                                          struct hip_packet_context *ctx)
{
    int                                 err     = 0;
    const struct hip_challenge_request *request = NULL;

    request = hip_get_param(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST);
    if (!request) {
        return 0;
    }

    // each on-path middlebox may add a challenge on its own
    do {
        struct puzzle_hash_input tmp_puzzle;
        const uint8_t            len = hip_challenge_request_opaque_len(request);

        HIP_IFEL(hip_midauth_puzzle_seed(request->opaque, len, tmp_puzzle.puzzle),
                 -1, "failed to derive midauth puzzle\n");
        tmp_puzzle.initiator_hit = ctx->input_msg->hitr;
        tmp_puzzle.responder_hit = ctx->input_msg->hits;

        HIP_IFEL(hip_solve_puzzle(&tmp_puzzle, request->K),
                 -EINVAL, "Solving of middlebox challenge failed\n");

        HIP_IFEL(hip_build_param_challenge_response(ctx->output_msg,
                                                    request, tmp_puzzle.solution) < 0,
                 -1,
                 "Error while creating CHALLENGE_RESPONSE parameter\n");

        // process next challenge parameter, if available
        request = (const struct hip_challenge_request *)
                  hip_get_next_param(ctx->input_msg, &request->tlv);
    } while (request && hip_get_param_type(request) == HIP_PARAM_CHALLENGE_REQUEST);

out_err:
    return err;
}

/**
 * Add a HOST_ID parameter corresponding to the local HIT of the association to
 * an UPDATE packet.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param ctx Pointer to the packet context, containing all information for
 *             the packet handling (received message, source and destination
 *             address, the ports and the corresponding entry from the host
 *             association database).
 *
 * @return zero on success, negative value otherwise
 */
static int add_host_id_param_update(UNUSED const uint8_t packet_type,
                                    UNUSED const uint32_t ha_state,
                                    struct hip_packet_context *ctx)
{
    const struct hip_challenge_request *challenge_request = NULL;
    struct local_host_id               *host_id_entry     = NULL;
    int                                 err               = 0;

    challenge_request = hip_get_param(ctx->input_msg,
                                      HIP_PARAM_CHALLENGE_REQUEST);

    // add HOST_ID to packets containing a CHALLENGE_RESPONSE
    if (challenge_request) {
        HIP_IFEL(!(host_id_entry = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID,
                                                                        &ctx->input_msg->hitr,
                                                                        HIP_ANY_ALGO,
                                                                        -1)),
                 -1,
                 "Unknown HIT\n");

        HIP_IFEL(hip_build_param_host_id(ctx->output_msg,
                                         &host_id_entry->host_id),
                 -1,
                 "Building of host id failed\n");
    }

out_err:
    return err;
}

/**
 * Initialization function for the midauth module.
 *
 * @return zero on success, negative value otherwise
 */
int hip_midauth_init(void)
{
    int err = 0;

    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_CHALLENGE_REQUEST,
                                          "HIP_PARAM_CHALLENGE_REQUEST"),
             -1, "failed to register parameter type\n");
    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_CHALLENGE_RESPONSE,
                                          "HIP_PARAM_CHALLENGE_RESPONSE"),
             -1, "failed to register parameter type\n");

    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_I1_SENT,
                                          &handle_challenge_request_param,
                                          32500),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_I2_SENT,
                                          &handle_challenge_request_param,
                                          32500),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_CLOSING,
                                          &handle_challenge_request_param,
                                          32500),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_R1,
                                          HIP_STATE_CLOSED,
                                          &handle_challenge_request_param,
                                          32500),
             -1, "Error on registering MIDAUTH handle function.\n");

    //
    // we hook on every occasion that causes an R2 to get sent.
    // R2 packet is first allocated at 40000, so we use a higher
    // base priority here.
    //
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_UNASSOCIATED,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_I1_SENT,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_I2_SENT,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_R2_SENT,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_ESTABLISHED,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_CLOSING,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_CLOSED,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_NONE,
                                          &handle_challenge_request_param,
                                          40322),
             -1, "Error on registering MIDAUTH handle function.\n");

    //
    // Priority computed the same as above, but UPDATE response is sent at
    // priority 30000 already (checking is 20000) and we must add our
    // CHALLENGE_REQUEST verification inbetween, hence a lower base priority.
    //
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &handle_challenge_request_param,
                                          20322),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &handle_challenge_request_param,
                                          20322),
             -1, "Error on registering MIDAUTH handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_R2_SENT,
                                          &add_host_id_param_update,
                                          20750),
             -1, "Error on registering MIDAUTH handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &add_host_id_param_update,
                                          20750),
             -1, "Error on registering MIDAUTH handle function.\n");

out_err:
    return err;
}
