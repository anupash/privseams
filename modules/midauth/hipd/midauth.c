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
 * solve a midauth puzzle which is essentially a normal HIP cookie
 * with some extra whipped cream on the top
 *
 * NEEDED in I2 and R2
 *
 * @param out the received R1 message
 * @param in an I2 message where the solution will be written
 * @return zero on success and negative on error
 * @see <a
 * href="http://tools.ietf.org/id/draft-heer-hip-middle-auth">Heer et
 * al, End-Host Authentication for HIP Middleboxes, Internet draft,
 * work in progress, February 2009</a>
 */
static int hip_handle_challenge_request_param(UNUSED const uint8_t packet_type,
                                              UNUSED const uint32_t ha_state,
                                              struct hip_packet_context *ctx)
{
    const struct hip_challenge_request *challenge_request = NULL;
    unsigned char                       sha_digest[SHA_DIGEST_LENGTH];
    struct puzzle_hash_input            tmp_puzzle;
    int                                 opaque_length = 0;
    int                                 err           = 0;

    challenge_request = hip_get_param(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST);

    // each on-path middlebox may add a challenge on its own
    while (challenge_request) {
        opaque_length = hip_get_param_contents_len(challenge_request) -
                        2 * sizeof(uint8_t);

        // the hashed opaque field is used as puzzle seed
        HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1,
                                  challenge_request->opaque,
                                  opaque_length,
                                  sha_digest),
                 -1, "Building of SHA1 Random seed I failed\n");

        memcpy(tmp_puzzle.puzzle,
               &sha_digest[SHA_DIGEST_LENGTH - PUZZLE_LENGTH],
               PUZZLE_LENGTH);
        tmp_puzzle.initiator_hit = ctx->input_msg->hitr;
        tmp_puzzle.responder_hit = ctx->input_msg->hits;

        HIP_IFEL(hip_solve_puzzle(&tmp_puzzle, challenge_request->K),
                 -EINVAL, "Solving of middlebox challenge failed\n");

        HIP_IFEL(hip_build_param_challenge_response(ctx->output_msg,
                                                    challenge_request,
                                                    tmp_puzzle.solution) < 0,
                 -1,
                 "Error while creating solution_m reply parameter\n");

        // process next challenge parameter, if available
        challenge_request = (const struct hip_challenge_request *)
                            hip_get_next_param(ctx->input_msg,
                                               (const struct hip_tlv_common *) challenge_request);

        if (hip_get_param_type(challenge_request) != HIP_PARAM_CHALLENGE_REQUEST) {
            break;
        }
    }

out_err:
    return err;
}

static int hip_add_host_id_param_update(UNUSED const uint8_t packet_type,
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
                                          &hip_handle_challenge_request_param,
                                          20550),
             -1, "Error on registering MIDAUTH handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_I2,
                                          HIP_STATE_I2_SENT,
                                          &hip_handle_challenge_request_param,
                                          20550),
             -1, "Error on registering MIDAUTH handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_handle_challenge_request_param,
                                          20550),
             -1, "Error on registering MIDAUTH handle function.\n");

    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_add_host_id_param_update,
                                          20750),
             -1, "Error on registering MIDAUTH handle function.\n");


out_err:
    return err;
}
