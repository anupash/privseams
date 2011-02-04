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
#include "modules/update/hipd/update.h"
#include "midauth_builder.h"
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
static int hip_add_puzzle_solution_m(UNUSED const uint8_t packet_type,
                                     UNUSED const uint32_t ha_state,
                                     struct hip_packet_context *ctx)
{
    const struct hip_challenge_request *pz;
    struct puzzle_hash_input            tmp_puzzle;
    int                                 err = 0;
    uint8_t                             digest[HIP_AH_SHA_LEN];

    pz = hip_get_param(ctx->input_msg, HIP_PARAM_CHALLENGE_REQUEST);
    while (pz) {
        if (hip_get_param_type(pz) != HIP_PARAM_CHALLENGE_REQUEST) {
            break;
        }

        HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, pz->opaque, 24, digest) < 0,
                 -1, "Building of SHA1 Random seed I failed\n");

        memcpy(tmp_puzzle.puzzle,
               &digest[HIP_AH_SHA_LEN - PUZZLE_LENGTH],
               PUZZLE_LENGTH);
        tmp_puzzle.initiator_hit = ctx->hadb_entry->hit_our;
        tmp_puzzle.responder_hit = ctx->hadb_entry->hit_peer;

        HIP_IFEL(hip_solve_puzzle(&tmp_puzzle, pz->K),
                 -EINVAL,
                 "Solving of puzzle failed\n");

        HIP_IFEL(hip_build_param_challenge_response(ctx->output_msg,
                                                    pz, tmp_puzzle.solution) < 0,
                 -1,
                 "Error while creating solution_m reply parameter\n");

        pz = (const struct hip_challenge_request *)
             hip_get_next_param(ctx->input_msg,
                                (const struct hip_tlv_common *) pz);
    }

out_err:
    return err;
}

static int hip_midauth_add_puzzle_solution_m_update(UNUSED const uint8_t packet_type,
                                                    UNUSED const uint32_t ha_state,
                                                    struct hip_packet_context *ctx)
{
    enum update_types update_type = UNKNOWN_UPDATE_PACKET;
    int               err         = 0;

    update_type = hip_classify_update_type(ctx->input_msg);

    if (update_type == SECOND_UPDATE_PACKET ||
        update_type == THIRD_UPDATE_PACKET) {
        /* TODO: no caching is done for PUZZLE_M parameters. This may be
         * a DOS attack vector. */
        HIP_IFEL(hip_add_puzzle_solution_m(0, 0, ctx),
                 -1, "Building of Challenge_Response failed\n");
    }

out_err:
    return err;
}

static int hip_midauth_add_host_id_update(UNUSED const uint8_t packet_type,
                                          UNUSED const uint32_t ha_state,
                                          struct hip_packet_context *ctx)
{
    enum update_types     update_type   = UNKNOWN_UPDATE_PACKET;
    struct local_host_id *host_id_entry = NULL;
    int                   err           = 0;

    update_type = hip_classify_update_type(ctx->input_msg);

    if (update_type == SECOND_UPDATE_PACKET ||
        update_type == THIRD_UPDATE_PACKET) {
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

    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_ECHO_REQUEST_M,
                                          "HIP_PARAM_ECHO_REQUEST_M"),
             -1, "failed to register parameter type\n");
    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_ECHO_RESPONSE_M,
                                          "HIP_PARAM_ECHO_RESPONSE_M"),
             -1, "failed to register parameter type\n");
    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_CHALLENGE_REQUEST,
                                          "HIP_PARAM_CHALLENGE_REQUEST"),
             -1, "failed to register parameter type\n");
    HIP_IFEL(lmod_register_parameter_type(HIP_PARAM_CHALLENGE_RESPONSE,
                                          "HIP_PARAM_CHALLENGE_RESPONSE"),
             -1, "failed to register parameter type\n");

    HIP_IFEL(hip_register_handle_function(HIP_R2,
                                          HIP_STATE_R2_SENT,
                                          &hip_add_puzzle_solution_m,
                                          40000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_midauth_add_host_id_update,
                                          40000),
             -1, "Error on registering UPDATE handle function.\n");
    HIP_IFEL(hip_register_handle_function(HIP_UPDATE,
                                          HIP_STATE_ESTABLISHED,
                                          &hip_midauth_add_puzzle_solution_m_update,
                                          40001),
             -1, "Error on registering UPDATE handle function.\n");

out_err:
    return err;
}
