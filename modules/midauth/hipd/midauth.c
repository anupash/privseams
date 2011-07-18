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
int hip_solve_puzzle_m(struct hip_common *out, struct hip_common *in)
{
    const struct hip_challenge_request *pz;
    struct hip_puzzle                   tmp;
    uint64_t                            solution;
    int                                 err = 0;
    uint8_t                             digist[HIP_AH_SHA_LEN];

    pz = hip_get_param(in, HIP_PARAM_CHALLENGE_REQUEST);
    while (pz) {
        if (hip_get_param_type(pz) != HIP_PARAM_CHALLENGE_REQUEST) {
            break;
        }

        HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, pz->opaque, 24, digist) < 0,
                 -1, "Building of SHA1 Random seed I failed\n");
        tmp.type      = pz->type;
        tmp.length    = pz->length;
        tmp.K         = pz->K;
        tmp.lifetime  = pz->lifetime;
        tmp.opaque[0] = tmp.opaque[1] = 0;
        tmp.I         = *digist & 0x40; //truncate I to 8 byte length

        HIP_IFEL((solution = hip_solve_puzzle(&tmp, in, HIP_SOLVE_PUZZLE)) == 0,
                 -EINVAL,
                 "Solving of puzzle failed\n");

        HIP_IFEL(hip_build_param_challenge_response(out, pz, ntoh64(solution)) < 0,
                 -1,
                 "Error while creating solution_m reply parameter\n");
        pz = (const struct hip_challenge_request *)
             hip_get_next_param(in, (const struct hip_tlv_common *) pz);
    }

out_err:
    return err;
}

int hip_midauth_puzzle_update(void)
{
    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (received_update_packet && type == HIP_UPDATE_ECHO_REQUEST) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet), -1,
                 "Building of Challenge_Response failed\n");
    } else {
        HIP_DEBUG("msg is NULL, midauth parameters not included in reply\n");
    }

    /* TODO: no caching is done for PUZZLE_M parameters. This may be
     * a DOS attack vector.
     */
    if (type == HIP_UPDATE_ECHO_RESPONSE) {
        HIP_IFEL(hip_solve_puzzle_m(update_packet_to_send, received_update_packet), -1,
                 "Building of Challenge_Response failed\n");
    }
}

void hip_midauth_init(void)
{
    /* register parameter types (builder:hip_check_network_param_type())
     *  HIP_PARAM_ECHO_REQUEST_M,
     *  HIP_PARAM_ECHO_RESPONSE_M,
     *  HIP_PARAM_CHALLENGE_REQUEST,
     *  HIP_PARAM_CHALLENGE_RESPONSE
     */
}
