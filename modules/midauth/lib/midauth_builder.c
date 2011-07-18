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
 * This file contains parameter handling functionality for the middlebox
 * authentication extension.
 *
 * @author Rene Hummen
 * @author Christof Mroz <christof.mroz@rwth-aachen.de>
 */

#include <string.h>

#include "lib/core/ife.h"
#include "modules/midauth/hipd/midauth.h"
#include "midauth_builder.h"

void hip_set_param_challenge_request(struct hip_challenge_request *const request,
                                        const uint8_t difficulty,
                                        const uint8_t lifetime,
                                        const uint8_t *const opaque,
                                        const uint8_t opaque_len)
{
    HIP_ASSERT(request);
    HIP_ASSERT(difficulty <= 8);
    HIP_ASSERT(opaque);

    static const size_t min_length = sizeof(*request)
                                     - sizeof(request->tlv)
                                     - sizeof(request->opaque);

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len(&request->tlv, min_length + opaque_len);
    hip_set_param_type(&request->tlv, HIP_PARAM_CHALLENGE_REQUEST);

    /* only the random_j_k is in host byte order */
    request->K        = difficulty;
    request->lifetime = lifetime;
    memcpy(&request->opaque, opaque, opaque_len);
}

/**
 * Build and append a HIP challenge_request to the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the puzzle_m is to be appended
 * @param val_K the K value for the puzzle_m
 * @param lifetime lifetime field of the puzzle_m
 * @param opaque the opaque data filed of the puzzle_m
 * @param opaque_len the length uf the opaque data field
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_request(struct hip_common *msg,
                                      uint8_t val_K,
                                      uint8_t lifetime,
                                      uint8_t *opaque,
                                      uint8_t opaque_len)
{
    struct hip_challenge_request request;

    hip_set_param_challenge_request(&request, val_K, lifetime, opaque, opaque_len);
    if (hip_build_param(msg, &request) != 0) {
        HIP_ERROR("failed to build parameter\n");
        return -1;
    }

    return 0;
}

/**
 * Build and append a HIP solution into the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the solution is to be appended
 * @param pz values from the corresponding hip_challenge_request copied to the solution
 * @param solution value for the solution (in host byte order)
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_response(struct hip_common *msg,
                                       const struct hip_challenge_request *request,
                                       uint8_t val_J[PUZZLE_LENGTH])
{
    struct hip_challenge_response response;
    int                           opaque_length = 0;
    int                           err           = 0;

    opaque_length = hip_get_param_contents_len(request) -
                    2 * sizeof(uint8_t);

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &response,
                               3 * sizeof(uint8_t) + sizeof(uint64_t) +
                               opaque_length);
    hip_set_param_type((struct hip_tlv_common *) &response,
                       HIP_PARAM_CHALLENGE_RESPONSE);

    memcpy(response.J, val_J, PUZZLE_LENGTH);
    response.K        = request->K;
    response.lifetime = request->lifetime;
    memcpy(&response.opaque, request->opaque, opaque_length);

    HIP_IFEL(hip_build_param(msg, &response), -1, "failed to build parameter\n");

out_err:
    return err;
}

uint8_t hip_challenge_response_opaque_len(const struct hip_challenge_response *response)
{
    static const size_t min_len = sizeof(*response) -
                                  sizeof(response->tlv) -
                                  sizeof(response->opaque);

    return hip_get_param_contents_len(&response->tlv) - min_len;
}

uint8_t hip_challenge_request_opaque_len(const struct hip_challenge_request *request)
{
    static const size_t min_len = sizeof(*request) -
                                  sizeof(request->tlv) -
                                  sizeof(request->opaque);

    return hip_get_param_contents_len(&request->tlv) - min_len;
}

//
// TODO: Create new file for utility functions decoupled from hipd?
//       Using a midauth_* namespace.
//
uint64_t hip_midauth_puzzle_seed(UNUSED const uint8_t opaque[],
                                 UNUSED const uint8_t opaque_len)
{
    return 0xdeadc0deL; // TODO: compute RHASH of opaque
}
