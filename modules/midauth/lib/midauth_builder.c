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
 * This file contains parameter handling functionality for the middlebox
 * authentication extension.
 *
 * @author Rene Hummen
 * @author Christof Mroz <christof.mroz@rwth-aachen.de>
 */

#include <stdint.h>
#include <string.h>

#include "lib/core/ife.h"
#include "modules/midauth/hipd/midauth.h"
#include "midauth_builder.h"


/**
 * Build and append a HIP CHALLENGE_REQUEST to the message.
 *
 * @param msg           the message where the CHALLENGE_REQUEST is appended
 * @param difficulty    the puzzle difficulty for the CHALLENGE_REQUEST
 * @param lifetime      lifetime the puzzle nonce
 * @param opaque        the nonce (challenge) of the CHALLENGE_REQUEST
 * @param opaque_len    the length of the nonce
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_request(struct hip_common *const msg,
                                      const uint8_t difficulty,
                                      const uint8_t lifetime,
                                      const uint8_t *opaque,
                                      const uint8_t opaque_len)
{
    struct hip_challenge_request request;
    static const size_t          min_length = sizeof(request) -
                                              sizeof(request.tlv) -
                                              sizeof(request.opaque);

    HIP_ASSERT(opaque);

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len(&request.tlv, min_length + opaque_len);
    hip_set_param_type(&request.tlv, HIP_PARAM_CHALLENGE_REQUEST);

    /* only the random_j_k is in host byte order */
    request.K        = difficulty;
    request.lifetime = lifetime;
    memcpy(&request.opaque, opaque, opaque_len);

    if (hip_build_param(msg, &request) != 0) {
        HIP_ERROR("failed to build parameter\n");
        return -1;
    }

    return 0;
}

/**
 * Build and append a HIP CHALLENGE_RESPONSE to the message.
 *
 * @param msg       the message where the CHALLENGE_RESPONSE is appended
 * @param request   the received CHALLENGE_REQUEST parameter for this response
 * @param solution  the solution for the puzzle in the CHALLENGE_REQUEST
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_response(struct hip_common *const msg,
                                       const struct hip_challenge_request *const request,
                                       const uint8_t solution[PUZZLE_LENGTH])
{
    struct hip_challenge_response response;
    const int                     opaque_len = hip_challenge_request_opaque_len(request);
    static const size_t           min_length = sizeof(response) -
                                               sizeof(response.tlv) -
                                               sizeof(response.opaque);

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len(&response.tlv, min_length + opaque_len);
    hip_set_param_type(&response.tlv, HIP_PARAM_CHALLENGE_RESPONSE);

    memcpy(response.J, solution, PUZZLE_LENGTH);
    response.K        = request->K;
    response.lifetime = request->lifetime;
    memcpy(response.opaque, request->opaque, opaque_len);

    if (hip_build_param(msg, &response)) {
        HIP_ERROR("failed to build parameter\n");
        return -1;
    }

    return 0;
}

/**
 * Compute length of opaque field in CHALLENGE_RESPONSE parameter.
 *
 * @param response  the CHALLENGE_RESPONSE parameter
 * @return length of the opaque field
 */
uint8_t hip_challenge_response_opaque_len(const struct hip_challenge_response *response)
{
    static const size_t min_len = sizeof(*response) -
                                  sizeof(response->tlv) -
                                  sizeof(response->opaque);

    return hip_get_param_contents_len(&response->tlv) - min_len;
}

/**
 * Compute length of opaque field in CHALLENGE_REQUEST parameter.
 *
 * @param request  the CHALLENGE_REQUEST parameter
 * @return length of the opaque field
 */
uint8_t hip_challenge_request_opaque_len(const struct hip_challenge_request *request)
{
    static const size_t min_len = sizeof(*request) -
                                  sizeof(request->tlv) -
                                  sizeof(request->opaque);

    return hip_get_param_contents_len(&request->tlv) - min_len;
}

/**
 * Convert opaque value in the CHALLENGE_REQUEST to seed value I of a HIP puzzle.
 *
 * @param opaque            the opaque value in the CHALLENGE_REQUEST
 * @param opaque_len        length of the opaque value
 * @param[out] puzzle_value the generated puzzle value
 * @return zero on success, -1 in case of an error
 */
int hip_midauth_puzzle_seed(const uint8_t opaque[],
                            const uint8_t opaque_len,
                            uint8_t puzzle_value[PUZZLE_LENGTH])
{
    unsigned char sha_digest[SHA_DIGEST_LENGTH];

    // the hashed opaque field is used as puzzle seed
    if (hip_build_digest(HIP_DIGEST_SHA1,
                         opaque,
                         opaque_len,
                         sha_digest)) {
        HIP_ERROR("Building of SHA1 Random seed I failed\n");
        return -1;
    }

    memcpy(puzzle_value,
           &sha_digest[SHA_DIGEST_LENGTH - PUZZLE_LENGTH],
           PUZZLE_LENGTH);

    return 0;
}
