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
 */

#ifndef MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H
#define MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H

#include <stdint.h>

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"


#define MAX_CHALLENGE_LENGTH 256


struct hip_challenge_request {
    struct hip_tlv_common tlv;
    uint8_t               K;
    uint8_t               lifetime;
    uint8_t               opaque[MAX_CHALLENGE_LENGTH];           /**< variable length */
} __attribute__((packed));

struct hip_challenge_response {
    struct hip_tlv_common tlv;
    uint8_t               K;
    uint8_t               lifetime;
    uint8_t               J[PUZZLE_LENGTH];
    uint8_t               opaque[MAX_CHALLENGE_LENGTH]; /**< variable length */
} __attribute__((packed));


int hip_build_param_challenge_request(struct hip_common *const msg,
                                      const uint8_t difficulty,
                                      const uint8_t lifetime,
                                      const uint8_t *opaque,
                                      const uint8_t opaque_len);

int hip_build_param_challenge_response(struct hip_common *const msg,
                                       const struct hip_challenge_request *const request,
                                       const uint8_t *const solution);

unsigned int hip_challenge_request_opaque_len(const struct hip_challenge_request *const request);

int hip_midauth_puzzle_seed(const uint8_t *const opaque,
                            const unsigned int opaque_len,
                            uint8_t *const puzzle_value);

#endif /* MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H */
