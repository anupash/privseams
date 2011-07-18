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
 */

#ifndef MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H
#define MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H

#include <inttypes.h>

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"


struct hip_challenge_request {
    hip_tlv     type;
    hip_tlv_len length;
    uint8_t     K;
    uint8_t     lifetime;
    uint8_t     opaque[24];           /**< variable length */
} __attribute__ ((packed));

struct hip_challenge_response {
    hip_tlv     type;
    hip_tlv_len length;
    uint8_t     K;
    uint8_t     lifetime;
    uint8_t     J[PUZZLE_LENGTH];
    uint8_t     opaque[24];           /**< variable length */
} __attribute__ ((packed));

int hip_build_param_challenge_request(struct hip_common *msg,
                                      uint8_t val_K,
                                      uint8_t lifetime,
                                      uint8_t *opaque,
                                      uint8_t opaque_len);

int hip_build_param_challenge_response(struct hip_common *msg,
                                       const struct hip_challenge_request *pz,
                                       uint8_t *const val_J);

#endif /* MODULES_MIDAUTH_HIPD_MIDAUTH_BUILDER_H */
