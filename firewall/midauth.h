/**
 * @file
 *
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
 *
 * @brief The header file for firewall/midauth.c
 * *
 * @author Thomas Jansen
 *
 */

#ifndef HIP_FIREWALL_MIDAUTH_H
#define HIP_FIREWALL_MIDAUTH_H

#define _BSD_SOURCE

#include <stdint.h>

#include "lib/core/protodefs.h"
#include "firewall_defines.h"

typedef int (*midauth_handler)(hip_fw_context_t *ctx);

struct midauth_handlers {
    midauth_handler i1;
    midauth_handler r1;
    midauth_handler i2;
    midauth_handler r2;
    midauth_handler u1;
    midauth_handler u2;
    midauth_handler u3;
    midauth_handler close;
    midauth_handler close_ack;
};

/**
 * Accepts a packet. Used in midauth_handlers as a default handler.
 *
 * @param ctx context of the packet
 * @return NF_ACCEPT
 */
int midauth_handler_accept(hip_fw_context_t *ctx);

/**
 * Check the correctness of a hip_solution_m
 *
 * @param hip the hip_common that contains the solution
 * @param s the solution to be checked
 * @return 0 if correct, nonzero otherwise
 */
int midauth_verify_challenge_response(struct hip_common *hip,
                                      struct hip_challenge_response *s);



/**
 * Insert a CHALLENGE_REQUEST parameter into a HIP packet.
 *
 * @param ctx context of the packet to be modified
 * @param val_K challenge_request parameter val_K
 * @param ltime challenge_request parameter lifetime
 * @param opaque challenge_request parameter opaque
 * @param opaque_len length of opaque
 * @return 0 on success
 */
int midauth_add_challenge_request(hip_fw_context_t *ctx,
                                  uint8_t val_K, uint8_t ltime,
                                  uint8_t *opaque, uint8_t opaque_len);

/**
 * Initialize midauth infrastructure.
 */
void midauth_init(void);

int midauth_filter_hip(hip_fw_context_t *ctx);

#endif /* HIP_FIREWALL_MIDAUTH_H */
