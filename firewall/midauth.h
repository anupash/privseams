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

#ifndef HIP_FIREWALL_MIDAUTH_H
#define HIP_FIREWALL_MIDAUTH_H

#define _BSD_SOURCE

#include <stdint.h>

#include "lib/core/protodefs.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "firewall_defines.h"

typedef int (*midauth_handler)(struct hip_fw_context *ctx);

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
int midauth_handler_accept(struct hip_fw_context *ctx);

int midauth_verify_challenge_response(const struct hip_challenge_response *const solution,
                                      const hip_hit_t initiator_hit,
                                      const hip_hit_t responder_hit);



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
int midauth_add_challenge_request(struct hip_fw_context *ctx,
                                  uint8_t val_K, uint8_t ltime,
                                  uint8_t *opaque, uint8_t opaque_len);

/**
 * Initialize midauth infrastructure.
 */
void midauth_init(void);

int midauth_filter_hip(struct hip_fw_context *ctx);

#endif /* HIP_FIREWALL_MIDAUTH_H */
