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

#ifndef HIP_HIPD_INPUT_H
#define HIP_HIPD_INPUT_H

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/debug.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"


/**
 * Checks for illegal controls in a HIP packet Controls field.
 *
 * <b>Do not confuse these controls with host association control fields.</b> HIP
 * packet Controls field values are dictated in RFCs/I-Ds. Therefore any bit
 * that is not dictated in these documents should not appear in the message and
 * should not be among legal values. Host association controls, on the other
 * hand are implementation specific values, and can be used as we please. Just
 * don't put those bits on wire!
 *
 * @param controls control value to be checked
 * @param legal    legal control values to check @c controls against
 * @return         1 if there are no illegal control values in @c controls,
 *                 otherwise 0.
 * @note           controls are given in host byte order.
 */
static inline int hip_controls_sane(uint16_t controls, uint16_t legal)
{
    return ((controls & HIP_PACKET_CTRL_ANON) | legal) == legal;
}

int hip_verify_packet_hmac(struct hip_common *msg,
                           struct hip_crypto_key *crypto_key);

int hip_verify_packet_hmac_general(struct hip_common *msg,
                                   const struct hip_crypto_key *crypto_key,
                                   const hip_tlv parameter_type);

int hip_receive_control_packet(struct hip_packet_context *ctx);

int hip_receive_udp_control_packet(struct hip_packet_context *ctx);

int hip_check_i1(const uint8_t packet_type,
                 const uint32_t ha_state,
                 struct hip_packet_context *ctx);

int hip_check_i2(const uint8_t packet_type,
                 const uint32_t ha_state,
                 struct hip_packet_context *ctx);

int hip_handle_i1(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_handle_i2_in_i2_sent(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx);

int hip_handle_i2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_check_notify(const uint8_t packet_type,
                     const uint32_t ha_state,
                     struct hip_packet_context *ctx);

int hip_handle_notify(const uint8_t packet_type,
                      const uint32_t ha_state,
                      struct hip_packet_context *ctx);

int hip_check_r1(const uint8_t packet_type,
                 const uint32_t ha_state,
                 struct hip_packet_context *ctx);

int hip_handle_r1(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_produce_keymat(UNUSED const uint8_t packet_type,
                       UNUSED const uint32_t ha_state,
                       struct hip_packet_context *ctx);

int hip_create_i2(UNUSED const uint8_t packet_type,
                  UNUSED const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_add_esp_info(UNUSED const uint8_t packet_type,
                     UNUSED const uint32_t ha_state,
                     struct hip_packet_context *ctx);

int hip_add_solution(UNUSED const uint8_t packet_type,
                     UNUSED const uint32_t ha_state,
                     struct hip_packet_context *ctx);

int hip_add_diffie_hellman(UNUSED const uint8_t packet_type,
                           UNUSED const uint32_t ha_state,
                           struct hip_packet_context *ctx);

int hip_check_r2(const uint8_t packet_type,
                 const uint32_t ha_state,
                 struct hip_packet_context *ctx);

int hip_handle_r2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_setup_ipsec_sa(const uint8_t packet_type,
                       const uint32_t ha_state,
                       struct hip_packet_context *ctx);

int hip_add_esp_info(UNUSED const uint8_t packet_type,
                       UNUSED const uint32_t ha_state,
                       struct hip_packet_context *ctx);


int hip_add_solution(UNUSED const uint8_t packet_type,
                       UNUSED const uint32_t ha_state,
                       struct hip_packet_context *ctx);

int hip_add_diffie_hellman(UNUSED const uint8_t packet_type,
                              UNUSED const uint32_t ha_state,
                              struct hip_packet_context *ctx);

#endif /* HIP_HIPD_INPUT_H */
