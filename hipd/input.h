/** @file
 * A header file for input.c.
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Samu Varjonen
 * @author  Rene Hummen
 * @author  Tim Just
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#ifndef HIP_HIPD_INPUT_H
#define HIP_HIPD_INPUT_H

#include "config.h"
#include "hiprelay.h"
#include "lib/core/state.h"
#include "lib/core/debug.h"
#include "lib/core/protodefs.h"

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
                                   const hip_tlv_type_t parameter_type);

int hip_verify_packet_rvs_hmac(struct hip_common *msg,
                               struct hip_crypto_key *crypto_key);

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

int hip_check_r2(const uint8_t packet_type,
                 const uint32_t ha_state,
                 struct hip_packet_context *ctx);

int hip_handle_r2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_produce_keying_material(struct hip_packet_context *ctx,
                                uint64_t I,
                                uint64_t J,
                                struct hip_dh_public_value **dhpv);

#endif /* HIP_HIPD_INPUT_H */
