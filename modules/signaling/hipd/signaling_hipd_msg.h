/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H
#define HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H

#include <stdint.h>

#include "lib/core/dh.h"
#include "lib/core/protodefs.h"
#include "lib/core/modularization.h"
#include "hipd/pkt_handling.h"

#include "modules/signaling/lib/signaling_prot_common.h"

#define DH_GROUP_ID 3
UNUSED static unsigned char mb_dh_pub_key[] = {
    0x5F, 0x4A, 0x82, 0x8B, 0x95, 0x99, 0x9B, 0xEE, 0xCE, 0xD2,
    0x90, 0x5C, 0xC8, 0x80, 0xD5, 0xCB, 0x76, 0x76, 0x1F, 0xEC,
    0xF3, 0xC3, 0x29, 0x60, 0x85, 0x0C, 0xF5, 0x62, 0x77, 0x61,
    0x04, 0x0F, 0x21, 0x00, 0x69, 0xF0, 0x31, 0xBA, 0xBF, 0x4E,
    0x4B, 0xCE, 0x91, 0x38, 0xCB, 0x47, 0x82, 0xBB, 0x6D, 0xBB,
    0xA4, 0x52, 0x9B, 0xC4, 0xC7, 0x6E, 0x2D, 0xB3, 0x99, 0x33,
    0x67, 0x44, 0xDF, 0x42, 0xCF, 0xFA, 0x23, 0x3E, 0x2F, 0x98,
    0x0F, 0x47, 0xD2, 0xEB, 0x8F, 0x02, 0xB4, 0xDD, 0x86, 0xB0,
    0xA2, 0x30, 0xA8, 0x86, 0xB9, 0xCA, 0x0B, 0x68, 0xCE, 0xD1,
    0xB0, 0xED, 0xEF, 0x69, 0x3D, 0xBA, 0x82, 0x13, 0xBC, 0x04,
    0xB7, 0x7C, 0xF1, 0xFB, 0xEB, 0xD7, 0x3E, 0x08, 0x12, 0x7A,
    0xE2, 0xCE, 0x3B, 0xCF, 0x9D, 0xC8, 0xFE, 0x34, 0xB2, 0x55,
    0x16, 0xFB, 0xFA, 0x77, 0x0A, 0x1B, 0x32, 0x58, 0x4A, 0x52,
    0xE2, 0xCF, 0x8A, 0xC0, 0x04, 0xFA, 0x58, 0xA6, 0x33, 0x3F,
    0x0B, 0xB7, 0xE7, 0xEE, 0x8D, 0x2D, 0x74, 0x92, 0x4A, 0x16,
    0x1D, 0x27, 0x49, 0x40, 0x60, 0xA7, 0xFB, 0xDB, 0x1E, 0xFC,
    0x3D, 0x75, 0xA6, 0x69, 0x71, 0x0F, 0xC6, 0xA9, 0x2D, 0x51,
    0x8E, 0x9B, 0xC6, 0xA0, 0x23, 0x58, 0x66, 0x9E, 0xD9, 0x1F,
    0xFB, 0x33, 0x35, 0x41, 0xEF, 0x5C, 0xBB, 0xD2, 0x7C, 0xF3,
    0xF5, 0x01
};

UNUSED static uint16_t mb_dh_pub_key_len = 192;
UNUSED static DH      *dh                = NULL;

/* Handler for incoming messages */
int signaling_handle_incoming_r2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_update(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_notification(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/* Handler for outgoing messages */
int signaling_add_user_signature(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_update_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_update_add_signed_service_ack_and_sig_conn(const uint8_t packet_type,
                                                         const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_generic_handle_service_offers(const uint8_t packet_type, struct hip_packet_context *ctx,
                                            struct signaling_connection *recv_conn,
                                            uint16_t flag_service_offer_signed,
                                            struct signaling_flags_info_req   *flags_info_requested,
                                            uint8_t role);
int signaling_i2_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_handle_unsigned_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_add_signed_service_ack_and_sig_conn(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

int signaling_r2_handle_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_signed_service_ack_and_sig_conn(UNUSED const uint8_t packet_type,
                                                     UNUSED const uint32_t ha_state, struct hip_packet_context *ctx);
/* Functions for initiating and answering to a bex update */
int signaling_send_first_update(const struct in6_addr *src_hit,
                                const struct in6_addr *dst_hit,
                                struct signaling_connection *conn);
int signaling_send_second_update(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx);
int signaling_send_third_update(const uint8_t packet_type,
                                const uint32_t ha_state,
                                struct hip_packet_context *ctx);

/* Functions for certificate exchange */
int signaling_send_user_auth_failed_ntf(struct hip_hadb_state *ha, const int reason);
int signaling_send_connection_failed_ntf(struct hip_hadb_state *ha, const int reason, const struct signaling_connection *conn);
int signaling_send_user_certificate_chain(struct hip_hadb_state *ha, struct signaling_connection *conn, uint32_t network_id);
int signaling_send_user_certificate_chain_ack(struct hip_hadb_state *ha,
                                              const uint32_t seq,
                                              const struct signaling_connection *const conn,
                                              uint32_t network_id);
/* utility functions */
int signaling_i2_handle_service_offers_common(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                              struct hip_packet_context *ctx, uint8_t flag);
int signaling_i2_check_offer_type(const uint8_t packet_type,
                                  const uint32_t ha_state,
                                  struct hip_packet_context *ctx);
int signaling_i2_group_service_offers(const uint8_t packet_type,
                                      const uint32_t ha_state,
                                      struct hip_packet_context *ctx);

int signaling_r2_check_offer_type(const uint8_t packet_type,
                                  const uint32_t ha_state,
                                  struct hip_packet_context *ctx);
int signaling_r2_group_service_offers(const uint8_t packet_type,
                                      const uint32_t ha_state,
                                      struct hip_packet_context *ctx);
int signaling_update_check_offer_type(const uint8_t packet_type,
                                      const uint32_t ha_state,
                                      struct hip_packet_context *ctx);
int signaling_update_add_diffie_hellman(const uint8_t packet_type,
                                        const uint32_t ha_state,
                                        struct hip_packet_context *ctx);
int signaling_update_group_service_offers(const uint8_t packet_type,
                                          const uint32_t ha_state,
                                          struct hip_packet_context *ctx);

int signaling_hipd_state_cleanup(const uint8_t packet_type,
                                 const uint32_t ha_state, struct hip_packet_context *ctx);
#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H*/
