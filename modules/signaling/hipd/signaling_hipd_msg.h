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

#define DH_GROUP_ID 3
#define DH_PUB_KEY_SIZE 192

#ifndef HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H
#define HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H

#include <stdint.h>

#include "lib/core/dh.h"
#include "lib/core/protodefs.h"
#include "lib/core/modularization.h"
#include "hipd/pkt_handling.h"

#include "modules/signaling/lib/signaling_prot_common.h"

extern unsigned char mb_dh_pub_key[];
extern uint16_t      mb_dh_pub_key_len;
extern DH           *dh;

/* Handler for incoming messages */
int signaling_handle_incoming_r2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_update(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_notification(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/* Handler for outgoing messages */
int signaling_mac_and_sign_handler(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_hmac2_and_sign(const uint8_t packet_type, const uint32_t ha_state,
                             struct hip_packet_context *ctx);
int signaling_add_user_signature(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_update_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state,
                                                  struct hip_packet_context *ctx);
int signaling_update_add_signed_service_ack_and_sig_conn(const uint8_t packet_type,
                                                         const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_generic_handle_service_offers(const uint8_t packet_type, struct hip_packet_context *ctx,
                                            struct signaling_connection *recv_conn,
                                            uint16_t flag_service_offer_signed,
                                            struct signaling_flags_info_req   *flags_info_requested,
                                            uint8_t role);
int signaling_i2_check_hmac(const uint8_t packet_type,
                            const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_check_signature(const uint8_t packet_type,
                                 const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state,
                                              struct hip_packet_context *ctx);
int signaling_i2_handle_unsigned_service_offers(const uint8_t packet_type, const uint32_t ha_state,
                                                struct hip_packet_context *ctx);
int signaling_i2_add_signed_service_ack_and_sig_conn(const uint8_t packet_type, const uint32_t ha_state,
                                                     struct hip_packet_context *ctx);
int signaling_r2_check_hmac2_and_sign(const uint8_t packet_type,
                                      const uint32_t ha_state, struct hip_packet_context *ctx);
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
int signaling_update_check_packet(UNUSED const uint8_t packet_type,
                                  UNUSED const uint32_t ha_state,
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
