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

#include "lib/core/protodefs.h"

#include "modules/signaling/lib/signaling_prot_common.h"

/* Handler for incoming messages */
int signaling_handle_incoming_i2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_r2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_i3(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_update(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_notification(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/* Handler for outgoing messages */
int signaling_i2_add_application_context(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_add_user_context(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_add_user_signature(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_application_context(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_user_context(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_user_signature(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_user_auth_resp(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/* Function for prolonged BEX */
int signaling_send_I3(struct hip_hadb_state *ha, struct signaling_connection *conn);

/* Functions for initiating and answering to a bex update */
int signaling_send_first_update(const struct in6_addr *src_hit,
                                const struct in6_addr *dst_hit,
                                struct signaling_connection *conn);
int signaling_send_second_update(const struct hip_common *first_update);
int signaling_send_third_update(const struct hip_common *second_update);

/* Functions for certificate exchange */
int signaling_send_user_auth_failed_ntf(struct hip_hadb_state *ha, const int reason);
int signaling_send_connection_failed_ntf(struct hip_hadb_state *ha, const int reason, const struct signaling_connection *conn);
int signaling_send_user_certificate_chain(struct hip_hadb_state *ha, struct signaling_connection *conn, uint32_t network_id);
int signaling_send_user_certificate_chain_ack(struct hip_hadb_state *ha,
                                              const uint32_t seq,
                                              const struct signaling_connection *const conn,
                                              uint32_t network_id);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H*/
