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

/* Update message types */
#define SIGNALING_FIRST_BEX_UPDATE              33001
#define SIGNALING_SECOND_BEX_UPDATE             33002
#define SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE  33003
#define SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE 33004

/* Handler for incoming messages */
int signaling_handle_incoming_i2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_r2(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_update(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_handle_incoming_notification(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/* Handler for outgoing messages */
int signaling_i2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_i2_add_user_sig(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_r2_add_user_sig(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);
int signaling_send_first_update(const struct in6_addr *src_hit, const struct in6_addr *dst_hit);
int signaling_send_second_update(const struct hip_common *first_update);

int signaling_send_user_auth_failed_ntf(hip_ha_t *ha, const int reason);


/* Classification of signaling update messages */
int signaling_get_update_type(hip_common_t *msg);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H*/
