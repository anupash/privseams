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

/*
 * Do something with the application information included in the I2 or R2 packet.
 * For now, just print it.
 */
int signaling_handle_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

int signaling_handle_bex_update(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

int signaling_send_scdb_add(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx);

int signaling_trigger_bex_update(struct hip_common *msg, UNUSED struct sockaddr_in6 *src);

/*
 * Add application information to I2 packet.
 */
int signaling_i2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

/*
 * Add application information to R2 packet.
 */
int signaling_r2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_MSG_H*/
