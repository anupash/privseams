/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University.
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
 * This file implements parameter handling functionality specific to
 * UPDATE packets for the Host Identity Protocol (HIP)
 */

#ifndef HIP_MODULES_UPDATE_HIPD_UPDATE_PARAM_HANDLING_H
#define HIP_MODULES_UPDATE_HIPD_UPDATE_PARAM_HANDLING_H

#include "lib/core/protodefs.h"
#include "update.h"

int hip_add_esp_info_param(const uint8_t packet_type,
                           const uint32_t ha_state,
                           struct hip_packet_context *ctx);

int hip_handle_esp_info_param(const uint8_t packet_type,
                              const uint32_t ha_state,
                              struct hip_packet_context *ctx);

int hip_add_seq_param(const uint8_t packet_type,
                      const uint32_t ha_state,
                      struct hip_packet_context *ctx);

int hip_handle_seq_param(const uint8_t packet_type,
                         const uint32_t ha_state,
                         struct hip_packet_context *ctx);

int hip_add_echo_request_param(const uint8_t packet_type,
                               const uint32_t ha_state,
                               struct hip_packet_context *ctx);

int hip_handle_echo_request_sign_param(const uint8_t packet_type,
                                       const uint32_t ha_state,
                                       struct hip_packet_context *ctx);

int hip_handle_echo_request_param(const uint8_t packet_type,
                                  const uint32_t ha_state,
                                  struct hip_packet_context *ctx);

int hip_handle_locator_parameter(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx);

int hip_handle_locator(const uint8_t packet_type,
                       const uint32_t ha_state,
                       struct hip_packet_context *ctx);

#endif /* HIP_MODULES_UPDATE_HIPD_UPDATE_PARAM_HANDLING_H */
