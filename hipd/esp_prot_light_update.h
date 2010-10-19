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

/**
 *@file
 * Provides messaging functionality required for HHL-based anchor
 * element updates.
 *
 * @brief Messaging required for HHL-based anchor element updates
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H
#define HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H

#include "lib/core/protodefs.h"
#include "lib/modularization/lmod.h"

int esp_prot_send_light_update(hip_ha_t *entry,
                               const int anchor_offset[],
                               const unsigned char *secret[MAX_NUM_PARALLEL_HCHAINS],
                               const int secret_length[],
                               const unsigned char *branch_nodes[MAX_NUM_PARALLEL_HCHAINS],
                               const int branch_length[]);
int esp_prot_handle_light_update(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx);

#endif /* HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H */
