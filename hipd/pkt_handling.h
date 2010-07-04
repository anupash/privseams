/**
 * @file
 * The header file for hipd/pkt_handling.c
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
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#ifndef HIP_HIPD_PKT_HANDLING_H
#define HIP_HIPD_PKT_HANDLING_H

#include <stdint.h>
#include "lib/core/protodefs.h"

int hip_register_handle_function(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 int (*handle_function)(const uint8_t packet_type,
                                                        const uint32_t ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint16_t priority);

int hip_run_handle_functions(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx);

void hip_uninit_handle_functions(void);

#endif /* HIP_HIPD_PKT_HANDLING_H */
