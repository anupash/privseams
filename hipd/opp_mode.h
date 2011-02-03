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
 * @file
 * This file represents the interface of the opportunistic mode for the Host
 * Identity Protocol (HIP).
 *
 * @brief Interface of the HIP opportunistic mode
 *
 * @author Rene Hummen
 */

#ifndef HIP_HIPD_OPP_MODE_H
#define HIP_HIPD_OPP_MODE_H

#include "lib/core/protodefs.h"


struct hip_hadb_state *hip_opp_get_hadb_entry(const hip_hit_t *const init_hit,
                                              const struct in6_addr *const resp_addr);
struct hip_hadb_state *hip_opp_get_hadb_entry_i1_r1(struct hip_common *msg,
                                                    const struct in6_addr *const src_addr);
int hip_handle_opp_r1(struct hip_packet_context *ctx);

#endif /* HIP_HIPD_OPP_MODE_H */
