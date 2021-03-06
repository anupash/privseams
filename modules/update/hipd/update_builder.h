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
 *
 * This file facilitates buiding of mobility and multi-homing-specific
 * parameters.
 */

#ifndef HIP_MODULES_UPDATE_HIPD_UPDATE_BUILDER_H
#define HIP_MODULES_UPDATE_HIPD_UPDATE_BUILDER_H

#include <stdint.h>

#include "lib/core/protodefs.h"
#include "update.h"

int hip_build_param_seq(struct hip_common *const msg, const uint32_t update_id);
int hip_build_param_ack(struct hip_common *const msg,
                        const uint32_t peer_update_id);
int hip_build_param_locator(struct hip_common *const msg,
                            const struct hip_locator_info_addr_item *const addrs,
                            const int addr_count);

#endif /* HIP_MODULES_UPDATE_HIPD_UPDATE_BUILDER_H */
