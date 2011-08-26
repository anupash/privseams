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
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPFW_SIGNALING_HIPFW_OSLAYER_H
#define HIP_HIPFW_SIGNALING_HIPFW_OSLAYER_H

#include <stdint.h>

#include "firewall/firewall_defines.h"

#include "lib/core/protodefs.h"

#define VERDICT_DROP    0;
#define VERDICT_ACCEPT  1;

/* Defines what is done in case of errors. */
#define VERDICT_DEFAULT VERDICT_ACCEPT

int signaling_hipfw_oslayer_init(void);
int signaling_hipfw_oslayer_uninit(void);

/* Check if the packet is conntracked or not. Take the corresponding actions. */
int signaling_hipfw_conntrack(hip_fw_context_t *ctx);


#endif /*HIP_HIPFW_SIGNALING_HIPFW_OSLAYER_H*/
