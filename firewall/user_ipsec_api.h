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
 * This implementation provides the API for userspace IPsec.
 *
 * @brief API for the userspace IPsec functionality
 */

#ifndef HIP_FIREWALL_USER_IPSEC_API_H
#define HIP_FIREWALL_USER_IPSEC_API_H

#define _BSD_SOURCE

#include <netinet/udp.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include "lib/core/hashchain.h"
#include "lib/core/protodefs.h"
#include "firewall_defines.h"

int userspace_ipsec_init(void);
int userspace_ipsec_uninit(void);
int hip_fw_userspace_ipsec_input(const struct hip_fw_context *ctx);
int hip_fw_userspace_ipsec_output(const struct hip_fw_context *ctx);

#endif /* HIP_FIREWALL_USER_IPSEC_API_H */
