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
 * @brief user-mode HIP BEET mode implementation
 */

#ifndef HIP_FIREWALL_USER_IPSEC_ESP_H
#define HIP_FIREWALL_USER_IPSEC_ESP_H

#define _BSD_SOURCE

#include <stdint.h>
#include <netinet/in.h>

#include "firewall_defines.h"
#include "user_ipsec_sadb.h"


int hip_beet_mode_output(const struct hip_fw_context *ctx,
                         struct hip_sa_entry *entry,
                         const struct in6_addr *preferred_local_addr,
                         const struct in6_addr *preferred_peer_addr,
                         unsigned char *esp_packet,
                         uint16_t *esp_packet_len);
int hip_beet_mode_input(const struct hip_fw_context *ctx,
                        struct hip_sa_entry *entry,
                        unsigned char *decrypted_packet,
                        uint16_t *decrypted_packet_len);

#endif /* HIP_FIREWALL_USER_IPSEC_ESP_H*/
