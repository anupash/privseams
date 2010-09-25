/**
 * @file
 *
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
 * Host Identity Protocol
 * Copyright (C) 2004-06 the Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @file
 *
 * @author Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * @author Rene Hummen <rene.hummen@rwth-aachen.de> (ported to HIPL project and major rewrite)
 *
 * @brief user-mode HIP BEET mode implementation
 *
 */

#ifndef HIP_FIREWALL_USER_IPSEC_ESP_H
#define HIP_FIREWALL_USER_IPSEC_ESP_H

#define _BSD_SOURCE

#include <stdint.h>
#include <netinet/in.h>

#include "firewall_defines.h"
#include "user_ipsec_sadb.h"


int hip_beet_mode_output(const hip_fw_context_t *ctx,
                         hip_sa_entry_t *entry,
                         const struct in6_addr *preferred_local_addr,
                         const struct in6_addr *preferred_peer_addr,
                         unsigned char *esp_packet,
                         uint16_t *esp_packet_len);
int hip_beet_mode_input(const hip_fw_context_t *ctx, hip_sa_entry_t *entry,
                        unsigned char *decrypted_packet,
                        uint16_t *decrypted_packet_len);

#endif /* HIP_FIREWALL_USER_IPSEC_ESP_H*/
