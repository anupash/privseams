/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
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
