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

#ifndef HIP_HIPD_HADB_LEGACY_H
#define HIP_HIPD_HADB_LEGACY_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "lib/core/protodefs.h"


int hip_hadb_get_peer_addr_info_old(hip_ha_t *entry,
                                    const struct in6_addr *addr,
                                    uint32_t *lifetime,
                                    struct timeval *modified_time);
void hip_update_handle_ack_old(hip_ha_t *entry,
                               struct hip_ack *ack,
                               int have_esp_info);
//add by santtu
int hip_hadb_add_udp_addr_old(hip_ha_t *entry,
                              struct in6_addr *addr,
                              int is_bex_address,
                              uint32_t lifetime,
                              int is_preferred_addr,
                              uint16_t port,
                              uint32_t priority,
                              uint8_t kind);

void hip_hadb_delete_peer_addrlist_one_old(hip_ha_t *ha, struct in6_addr *addr);

#endif /* HIP_HIPD_HADB_LEGACY_H */
