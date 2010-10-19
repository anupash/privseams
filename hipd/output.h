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
 * @author Janne Lundberg
 * @author Miika Komu
 * @author Mika Kousa
 * @author Kristian Slavov
 * @author Rene Hummen
 */

#ifndef HIP_HIPD_OUTPUT_H
#define HIP_HIPD_OUTPUT_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "lib/core/state.h"


#define HIP_MAX_ICMP_PACKET 512

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;


struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
                                 int (*sign)(void *key, struct hip_common *m),
                                 void *private_key,
                                 const struct hip_host_id *host_id_pub,
                                 int cookie_k);

int hip_send_r1(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int hip_send_r2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int hip_send_r2_response(struct hip_common *r2,
                         struct in6_addr *r2_saddr,
                         struct in6_addr *r2_daddr,
                         hip_ha_t *entry,
                         struct hip_portpair_t *r2_info);

int hip_send_i1(hip_hit_t *, const hip_hit_t *, hip_ha_t *);

int hip_send_i2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int are_addresses_compatible(const struct in6_addr *src_addr,
                             const struct in6_addr *dst_addr);
int hip_send_pkt(const struct in6_addr *local_addr, const struct in6_addr *peer_addr,
                 const in_port_t src_port, const in_port_t dst_port,
                 struct hip_common *msg, hip_ha_t *entry, const int retransmit);
int hip_send_udp_stun(struct in6_addr *local_addr, struct in6_addr *peer_addr,
                      in_port_t src_port, in_port_t dst_port,
                      const void *msg, int length);

#endif /* HIP_HIPD_OUTPUT_H */
