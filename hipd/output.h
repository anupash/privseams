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

#ifndef HIP_HIPD_OUTPUT_H
#define HIP_HIPD_OUTPUT_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "lib/core/state.h"


extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;


int hip_create_r1(struct hip_common *const msg,
                  const struct in6_addr *const src_hit,
                  int (*sign)(void *const key, struct hip_common *const m),
                  void *const private_key,
                  const struct hip_host_id *const host_id_pub,
                  const int cookie_k);

int hip_send_r1(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int hip_add_rvs_reg_from(const uint8_t packet_type,
                         const uint32_t ha_state,
                         struct hip_packet_context *ctx);

int hip_hmac2_and_sign(const uint8_t packet_type,
                       const uint32_t ha_state,
                       struct hip_packet_context *ctx);

int hip_add_rvs_relay_to(const uint8_t packet_type,
                         const uint32_t ha_state,
                         struct hip_packet_context *ctx);

int hip_create_r2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_send_r2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int hip_send_i1(hip_hit_t *, const hip_hit_t *, struct hip_hadb_state *);

int hip_add_signed_echo_response(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx);

int hip_mac_and_sign_packet(struct hip_common *msg,
                            const struct hip_hadb_state *const hadb_entry);

int hip_mac_and_sign_handler(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx);

int hip_add_unsigned_echo_response(const uint8_t packet_type,
                                   const uint32_t ha_state,
                                   struct hip_packet_context *ctx);

int hip_create_i2(const uint8_t packet_type,
                  const uint32_t ha_state,
                  struct hip_packet_context *ctx);

int hip_create_i2_build_r1_counter_and_hip_transform(const uint8_t packet_type,
                                                     const uint32_t ha_state,
                                                     struct hip_packet_context *ctx);

int hip_create_i2_build_host_id(const uint8_t packet_type,
                                const uint32_t ha_state,
                                struct hip_packet_context *ctx);

int hip_create_i2_encrypt_host_id_and_setup_inbound_ipsec(const uint8_t packet_type,
                                                          const uint32_t ha_state,
                                                          struct hip_packet_context *ctx);

int hip_create_i2_build_reg_req_and_esp_tranform(const uint8_t packet_type,
                                                 const uint32_t ha_state,
                                                 struct hip_packet_context *ctx);

int hip_send_i2(const uint8_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int are_addresses_compatible(const struct in6_addr *src_addr,
                             const struct in6_addr *dst_addr);
int hip_send_pkt(const struct in6_addr *local_addr,
                 const struct in6_addr *peer_addr,
                 const in_port_t src_port,
                 const in_port_t dst_port,
                 struct hip_common *msg,
                 struct hip_hadb_state *entry,
                 const int retransmit);
int hip_send_udp_stun(struct in6_addr *local_addr, struct in6_addr *peer_addr,
                      in_port_t src_port, in_port_t dst_port,
                      const void *msg, int length);

#endif /* HIP_HIPD_OUTPUT_H */
