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

#ifndef HIP_FIREWALL_LSI_H
#define HIP_FIREWALL_LSI_H

#define _BSD_SOURCE

#include <libipq.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"

int hip_trigger_bex(const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    const hip_lsi_t *src_lsi,
                    const hip_lsi_t *dst_lsi,
                    const struct in6_addr *src_ip,
                    const struct in6_addr *dst_ip);
int hip_fw_handle_incoming_hit(const ipq_packet_msg_t *m,
                               const struct in6_addr *ip_src,
                               const struct in6_addr *ip_dst,
                               const int lsi_support);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m,
                               struct in_addr *ip_src,
                               struct in_addr *ip_dst);

int hip_is_packet_lsi_reinjection(hip_lsi_t *lsi);
int hip_reinject_packet(const struct in6_addr *src_hit,
                        const struct in6_addr *dst_hit,
                        const ipq_packet_msg_t *m,
                        const int ip_orig_traffic,
                        const int incoming);

#endif /* HIP_FIREWALL_LSI_H */
