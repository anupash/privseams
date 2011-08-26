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
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPFW_SIGNALING_HIPFW_CONNTRACK_DB_H
#define HIP_HIPFW_SIGNALING_HIPFW_CONNTRACK_DB_H

#include <stdint.h>

#include "firewall/common_types.h"
#include "lib/core/protodefs.h"

typedef struct signaling_cdb_entry {
    hip_hit_t local_hit;
    hip_hit_t remote_hit;
    struct slist * connections;
} signaling_cdb_entry_t;

int signaling_cdb_init(void);
int signaling_cdb_uninit(void);

int signaling_cdb_add(const struct in6_addr *local_hit,
                      const struct in6_addr *remote_hit,
                      struct signaling_connection *conn);

signaling_cdb_entry_t *signaling_cdb_entry_find(const struct in6_addr *local_hit,
                                                const struct in6_addr *remote_hit);
struct signaling_connection *signaling_cdb_entry_get_connection(const struct in6_addr *local_hit,
                                                                const struct in6_addr *remote_hit,
                                                                const uint32_t id);
int signaling_cdb_entry_find_connection(const uint16_t src_port, const uint16_t dest_port,
                                        signaling_cdb_entry_t * entry,
                                        struct signaling_connection **ret);

struct signaling_connection *signaling_cdb_entry_find_connection_by_dst_port(const struct in6_addr *src_hit,
                                                                             const struct in6_addr *dst_hit,
                                                                             const uint16_t dest_port);

struct signaling_connection *signaling_cdb_get_waiting(const struct in6_addr *src_hit,
                                                       const struct in6_addr *dst_hit);

int signaling_cdb_direction(const struct in6_addr *src_hit,
                            const struct in6_addr *dst_hit);

int signaling_cdb_entry_print(signaling_cdb_entry_t * entry);

void signaling_cdb_apply_func(int(*func)(signaling_cdb_entry_t *));

uint32_t signaling_cdb_get_next_connection_id(void);

void signaling_cdb_print(void);

#endif /* HIP_HIPFW_SIGNALING_HIPFW_CONNTRACK_DB_H */
