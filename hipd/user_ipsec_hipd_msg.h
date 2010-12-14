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
 * Messaging required for the userspace IPsec implementation of the hipfw
 *
 * @brief userspace IPsec hipd <-> hipfw communication
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_HIPD_USER_IPSEC_HIPD_MSG_H
#define HIP_HIPD_USER_IPSEC_HIPD_MSG_H

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"

int hip_userspace_ipsec_activate(const struct hip_common *msg);
struct hip_common *create_add_sa_msg(const struct in6_addr *saddr,
                                     const struct in6_addr *daddr,
                                     const struct in6_addr *src_hit,
                                     const struct in6_addr *dst_hit,
                                     const uint32_t spi, const int ealg,
                                     const struct hip_crypto_key *enckey,
                                     const struct hip_crypto_key *authkey,
                                     const int retransmission,
                                     const int direction, const int update,
                                     hip_ha_t *entry);
struct hip_common *create_delete_sa_msg(const uint32_t spi,
                                        const struct in6_addr *peer_addr,
                                        const struct in6_addr *dst_addr,
                                        const int family,
                                        const int src_port,
                                        const int dst_port);
struct hip_common *create_flush_all_sa_msg(void);

#endif /* HIP_HIPD_USER_IPSEC_HIPD_MSG_H */
