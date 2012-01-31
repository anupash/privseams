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

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include "lib/core/protodefs.h"
#include "lib/core/linkedlist.h"


struct signaling_cdb_entry {
    hip_hit_t src_hit;
    hip_hit_t dst_hit;
    uint16_t  src_port;
    uint16_t  dst_port;
    int       status;
};


void signaling_cdb_init(void);
void signaling_cdb_uninit(void);
int signaling_cdb_add_connection(const struct in6_addr src_hit,
                                 const struct in6_addr dst_hit,
                                 const uint16_t        src_port,
                                 const uint16_t        dst_port,
                                 const int             status);
struct signaling_cdb_entry *signaling_cdb_get_connection(const struct in6_addr src_hit,
                                                         const struct in6_addr dst_hit,
                                                         const uint16_t        src_port,
                                                         const uint16_t        dst_port);
void signaling_cdb_del_connection(const struct in6_addr src_hit,
                                  const struct in6_addr dst_hit,
                                  const uint16_t        src_port,
                                  const uint16_t        dst_port);
void signaling_cdb_print(void);

#endif /* HIP_HIPFW_SIGNALING_HIPFW_CONNTRACK_DB_H */
