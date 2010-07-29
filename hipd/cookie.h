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
 */

#ifndef HIP_HIPD_COOKIE_H
#define HIP_HIPD_COOKIE_H

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"

struct hip_r1entry {
    struct hip_common *r1;
    uint32_t           generation;
    uint64_t           Ci;
    uint8_t            Ck;
    uint8_t            Copaque[3];
};

#define HIP_R1TABLESIZE         3 /* precreate only this many R1s */
struct hip_common *hip_get_r1(struct in6_addr *ip_i,
                              struct in6_addr *ip_r,
                              struct in6_addr *peer_hit);
struct hip_r1entry *hip_init_r1(void);
void hip_uninit_r1(struct hip_r1entry *);
int hip_recreate_all_precreated_r1_packets(void);
int hip_precreate_r1(struct hip_r1entry *r1table,
                     const struct in6_addr *hit,
                     int (*sign)(void *key, struct hip_common *m),
                     void *privkey,
                     struct hip_host_id *pubkey);
int hip_verify_cookie(in6_addr_t *ip_i, in6_addr_t *ip_r,  hip_common_t *hdr,
                      struct hip_solution *cookie);
int hip_inc_cookie_difficulty(void);
int hip_dec_cookie_difficulty(void);
int hip_get_puzzle_difficulty_msg(struct hip_common *msg);
int hip_set_puzzle_difficulty_msg(struct hip_common *msg);

#endif /* HIP_HIPD_COOKIE_H */
