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

#ifndef HIP_FIREWALL_CONNTRACK_H
#define HIP_FIREWALL_CONNTRACK_H

#define _BSD_SOURCE

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "common_types.h"
#include "firewall_defines.h"
#include "rule_management.h"


/*-------------- CONNECTION TRACKING ------------*/

extern time_t connection_timeout;
extern time_t cleanup_interval;

enum {
    ORIGINAL_DIR,
    REPLY_DIR,
};

int filter_esp_state(const struct hip_fw_context *ctx);
int filter_state(const struct in6_addr *ip6_src,
                 const struct in6_addr *ip6_dst,
                 struct hip_common *buf,
                 const struct state_option *option,
                 const int accept, struct hip_fw_context *ctx);
int conntrack(const struct in6_addr *ip6_src,
              const struct in6_addr *ip6_dst,
              struct hip_common *buf, struct hip_fw_context *ctx);

struct esp_tuple *find_esp_tuple(const struct slist *esp_list,
                                 const uint32_t spi);
struct tuple *get_tuple_by_hits(const struct in6_addr *src_hit,
                                const struct in6_addr *dst_hit);
int hipfw_relay_esp(const struct hip_fw_context *ctx);

void hip_fw_conntrack_periodic_cleanup(void);
#endif /* HIP_FIREWALL_CONNTRACK_H */
