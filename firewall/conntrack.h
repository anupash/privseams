/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
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
enum {
    ORIGINAL_DIR,
    REPLY_DIR,
};

int filter_esp_state(const hip_fw_context_t *ctx);
int filter_state(const struct in6_addr *ip6_src,
                 const struct in6_addr *ip6_dst,
                 struct hip_common *buf,
                 const struct state_option *option,
                 const int accept, hip_fw_context_t *ctx);
int conntrack(const struct in6_addr *ip6_src,
              const struct in6_addr *ip6_dst,
              struct hip_common *buf, hip_fw_context_t *ctx);

struct esp_tuple *find_esp_tuple(const SList *esp_list, const uint32_t spi);
struct tuple *get_tuple_by_hits(const struct in6_addr *src_hit,
                                const struct in6_addr *dst_hit);
int hipfw_relay_esp(const hip_fw_context_t *ctx);

#endif /* HIP_FIREWALL_CONNTRACK_H */
