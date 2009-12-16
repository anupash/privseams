#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "firewall_defines.h"
#include "rule_management.h"
#include "common_types.h"


/*-------------- CONNECTION TRACKING ------------*/
enum{
  ORIGINAL_DIR,
  REPLY_DIR,
    };

int filter_esp_state(const hip_fw_context_t * ctx);
int filter_state(const struct in6_addr * ip6_src,
		 const struct in6_addr * ip6_dst,
		 struct hip_common * buf,
		 const struct state_option * option,
		 const int accept, hip_fw_context_t *ctx);
void conntrack(const struct in6_addr * ip6_src,
        const struct in6_addr * ip6_dst,
	    struct hip_common * buf, hip_fw_context_t *ctx);

void init_timeout_checking(long int timeout_val);

struct esp_tuple * find_esp_tuple(const SList * esp_list, const uint32_t spi);

#endif
