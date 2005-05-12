#ifndef HELPERS_H
#define HELPERS_H

#include <netinet/in.h>
#include "firewall.h"

//struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
//					  const struct hip_tlv_common *current_param);
char * addr_to_numeric(const struct in6_addr *addrp);
struct in6_addr * numeric_to_addr(const char *num);
void print_rule(const struct rule * rule);
void free_rule(struct rule * rule);
//void print_rule_table();
#endif //helpers
