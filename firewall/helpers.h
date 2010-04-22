/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_HELPERS_H
#define HIP_FIREWALL_HELPERS_H

#include <netinet/in.h>

#include "lib/core/debug.h"
#include "rule_management.h"
#include "firewall.h"

char *addr_to_numeric(const struct in6_addr *addrp);
struct in6_addr *numeric_to_addr(const char *num);
void system_print(char *command);

#endif /* HIP_FIREWALL_HELPERS_H */
