/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_HELPERS_H
#define HIP_FIREWALL_HELPERS_H

#include <netinet/in.h>

char *addr_to_numeric(const struct in6_addr *addrp);
struct in6_addr *numeric_to_addr(const char *num);
void system_print(const char *command);

#endif /* HIP_FIREWALL_HELPERS_H */
