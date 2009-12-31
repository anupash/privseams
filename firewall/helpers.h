#ifndef HELPERS_H
#define HELPERS_H

#include <netinet/in.h>

#include "libhipcore/debug.h"
#include "rule_management.h"
#include "firewall.h"

char * addr_to_numeric(const struct in6_addr *addrp);
struct in6_addr * numeric_to_addr(const char *num);
void system_print(char* command);
#endif //helpers
