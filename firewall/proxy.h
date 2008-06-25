#ifndef HIP_PROXY_H
#define HIP_PROXY_H

#include "firewall.h"

typedef struct hip_proxy_t {
	hip_hit_t hit_our;
	hip_hit_t hit_peer;
	hip_hit_t hit_proxy;
	struct in6_addr addr_our;
	struct in6_addr addr_peer;
	struct in6_addr addr_proxy;
	int state;
	int hip_capable;
} hip_proxy_t;

#endif /* HIP_PROXY_H */
