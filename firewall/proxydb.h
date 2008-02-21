#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

#include "hashtable.h"

HIP_HASHTABLE *hip_proxy_db = NULL;

struct hip_proxy {
	hip_hit_t hit_our;
	hip_hit_t hit_peer;
	struct in6_addr addr_our;
	struct in6_addr addr_peer;
	int state;
	int hip_capable;
}
