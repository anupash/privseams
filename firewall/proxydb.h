#ifndef PROXYDB_H
#define PROXYDB_H

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "debug.h"
#include "hidb.h"
#include "hashtable.h"

HIP_HASHTABLE *hip_proxy_db = NULL;
int hip_proxy_raw_sock_v4 = 0;
int hip_proxy_raw_sock_v6 = 0;

typedef struct hip_proxy_t {
	hip_hit_t hit_our; // hit_proxy_client
	hip_hit_t hit_peer;  // hit_proxy_peer
	hip_hit_t hit_proxy; // hit_proxy_server
	struct in6_addr addr_our; // addr_proxy_client
	struct in6_addr addr_peer; // addr_proxy_peer
	struct in6_addr addr_proxy; // addr_proxy_server
	int state;
	int hip_capable;
} hip_proxy_t;
#endif