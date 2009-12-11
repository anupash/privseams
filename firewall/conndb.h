#ifndef HIP_CONNDB_H
#define HIP_CONNDB_H

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifndef ANDROID_CHANGES
#include <linux/icmpv6.h>
#else
#include <linux/icmp.h>
#include <linux/coda.h>
#include "icmp6.h"
#endif

#include "debug.h"
#include "hidb.h"
#include "hashtable.h"

struct hip_conn_key {
	uint8_t protocol;
	uint16_t port_client;
	uint16_t port_peer;
	struct in6_addr hit_peer;
	struct in6_addr hit_proxy;
}  __attribute__ ((packed));

typedef struct hip_conn {
	struct hip_conn_key key;
	int state;
	struct in6_addr addr_client; // addr_proxy_client	
	struct in6_addr addr_peer; // addr_proxy_peer	
} hip_conn_t;

void hip_init_conn_db(void);
hip_conn_t *hip_conn_find_by_portinfo(struct in6_addr *hit_proxy,
				      struct in6_addr *hit_peer,
				      int protocol,
				      int port_client,
				      int port_peer);

#endif /*  HIP_CONNDB_H */
