/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_PROXYDB_H
#define HIP_FIREWALL_PROXYDB_H

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "lib/core/debug.h"
#include "hipd/hidb.h"
#include "lib/core/hashtable.h"
#include "firewall_control.h"

typedef struct hip_proxy_t {
    hip_hit_t       hit_proxy;
    hip_hit_t       hit_peer;
    struct in6_addr addr_client;
    struct in6_addr addr_peer;
    struct in6_addr addr_proxy;
    int             state;
    int             hip_capable;
} hip_proxy_t;

void hip_init_proxy_db(void);

hip_proxy_t *hip_proxy_find_by_addr(const struct in6_addr *addr,
                                    const struct in6_addr *addr2);
int hip_proxy_add_entry(const struct in6_addr *addr_client,
                        const struct in6_addr *addr_peer);

int hip_proxy_update_state(struct in6_addr *client_addr,
                           struct in6_addr *peer_addr,
                           struct in6_addr *proxy_addr,
                           hip_hit_t *proxy_hit,
                           hip_hit_t *peer_hit,
                           int state);

void hip_uninit_proxy_db(void);

#endif /* HIP_FIREWALL_PROXYDB_H */
