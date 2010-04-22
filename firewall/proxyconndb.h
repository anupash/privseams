/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_PROXYCONNDB_H
#define HIP_FIREWALL_PROXYCONNDB_H

#include "lib/core/debug.h"

struct hip_proxy_conn_key {
    uint8_t         protocol;
    uint16_t        port_client;
    uint16_t        port_peer;
    struct in6_addr hit_peer;
    struct in6_addr hit_proxy;
}  __attribute__ ((packed));

typedef struct hip_proxy_conn {
    struct hip_proxy_conn_key key;
    int                       state;
    struct in6_addr           addr_client;
    struct in6_addr           addr_peer;
} hip_proxy_conn_t;

void hip_proxy_init_conn_db(void);
hip_proxy_conn_t *hip_proxy_conn_find_by_portinfo(
        const struct in6_addr *hit_proxy,
        const struct in6_addr *hit_peer,
        const int protocol,
        const int port_client,
        const int port_peer);

void hip_proxy_uninit_conn_db(void);

int hip_proxy_conn_add_entry(const struct in6_addr *addr_client,
                             const struct in6_addr *addr_peer,
                             const struct in6_addr *hit_proxy,
                             const struct in6_addr *hit_peer,
                             const int protocol,
                             const int port_client,
                             const int port_peer,
                             const int state);

#endif /*  HIP_FIREWALL_PROXYCONNDB_H */
