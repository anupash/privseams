/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */

#ifndef HIP_HIPD_NETDEV_H
#define HIP_HIPD_NETDEV_H

#include <sys/socket.h>
#include <netinet/ip6.h>
#include <openssl/rand.h>

#include "lib/tool/nlink.h"
#include "lib/core/list.h"
#include "lib/core/debug.h"
#include "lib/core/prefix.h"

#include "hit_to_ip.h"

struct rtnl_handle;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(void);
void hip_delete_all_addresses(void);
int hip_netdev_event(struct nlmsghdr *msg, int len, void *arg);
int hip_add_iface_local_hit(const hip_hit_t *local_hit);
int hip_add_iface_local_route(const hip_hit_t *local_hit);
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst);
int hip_netdev_trigger_bex_msg(const struct hip_common *msg);
void hip_add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

int hip_netdev_white_list_add(char *device_name);
int hip_exists_address_in_list(const struct sockaddr *addr, int ifindex);

void hip_copy_peer_addrlist_changed(hip_ha_t *ha);

int hip_map_id_to_addr(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *addr);

#endif /* HIP_HIPD_NETDEV_H */
