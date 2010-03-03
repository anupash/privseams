/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */
#ifndef HIP_HIPD_NETDEV_H
#define HIP_HIPD_NETDEV_H

#include <sys/socket.h>
#include <netinet/ip6.h>
#include <openssl/rand.h>
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/tool/nlink.h"
#include "lib/core/list.h"
#include "lib/core/debug.h"
#include "lib/core/prefix.h"
#include "lib/core/misc.h"
#include "hit_to_ip.h"

#ifdef CONFIG_HIP_MAEMO
/* Fix the maemo environment's broken macros */

#undef NLMSG_NEXT
#define NLMSG_NEXT(nlh, len)      ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                                   (struct nlmsghdr *) (void *) (((char *) (nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))

#undef IFA_RTA
#define IFA_RTA(r)  ((struct rtattr *) (void *) (((char *) (r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#undef RTA_NEXT
#define RTA_NEXT(rta, attrlen)   ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                                  (struct rtattr *) (void *) (((char *) (rta)) + RTA_ALIGN((rta)->rta_len)))
#endif

struct rtnl_handle;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct rtnl_handle *nl);
void hip_delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int hip_add_iface_local_hit(const hip_hit_t *local_hit);
int hip_add_iface_local_route(const hip_hit_t *local_hit);
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst);
int hip_netdev_trigger_bex_msg(struct hip_common *msg);
void hip_add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

int hip_netdev_white_list_add(char *device_name);
int hip_exists_address_in_list(const struct sockaddr *addr, int ifindex);

void hip_copy_peer_addrlist_changed(hip_ha_t *ha);

int hip_map_id_to_addr(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *addr);

#endif /* HIP_HIPD_NETDEV_H */
