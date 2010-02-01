/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */
#ifndef NETDEV_H
#define NETDEV_H

#include <sys/socket.h>
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include <netinet/ip6.h>
#include <openssl/rand.h>
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/tool/nlink.h"
#include "lib/core/list.h"
#include "lib/core/debug.h"
#include "lib/core/utils.h"
#include "lib/core/misc.h"
#include "hit_to_ip.h"

#ifdef CONFIG_HIP_MAEMO
/* Fix the maemo environment's broken macros */

#undef NLMSG_NEXT
#define NLMSG_NEXT(nlh,len)      ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                                  (struct nlmsghdr*)(void*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))

#undef IFA_RTA
#define IFA_RTA(r)  ((struct rtattr*)(void*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#undef RTA_NEXT
#define RTA_NEXT(rta,attrlen)   ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                                 (struct rtattr*)(void*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#endif

struct rtnl_handle;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct rtnl_handle *nl);
void delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int hip_add_iface_local_hit(const hip_hit_t *local_hit);
int hip_add_iface_local_route(const hip_hit_t *local_hit);
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst);
int hip_get_default_hit(struct in6_addr *hit);
int hip_get_default_hit_msg(struct hip_common *msg);
int hip_get_default_lsi(struct in_addr *lsi);
int hip_get_puzzle_difficulty_msg(struct hip_common *msg);
int hip_set_puzzle_difficulty_msg(struct hip_common *msg);

int hip_netdev_trigger_bex_msg(struct hip_common *msg);
void add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

int hip_netdev_white_list_add(char* device_name);
int exists_address_in_list(const struct sockaddr *addr, int ifindex);

void hip_copy_peer_addrlist_changed(hip_ha_t *ha);

int hip_map_id_to_addr(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *addr);

#endif /* NETDEV_H */
