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
#ifndef ANDROID_CHANGES
#include <netinet/ip6.h>
#endif
#include <openssl/rand.h>
#include "nlink.h"
#include "list.h"
#include "debug.h"
#include "libhipcore/utils.h"
#include "libhipcore/misc.h"
#include "hit_to_ip.h"

extern int suppress_af_family; /* Defined in hipd/hipd.c*/
extern int address_count;
extern HIP_HASHTABLE *addresses;
extern int hip_wait_addr_changes_to_stabilize;
extern int address_change_time_counter;
struct rtnl_handle;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct rtnl_handle *nl);
void delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int hip_select_source_address(struct in6_addr *src, const struct in6_addr *dst);
int hip_get_default_hit(struct in6_addr *hit);
int hip_get_default_hit_msg(struct hip_common *msg);
int hip_get_default_lsi(struct in_addr *lsi);
int hip_get_puzzle_difficulty_msg(struct hip_common *msg);
int hip_set_puzzle_difficulty_msg(struct hip_common *msg);

int hip_netdev_trigger_bex_msg(struct hip_common *msg);
int exists_address_in_list(const struct sockaddr *addr, int ifindex);
void add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

int hip_netdev_white_list_add(char* device_name);

#endif /* NETDEV_H */
