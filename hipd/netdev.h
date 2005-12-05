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

#include "nlink.h"
#include "hip.h"
#include "list.h"
#include "debug.h"

extern int address_count;
extern struct list_head addresses;
struct rtnl_handle;

int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct rtnl_handle *nl);
void delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int filter_address(struct sockaddr *addr, int ifindex);

#endif /* NETDEV_H */
