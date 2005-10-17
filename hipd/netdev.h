/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */
#ifndef NETDEV_H
#define NETDEV_H

#include <netinet/ip6.h>
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include "hip.h"
#include "list.h"
#include "debug.h"
#include "netlink.h"

extern int address_count;
extern struct list_head addresses;

int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct hip_nl_handle *nl);
void delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int filter_address(struct sockaddr *addr, int ifindex);

#endif /* NETDEV_H */
