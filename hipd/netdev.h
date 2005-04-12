/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */
#ifndef NETDEV_H
#define NETDEV_H

#include <netinet/ip6.h>
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include <net/hip.h>
#include "netlink.h"
#include "list.h"

#define SA2IP(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
        (void*)&((struct sockaddr_in*)x)->sin_addr : \
        (void*)&((struct sockaddr_in6*)x)->sin6_addr
#define SALEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? 4 : 16

struct netdev_address {
	struct list_head next;
	struct sockaddr_storage addr;
	int if_index;
};

int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct hip_nl_handle *nl);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);

#endif /* NETDEV_H */
