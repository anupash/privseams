#ifndef _HIP_NETLINK_H
#define _HIP_NETLINK_H

#include "builder.h"
//#include "debug.h"
#include "hip.h"

#  include <stdio.h>
#  include <linux/netlink.h>

typedef int (*hip_filter_t)(const struct nlmsghdr *n, int len, void *arg);


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

struct hip_nl_handle
{
        int                     fd;
        struct sockaddr_nl      local;
        struct sockaddr_nl      peer;
        __u32                   seq;
        __u32                   dump;
};

int hip_netlink_open(struct hip_nl_handle *nl, unsigned subscriptions, int protocol);
int hip_netlink_receive(struct hip_nl_handle *nl, hip_filter_t handler, void *arg);
int hip_netlink_send_buf(struct hip_nl_handle *nl, const char *buf, int len);
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg);
int hip_netlink_talk(struct hip_nl_handle *nl, struct hip_work_order *req, struct hip_work_order *resp);
int hip_netlink_send(struct hip_work_order *hwo);

#endif /* _HIP_NETLINK_H */
