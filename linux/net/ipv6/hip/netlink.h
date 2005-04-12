#ifndef _HIP_NETLINK_H
#define _HIP_NETLINK_H

#include <net/hip.h> /* struct hip_work_order */
#ifdef __KERNEL__
#include <net/sock.h> /* struct sock */
#include "workqueue.h"
#else
#include <stdio.h>
#include <linux/netlink.h>

struct hip_nl_handle
{
        int                     fd;
        struct sockaddr_nl      local;
        struct sockaddr_nl      peer;
        __u32                   seq;
        __u32                   dump;
};

typedef int (*hip_filter_t)(const struct nlmsghdr *n, int len, void *arg);

#endif

#include "builder.h"
#include "debug.h"

#ifdef __KERNEL__
int hip_netlink_open(void);
void hip_netlink_close(void);
#else
int hip_netlink_open(struct hip_nl_handle *nl, unsigned subscriptions, int protocol);
int hip_netlink_receive(struct hip_nl_handle *nl, hip_filter_t handler, void *arg);
int hip_netlink_send_buf(struct hip_nl_handle *nl, const char *buf, int len);
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg);
int hip_netlink_talk(struct hip_nl_handle *nl, struct hip_work_order *req, struct hip_work_order *resp);
#endif
int hip_netlink_send(struct hip_work_order *hwo);

#endif /* _HIP_NETLINK_H */
