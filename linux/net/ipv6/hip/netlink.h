#ifndef _HIP_NETLINK_H
#define _HIP_NETLINK_H

#include <net/hip.h> /* struct hip_work_order */
#ifdef __KERNEL__
#include <net/sock.h> /* struct sock */
#include "workqueue.h"
#else
#include <stdio.h>
#include <iproute/libnetlink.h> /* struct rtnl* */
#endif

#include "builder.h"
#include "debug.h"

#ifdef __KERNEL__
int hip_netlink_open();
void hip_netlink_close(void);
#else
int hip_netlink_receive();
#endif
int hip_netlink_send(struct hip_work_order *hwo);

#endif /* _HIP_NETLINK_H */
