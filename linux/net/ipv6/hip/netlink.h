#ifndef _HIP_NETLINK_H
#define _HIP_NETLINK_H

#include <net/hip.h> /* struct hip_work_order */
#ifdef __KERNEL__
#include <net/sock.h> /* struct sock */
#endif
#include "builder.h"
#include "debug.h"

int hip_netlink_open(int *fd);
void hip_netlink_close(void);
int hip_netlink_send(struct hip_work_order *hwo);
struct hip_work_order *hip_netlink_receive(void);

#endif /* _HIP_NETLINK_H */
