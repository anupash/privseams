#ifndef _HIP_NETLINK_H
#define _HIP_NETLINK_H

#include <net/hip.h> /* struct hip_work_order */

int hip_netlink_open();
void hip_netlink_close();
int hip_netlink_send(struct hip_work_order *hwo);
struct hip_work_order *hip_netlink_receive(void);

#endif /* _HIP_NETLINK_H */
