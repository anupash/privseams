#ifndef HIP_UPDATE_H
#define HIP_UPDATE_H

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#ifdef __KERNEL__
#include <net/ipv6.h>
#include <linux/xfrm.h>
#include <net/xfrm.h>
#else
/* FIXME: where to include these from in userspace? */
#define IPV6_ADDR_ANY           0x0000U
#define IPV6_ADDR_UNICAST       0x0001U 
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U

#endif

#include <net/hip.h>

int hip_receive_update(struct hip_common *msg,
		       struct in6_addr *update_saddr,
		       struct in6_addr *update_daddr);
int hip_send_update(struct hip_hadb_state *entry, struct hip_rea_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags);
void hip_send_update_all(struct hip_rea_info_addr_item *addr_list, int addr_count, int ifindex, int flags);

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
#endif /* HIP_UPDATE_H */
