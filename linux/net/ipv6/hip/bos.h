#ifndef HIP_BOS_NEW_H
#define HIP_BOS_NEW_H

#include <net/hip.h>
#include <linux/socket.h>

#include "socket.h"

#ifdef __KERNEL__
#include <linux/net.h>
#include <linux/socket.h>

//#include <linux/mm.h>
//#include <net/sock.h>
//#include <net/ipv6.h>
//#include <net/addrconf.h>

#else

#include <sys/types.h>
#include <netdb.h>

#endif

//extern struct my_addrinfo;
int handle_bos_peer_list(int family, struct my_addrinfo **pai, int msg_len);

#if (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__

int hip_send_bos(const struct hip_common *msg);
int hip_create_bos_signature(struct hip_host_id *priv, int algo, struct hip_common *bos);
int hip_verify_packet_signature(struct hip_common *bos, struct hip_host_id *peer_host_id);

int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry);

#endif /* (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__  */

#endif /* HIP_BOS_NEW_H */
