#ifndef HIP_BOS_NEW_H
#define HIP_BOS_NEW_H

#include <net/hip.h>

#ifdef __KERNEL__

#include <linux/net.h>
//#include <linux/socket.h>
//#include <linux/mm.h>
//#include <net/sock.h>
//#include <net/ipv6.h>

//#include <net/addrconf.h>

#else

#include <sys/types.h>

#endif

#if (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__

/* This is the maximum number of source addresses for sending BOS packets */
#define MAX_SRC_ADDRS 128

int hip_send_bos(const struct hip_common *msg);
int hip_create_bos_signature(struct hip_host_id *priv, int algo, struct hip_common *bos);

#endif /* (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__  */

#endif /* HIP_BOS_NEW_H */
