#ifndef HIP_PREOUTPUT_H
#define HIP_PREOUTPUT_H

#ifdef __KERNEL__
#include <linux/ipv6.h> /* struct ipv6hdr */
#include <linux/skbuff.h> /* struct sk_buff */
#include <linux/types.h>
#include "netlink.h"
#endif

#include <net/hip.h>
#include "xfrmapi.h"
#include "misc.h"
#include "debug.h"

#ifndef __KERNEL__
#endif

// FIXME: hip_csum_send should be moved into its own file to make this
// file kernel only.

#ifdef __KERNEL__
/* Called by transport layer */
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb);

/* Called by HIP native socket to send a packet to wire */
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
                     struct hip_common* buf, struct flowi *out_fl);
#endif

/* Called by userspace daemon or kernel packet processing to send a
   packet to wire */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf);

#endif /* HIP_PREOUTPUT_H */
