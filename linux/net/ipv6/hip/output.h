#ifndef HIP_OUTPUT_H
#define HIP_OUTPUT_H

#ifdef __KERNEL__
#  include <linux/ipv6.h>
#  include <linux/skbuff.h>
#  include <net/checksum.h>
#  include <net/addrconf.h>
#  include <net/xfrm.h>
#  include <linux/netfilter.h>
#  include <linux/skbuff.h>
#  include <net/ip6_route.h>
#endif /* __KERNEL__ */

#include <net/hip.h>
#include "hadb.h"
#include "debug.h"
#include "misc.h"
#include "hip.h"
#include "hadb.h"
#include "db.h"
#include "builder.h"
#include "cookie.h"
#include "builder.h"

#ifdef __KERNEL__
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb);
int hip_csum_verify(struct sk_buff *skb);
struct hip_common *hip_create_r1(const struct in6_addr *src_hit);
int hip_send_r1(struct sk_buff *skb);
int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_ip,
		struct in6_addr *dst_hit);
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf, struct flowi *out_fl);
#endif /* __KERNEL__ */

int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf);
int hip_send_i1(struct in6_addr *dsthit, hip_ha_t *entry);
void hip_send_notify_all(void);

#endif /* HIP_OUTPUT_H */
