#ifndef HIP_OUTPUT_H
#define HIP_OUTPUT_H

#include "hadb.h"

#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <net/hip.h>

int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_ip,
		struct in6_addr *dst_hit);
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb);
int hip_csum_verify(struct sk_buff *skb);
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf);
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf, struct flowi *out_fl);
int hip_send_i1(struct in6_addr *srchit, struct in6_addr *dsthit, hip_ha_t *entry);
int hip_send_r1(struct sk_buff *skb);
void hip_send_notify_all(void);

#endif /* HIP_OUTPUT_H */
