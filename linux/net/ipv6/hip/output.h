#ifndef HIP_OUTPUT_H
#define HIP_OUTPUT_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/hip_glue.h>
#include <net/hip.h>
#include <net/ip6_route.h>
#include <net/checksum.h>
#include <net/addrconf.h>
#include <net/ipv6.h>

#include "db.h"
#include "debug.h"
#include "workqueue.h"
#include "input.h"
#include "daemon.h"
#include "builder.h"
#include "misc.h"
#include "security.h"

int hip_send_i1(struct in6_addr *dsthit);
int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_hit);
void hip_send_rea_all(int interface_id,
		      struct hip_rea_info_addr_item *addresses,
		      int rea_info_address_count, int netdev_flags);
void hip_rea_delete_sent_list(void);
void hip_ac_delete_sent_list(void);
void hip_send_update_all(void);
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb);
int hip_csum_verify(struct sk_buff *skb);
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf);
int hip_send_i1(struct in6_addr *dsthit);
int hip_send_r1(struct sk_buff *skb);
int hip_send_ac_or_acr(int pkt_type, struct in6_addr *src_hit, struct in6_addr *dst_hit,
		       struct in6_addr *src_addr, struct in6_addr *dst_addr,
		       uint16_t ac_id, uint16_t rea_id, uint32_t rtt,
		       uint32_t interface_id, uint32_t lifetime);
void hip_list_sent_ac_packets(char *str);
void hip_ac_delete_sent_list_one(int delete_all, uint16_t rea_id,
				 uint16_t ac_id);
void hip_ac_delete_sent_list_one(int, uint16_t, uint16_t);

#endif /* HIP_OUTPUT_H */
