#ifndef HIP_REA_H
#define HIP_REA_H

#include "db.h"
#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <net/hip.h>


int hip_send_ac_or_acr(int pkt_type, hip_ha_t *entry, 
		       struct in6_addr *src_addr, struct in6_addr *dst_addr,
		       uint16_t ac_id, uint16_t rea_id, uint32_t rtt,
		       uint32_t interface_id, uint32_t lifetime);

void hip_send_rea_all(int interface_id, struct hip_rea_info_addr_item *addresses,
		      int rea_info_address_count, int netdev_flags);


int hip_receive_ac_or_acr(struct sk_buff *skb, int pkt_type);
int hip_receive_rea(struct sk_buff *skb);
void hip_ac_delete_sent_list(void);
void hip_rea_delete_sent_list(void);
void hip_ac_delete_sent_list_one(int delete_all, uint16_t rea_id,
				 uint16_t ac_id);

#endif
