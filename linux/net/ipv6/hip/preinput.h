#ifndef HIP_PREINPUT_H
#define HIP_PREINPUT_H

#include <linux/ipv6.h> /* struct ipv6hdr */
#include <linux/skbuff.h> /* struct sk_buff */
#include <linux/types.h>

#include "debug.h"
#include "workqueue.h"
#include "beet.h"
  
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr);
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff);
int hip_csum_verify(struct sk_buff *skb);

#endif /* HIP_PREINPUT_H */
