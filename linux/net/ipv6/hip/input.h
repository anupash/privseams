#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifndef __KERNEL__
#  define __KERNEL__
#endif

#ifndef MODULE
#  define MODULE
#endif

#include <net/keymat.h>
#include <linux/sched.h>
#include <net/ipv6.h>

#include "db.h"
#include "debug.h"
#include "hip.h"
/*#include "db.h"*/
#include "security.h"



extern struct cipher_context *own_dh_cx;
uint16_t hip_get_next_atomic_val_16(atomic_t *a, spinlock_t *lock);
int hip_create_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature);
int hip_inbound(struct sk_buff **skb, int unused);
void hip_handle_esp(struct ipv6hdr *hdr);
int hip_receive_r1(struct sk_buff *skb);
int hip_receive_i2(struct sk_buff *skb);
int hip_receive_i1(struct sk_buff *skb);
int hip_receive_r2(struct sk_buff *skb);
int hip_receive_ac_or_acr(struct sk_buff *skb, int pkt_type);
int hip_receive_rea(struct sk_buff *skb);

#endif /* HIP_INPUT_H */
