#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifdef __KERNEL__
#  include <asm/atomic.h>
#  include <linux/skbuff.h>
#  include <net/ipv6.h>
#  include <net/checksum.h>
#endif /* __KERNEL__ */ 

#include <net/hip.h>
#include "workqueue.h"
#include "debug.h"
#include "xfrmapi.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto/dsa.h"
#include "builder.h"
#include "hip.h"
#include "dh.h"
#include "misc.h"
#include "workqueue.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "socket.h"
#ifdef CONFIG_HIP_RVS
#include "rvs.h"
#endif
#include "crypto/rsa.h"

#ifdef __KERNEL__
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr);
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff);
#endif /* __KERNEL__ */

int hip_create_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature);
int hip_receive_r1(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_i2(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_i1(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_r2(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_notify(struct hip_common *, struct in6_addr *,
		       struct in6_addr *);
int hip_receive_bos(struct hip_common *, struct in6_addr *,
		    struct in6_addr *); 

void hip_hwo_input_destructor(struct hip_work_order *hwo);

int hip_verify_packet_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key);
int hip_verify_packet_signature(struct hip_common *msg,
				struct hip_host_id *hid);
int hip_verify_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature);
#endif /* HIP_INPUT_H */
