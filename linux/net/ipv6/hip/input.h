#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#ifdef __KERNEL__
#  include <asm/atomic.h>
#  include <linux/skbuff.h>
#  include <net/ipv6.h>
#  include <net/checksum.h>
#endif /* __KERNEL__ */ 

#include <net/hip.h>
#include "workqueue.h"
#include "debug.h"
#include "xfrm.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto.h"
#include "builder.h"
#include "hip.h"
#include "misc.h"
#include "workqueue.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "socket.h"
#include "pk.h"
#ifdef CONFIG_HIP_RVS
#include "rvs.h"
#endif

int hip_verify_packet_hmac(struct hip_common *, struct hip_crypto_key *);
int hip_receive_r1(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_i2(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_i1(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_r2(struct hip_common *, struct in6_addr *, struct in6_addr *);
int hip_receive_notify(struct hip_common *, struct in6_addr *,
		       struct in6_addr *);
int hip_receive_bos(struct hip_common *, struct in6_addr *,
		    struct in6_addr *);
void hip_hwo_input_destructor(struct hip_work_order *hwo);

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
#endif /* HIP_INPUT_H */
