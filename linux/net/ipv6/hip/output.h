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
#include "hidb.h"
#include "builder.h"
#include "cookie.h"
#include "builder.h"
#include "preoutput.h"

struct hip_common *hip_create_r1(const struct in6_addr *src_hit);
int hip_xmit_r1(struct in6_addr *i1_saddr, struct in6_addr *i1_daddr,
		struct in6_addr *dst_ip, struct in6_addr *dst_hit);
int hip_send_i1(struct in6_addr *dsthit, hip_ha_t *entry);
void hip_send_notify_all(void);

#endif /* HIP_OUTPUT_H */
