#ifndef HIP_OUTPUT_H
#define HIP_OUTPUT_H

#include "hidb.h"
#include "hadb.h"
#include "misc.h"
#include "hadb.h"
#include "builder.h"
#include "cookie.h"
#include "builder.h"
#include "output.h"
#include "beet.h"
#include "close.h"
#include "user.h"
#include "string.h"

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;
extern int hip_nat_status;

/* Called by userspace daemon or kernel packet processing to send a
   packet to wire */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  uint32_t src_port, uint32_t dst_port,
		  struct hip_common* buf, hip_ha_t *entry, int retransmit);

struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *src_privkey,
				 const struct hip_host_id *src_pubkey,
				 int cookie);
int hip_xmit_r1(struct in6_addr *i1_saddr,
		struct in6_addr *i1_daddr,
		struct in6_addr *src_hit, 
		struct in6_addr *dst_ip, struct in6_addr *dst_hit, 
		struct hip_stateless_info *i1_info,
		const struct in6_addr *traversed_rvs,
		const int rvs_count);
int hip_send_i1(hip_hit_t *, hip_hit_t *, hip_ha_t *);
void hip_send_notify_all(void);

#endif /* HIP_OUTPUT_H */
