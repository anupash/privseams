/** @file
 * A header file for output.c.
 * 
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
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
#include "close.h"
#include "user.h"
#include "string.h"
#include "nat.h"

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;
extern int hip_nat_status;

int hip_send_raw(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		 struct hip_common*, hip_ha_t *, int);
int hip_send_udp(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		 struct hip_common*, hip_ha_t *, int);

struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *src_privkey,
				 const struct hip_host_id *src_pubkey,
				 int cookie);
int hip_xmit_r1(struct in6_addr *, struct in6_addr *, struct in6_addr *,
		struct in6_addr *, const in_port_t, struct in6_addr *,
		hip_portpair_t *, const void *, const int, uint16_t *);

int hip_send_i1(hip_hit_t *, hip_hit_t *, hip_ha_t *);
void hip_send_notify_all(void);

#ifdef CONFIG_HIP_HI3
static void no_matching_trigger(void *, void *, void *);
int hip_send_i3(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		struct hip_common *, hip_ha_t *, int);
#endif /* CONFIG_HIP_HI3 */

#endif /* HIP_OUTPUT_H */
