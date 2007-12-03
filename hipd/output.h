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
#include <netinet/ip.h>

#ifdef CONFIG_HIP_HI3
//#include "i3_id.h"
#endif

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;
extern int hip_nat_status;
extern int hip_locator_status;

enum number_dh_keys_t { ONE, TWO };

int hip_send_raw(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		 struct hip_common*, hip_ha_t *, int);
int hip_send_udp(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		 struct hip_common*, hip_ha_t *, int);
int hip_send(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		 struct hip_common*, hip_ha_t *, int);

struct hip_common *hip_create_r1(const struct in6_addr *src_hit, 
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *host_id_priv,
				 const struct hip_host_id *host_id_pub,
				 int cookie_k);
/**
 * Transmits an R1 packet to the network.
 *
 * Sends an R1 packet to the peer and stores the cookie information that was
 * sent. The packet is sent either to @c i1_saddr or  @c dst_ip depending on the
 * value of @c dst_ip. If @c dst_ip is all zeroes (::/128) or NULL, R1 is sent
 * to @c i1_saddr; otherwise it is sent to @c dst_ip. In case the incoming I1
 * was relayed through a middlebox (e.g. rendezvous server) @c i1_saddr should
 * have the address of that middlebox.
 *
 * @param i1_saddr      a pointer to the source address from where the I1 packet
 *                      was received.
 * @param i1_daddr      a pointer to the destination address where to the I1
 *                      packet was sent to (own address).
 * @param src_hit       a pointer to the source HIT i.e. responder HIT
 *                      (own HIT). 
 * @param dst_ip        a pointer to the destination IPv6 address where the R1
 *                      should be sent (peer ip).
 * @param dst_port      Destination port for R1. If zero, I1 source port is
 *                      used.
 * @param dst_hit       a pointer to the destination HIT i.e. initiator HIT
 *                      (peer HIT).
 * @param i1_info       a pointer to the source and destination ports
 *                      (when NAT is in use).
 * @return              zero on success, or negative error value on error.
 */
int hip_xmit_r1(hip_common_t *i1, in6_addr_t *i1_saddr, in6_addr_t *i1_daddr,
                in6_addr_t *dst_ip, const in_port_t dst_port,
                hip_portpair_t *i1_info, uint16_t *nonce, hip_tlv_type_t *param_type);
int hip_build_locators(struct hip_common *);
int hip_build_locators2(struct hip_common *);

int hip_send_i1(hip_hit_t *, hip_hit_t *, hip_ha_t *);
void hip_send_notify_all(void);

#ifdef CONFIG_HIP_HI3
static void no_matching_trigger(void *, void *, void *);
int hip_send_i3(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		struct hip_common *, hip_ha_t *, int);

int hip_build_locators(struct hip_common *);

#endif /* CONFIG_HIP_HI3 */

#endif /* HIP_OUTPUT_H */
