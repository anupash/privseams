/** @file
 * A header file for output.c.
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_OUTPUT_H
#define HIP_OUTPUT_H
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "dh.h"
#include "hidb.h"
#include "hadb.h"
#include "lib/core/misc.h"
#include "lib/core/builder.h"
#include "cookie.h"
#include "close.h"
#include "user.h"
#include "nat.h"
#include "registration.h"


/* #include <libiptc/libiptc.h> */
#include "hipd/esp_prot_hipd_msg.h"
//#include "i3_id.h"

#define HIP_MAX_ICMP_PACKET 512

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;


int send_tcp_packet(void *hdr, int newSize, int trafficType, int sockfd,
		    int addOption, int addHIT);

struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
				 int (*sign)(void *key, struct hip_common *m),
				 void *private_key,
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
                hip_portpair_t *i1_info, uint16_t relay_para_type);

int hip_send_r2_response(struct hip_common *r2,
		struct in6_addr *r2_saddr,
		struct in6_addr *r2_daddr,
		hip_ha_t *entry,
		hip_portpair_t *r2_info);

int hip_send_i1(hip_hit_t *, hip_hit_t *, hip_ha_t *);
int are_addresses_compatible(const struct in6_addr *src_addr,
							 const struct in6_addr *dst_addr);
int hip_send_pkt(const struct in6_addr *local_addr, const struct in6_addr *peer_addr,
		const in_port_t src_port, const in_port_t dst_port,
		struct hip_common *msg, hip_ha_t *entry, const int retransmit);
int hip_send_icmp(int sockfd, hip_ha_t *entry);
int hip_send_udp_stun(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 const void* msg, int length);

#ifdef CONFIG_HIP_I3
int hip_send_i3(const struct in6_addr *, const struct in6_addr *, const in_port_t, const in_port_t,
		struct hip_common *, hip_ha_t *, int);
#endif /* CONFIG_HIP_I3 */

#endif /* HIP_OUTPUT_H */
