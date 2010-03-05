/** @file
 * A header file for output.c.
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPD_OUTPUT_H
#define HIP_HIPD_OUTPUT_H
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

int hip_send_r1(const uint32_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *ctx);

int hip_send_r2(const uint32_t packet_type,
                const uint32_t ha_state,
                struct hip_packet_context *packet_ctx);

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
                      const void *msg, int length);

#endif /* HIP_HIPD_OUTPUT_H */
