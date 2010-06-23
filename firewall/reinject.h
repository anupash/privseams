/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_REINJECT_H
#define HIP_FIREWALL_REINJECT_H

#include <netinet/in.h>

void hip_firewall_init_raw_sockets(void);
int hip_firewall_send_outgoing_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto);
int hip_firewall_send_incoming_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto, int ttl);

#endif /* HIP_FIREWALL_REINJECT_H*/
