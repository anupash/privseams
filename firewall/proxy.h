/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_PROXY_H
#define HIP_FIREWALL_PROXY_H

#define _BSD_SOURCE

#include <libipq.h>
#include <netinet/in.h>

int request_hipproxy_status(void);

int init_proxy(void);
int uninit_proxy(void);
int handle_proxy_outbound_traffic(const ipq_packet_msg_t *m,
                                  const struct in6_addr *src_addr,
                                  const struct in6_addr *dst_addr,
                                  const int hdr_size,
                                  const int ip_version);
int handle_proxy_inbound_traffic(const ipq_packet_msg_t *m,
                                 const struct in6_addr *src_addr);

#endif /* HIP_FIREWALL_PROXY_H */
