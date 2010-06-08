/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_LSI_H
#define HIP_FIREWALL_LSI_H

#define _BSD_SOURCE

#include <libipq.h>
#include <netinet/in.h>

#include "lib/core/protodefs.h"

int hip_trigger_bex(const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    struct in6_addr *src_lsi,
                    struct in6_addr *dst_lsi,
                    struct in6_addr *src_ip,
                    struct in6_addr *dst_ip);
int hip_fw_handle_incoming_hit(const ipq_packet_msg_t *m,
                               const struct in6_addr *ip_src,
                               const struct in6_addr *ip_dst,
                               const int lsi_support);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m,
                               struct in_addr *ip_src,
                               struct in_addr *ip_dst);

int hip_is_packet_lsi_reinjection(hip_lsi_t *lsi);

#endif /* HIP_FIREWALL_LSI_H */
