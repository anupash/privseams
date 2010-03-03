#ifndef HIP_FIREWALL_LSI_H
#define HIP_FIREWALL_LSI_H

#include <libipq.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#include "lib/core/protodefs.h"

int hip_fw_handle_incoming_hit(const ipq_packet_msg_t *m,
                               const struct in6_addr *ip_src,
                               const struct in6_addr *ip_dst,
                               const int lsi_support,
                               const int sys_opp_support);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m,
                               struct in_addr *ip_src,
                               struct in_addr *ip_dst);

int hip_is_packet_lsi_reinjection(hip_lsi_t *lsi);

int hip_reinject_packet(const struct in6_addr *src_hit,
                        const struct in6_addr *dst_hit,
                        const ipq_packet_msg_t *m,
                        const int ipOrigTraffic,
                        const int incoming);

int hip_request_peer_hit_from_hipd_at_firewall(const struct in6_addr *peer_ip,
                                               struct in6_addr *peer_hit,
                                               const struct in6_addr *local_hit,
                                               in_port_t *src_tcp_port,
                                               in_port_t *dst_tcp_port,
                                               int *fallback,
                                               int *reject);
#endif
