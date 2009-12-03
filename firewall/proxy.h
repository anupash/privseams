#ifndef HIP_PROXY_H
#define HIP_PROXY_H

#include "firewall.h"
#include "proxydb.h"

int hip_proxy_init_raw_sockets();
int hip_fw_proxy_set_peer_hit(hip_common_t *msg);
int hip_proxy_send_pkt(struct in6_addr *local_addr, struct in6_addr *peer_addr,	u8 *msg, u16 len, int protocol);
int hip_proxy_send_inbound_icmp_pkt(struct in6_addr* src_addr, struct in6_addr* dst_addr, u8* buff, u16 len);
int hip_proxy_send_to_client_pkt(struct in6_addr *local_addr, struct in6_addr *peer_addr, u8 *buff, u16 len);
int handle_proxy_outbound_traffic(ipq_packet_msg_t *m, struct in6_addr *src_addr, struct in6_addr *dst_addr, int hdr_size, int ip_version);
int handle_proxy_inbound_traffic(ipq_packet_msg_t *m, struct in6_addr *src_addr);

#endif /* HIP_PROXY_H */
