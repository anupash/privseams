#ifndef HIP_PROXY_H
#define HIP_PROXY_H

#include <libipq.h>

#include "firewall.h"
#include "proxydb.h"

int hip_proxy_init_raw_sockets();
int hip_fw_proxy_set_peer_hit(hip_common_t *msg);
int handle_proxy_outbound_traffic(const ipq_packet_msg_t *m,
		const struct in6_addr *src_addr,
		const struct in6_addr *dst_addr,
		const int hdr_size,
		const int ip_version);
int handle_proxy_inbound_traffic(const ipq_packet_msg_t *m,
				 const struct in6_addr *src_addr);

#endif /* HIP_PROXY_H */
