#ifndef HIP_LSI_H
#define HIP_LSI_H

#include <libipq.h>
#include "firewalldb.h"
#include "debug.h"
#include "ife.h"

int is_packet_reinjection(struct in_addr *ip_src);

int hip_fw_handle_incoming_hit(ipq_packet_msg_t *m, struct in6_addr *ip_src,
			       struct in6_addr *ip_dst, int, int);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src,
			       struct in_addr *ip_dst);

int hip_is_packet_lsi_reinjection(hip_lsi_t *lsi);

int reinject_packet(struct in6_addr *src_hit, struct in6_addr *dst_hit,
		    ipq_packet_msg_t *m, int ipOrigTraffic, int incoming);

int hip_request_peer_hit_from_hipd_at_firewall(
			const struct in6_addr *peer_ip,
	         	struct in6_addr       *peer_hit,
			const struct in6_addr *local_hit,
			in_port_t             *src_tcp_port,
			in_port_t             *dst_tcp_port,
			int                   *fallback,
			int                   *reject);
#endif
