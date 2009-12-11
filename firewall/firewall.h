#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include "builder.h"
#include "protodefs.h"

extern int esp_relay;

void hip_fw_init_opptcp();
void hip_fw_uninit_opptcp();
void hip_fw_init_proxy();
void hip_fw_uninit_proxy();

void set_stateful_filtering(int v);
int hip_fw_sys_opp_set_peer_hit(struct hip_common *msg);
int hip_get_bex_state_from_IPs(struct in6_addr *src_ip,
		      	       struct in6_addr *dst_ip,
			       struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       hip_lsi_t       *src_lsi,
			       hip_lsi_t       *dst_lsi);

hip_hit_t *hip_fw_get_default_hit(void);
int hip_fw_hit_is_our(struct in6_addr *hit);

#endif
