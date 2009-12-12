#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include "builder.h"
#include "protodefs.h"

/** globally used variables defined in firewall.c */
extern int filter_traffic;
extern int system_based_opp_mode;
extern int hip_datapacket_mode;
extern int hip_proxy_status;
extern int hip_opptcp;
extern int hip_kernel_ipsec_fallback;
extern int hip_lsi_support;
extern int esp_relay;
#ifdef CONFIG_HIP_MIDAUTH
extern int use_midauth;
#endif

extern int hip_fw_sock;
extern int hip_fw_async_sock;

void hip_fw_init_opptcp(void);
void hip_fw_uninit_opptcp(void);
void hip_fw_init_proxy(void);
void hip_fw_uninit_proxy(void);
void set_stateful_filtering(const int active);
int hip_fw_sys_opp_set_peer_hit(const struct hip_common *msg);
int hip_get_bex_state_from_IPs(const struct in6_addr *src_ip,
		      	   const struct in6_addr *dst_ip,
			       struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       hip_lsi_t *src_lsi,
			       hip_lsi_t *dst_lsi);
hip_hit_t *hip_fw_get_default_hit(void);
hip_lsi_t *hip_fw_get_default_lsi(void);
int hip_fw_hit_is_our(const struct in6_addr *hit);

#endif
